//! Reference remote HTTP delivery agent (roadmap T20: live remote-agent
//! evidence) — the server-side counterpart of [`crate::delivery::HttpAgentSink`].
//!
//! # Reference implementation
//!
//! This module is a **reference implementation** of the delivery-agent HTTP
//! contract, suitable for production-style single-process deployments and for
//! live evidence runs. It is self-contained (axum + tokio only, no repository
//! or workflow dependencies) and can be compiled and run standalone through
//! `acmex agent serve` or embedded as a library router. State is kept **in
//! memory**; deployments that need durability or multi-instance HA should
//! replace `AgentServerState` with a durable backend while keeping the same
//! wire contract.
//!
//! # Wire contract (mirrors the in-process fake agent, the protocol
//! de-facto standard, and `http_sink.rs`)
//!
//! | Route | Method | Success | Semantics |
//! |---|---|---|---|
//! | `/stages` | POST | `201` | Stage material for one version. Idempotent per version (first stage wins; re-staging never changes the active pointer). Headers: `Idempotency-Key: <version id>` (validated when present). |
//! | `/stages/{version}/activate` | POST | `204` | Atomically switch the single active pointer to `{version}`. `404` if the version was never staged. |
//! | `/stages/{version}/health` | GET | `200` | `{"healthy": bool, "detail": ...}`. Active version → healthy; staged-but-not-active → unhealthy (`"route exists but is not active"`); unknown version → `404` (the sink maps non-2xx to `DeploymentHealth::Unknown`). |
//! | `/stages/{version}/rollback` | POST | `204` | Deactivate `{version}` if it is active. `404` if unknown. |
//! | `/stages/{version}` | DELETE | `204`/`404` | Remove the staged route (and clear the pointer if it was active). Idempotent via `404` → `CleanupOutcome::AlreadyClean`. |
//! | `/healthz` | GET | `200` | Readiness probe, **no authentication**; used by subprocess tests to await startup. |
//!
//! All `/stages*` routes require `Authorization: Bearer <token>` compared in
//! constant time. The token can only come from a `SecretRef` (`env:`/`file:`)
//! — bare strings, `vault:` and `provider:` references are rejected — and it
//! never appears in logs, Debug output, or error messages.
//!
//! Exactly one staged version is active at any time: the active pointer is a
//! single mutex-guarded slot switched atomically (the guard is never held
//! across an `.await`).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};

use crate::dns::spec::{EnvFileSecretResolver, SecretBytes, SecretRef, SecretResolver};
use crate::error::AcmeError;

/// Default listen address for `acmex agent serve`.
pub const DEFAULT_AGENT_LISTEN_ADDR: &str = "127.0.0.1:9460";

/// Server configuration. The token is held as [`SecretBytes`] (redacted
/// `Debug`, zeroized on drop) and can only be constructed from a
/// [`SecretRef`] via [`AgentServerConfig::from_secret_ref`].
#[derive(Clone)]
pub struct AgentServerConfig {
    /// Address to bind.
    pub listen: SocketAddr,
    /// Bearer token required on every `/stages*` request.
    pub token: SecretBytes,
}

impl AgentServerConfig {
    /// Creates a configuration from an already-resolved token.
    pub fn new(listen: SocketAddr, token: SecretBytes) -> Self {
        Self { listen, token }
    }

    /// Resolves the token reference with the built-in `env:`/`file:` resolver.
    /// Errors name the reference (via `describe()`), never the value.
    pub async fn from_secret_ref(
        listen: SocketAddr,
        reference: &SecretRef,
    ) -> Result<Self, AgentServerError> {
        let resolved = EnvFileSecretResolver
            .resolve(reference)
            .await
            .map_err(|_| {
                AgentServerError::TokenReference(format!(
                    "cannot resolve agent token {} (the value itself is never echoed)",
                    reference.describe()
                ))
            })?;
        if resolved.expose().is_empty() {
            return Err(AgentServerError::TokenReference(format!(
                "agent token {} resolved to an empty value",
                reference.describe()
            )));
        }
        Ok(Self {
            listen,
            token: SecretBytes::new(resolved.expose().to_vec()),
        })
    }
}

impl fmt::Debug for AgentServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentServerConfig")
            .field("listen", &self.listen)
            .field("token", &"**redacted**")
            .finish()
    }
}

/// Classified agent server failures (`retryable` vs `terminal`). Messages
/// never contain the token.
#[derive(Debug, thiserror::Error)]
pub enum AgentServerError {
    /// The listen address could not be bound (e.g. port still in use).
    #[error("agent bind failed on {addr}: {message}")]
    Bind {
        /// Address that failed to bind.
        addr: SocketAddr,
        /// Underlying OS message.
        message: String,
    },
    /// The token reference is malformed or cannot be resolved.
    #[error("agent token reference invalid: {0}")]
    TokenReference(String),
    /// The serve loop ended unexpectedly.
    #[error("agent serve loop failed: {0}")]
    Serve(String),
}

impl AgentServerError {
    /// `Bind` and `Serve` failures may succeed on a retry (port frees up,
    /// transient runtime fault); a bad token reference is terminal and needs
    /// operator intervention.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Bind { .. } | Self::Serve(_) => true,
            Self::TokenReference(_) => false,
        }
    }
}

impl From<AgentServerError> for AcmeError {
    fn from(error: AgentServerError) -> Self {
        match error {
            AgentServerError::Bind { .. } => AcmeError::Configuration(error.to_string()),
            AgentServerError::TokenReference(message) => AcmeError::Configuration(message),
            AgentServerError::Serve(message) => AcmeError::Transport(message),
        }
    }
}

/// Parses a `--token-ref` command-line value. Only `env:`/`file:` forms are
/// accepted; bare strings and `vault:`/`provider:` schemes are rejected. The
/// error never echoes the input, because a bare string *is* a secret.
pub fn parse_agent_token_ref(value: &str) -> Result<SecretRef, AgentServerError> {
    let reference = SecretRef::parse(value).map_err(|_| {
        AgentServerError::TokenReference(
            "--token-ref must be a SecretRef of the form env:NAME or file:/path; \
             bare strings are not accepted"
                .to_string(),
        )
    })?;
    match reference {
        SecretRef::Env { .. } | SecretRef::File { .. } => Ok(reference),
        SecretRef::Vault { .. } | SecretRef::ProviderSpecific { .. } => {
            Err(AgentServerError::TokenReference(
                "--token-ref must be an env:/file: SecretRef; the built-in agent \
                 does not resolve vault:/provider: references"
                    .to_string(),
            ))
        }
    }
}

/// One staged version as observed by the agent. Only metadata and the leaf
/// fingerprint are retained; PEM bodies (and in particular the private key)
/// are never kept in memory.
#[derive(Debug, Clone)]
struct StagedVersion {
    /// Retained so a hardened agent can extend health to fingerprint
    /// verification; the reference health check only consults the active
    /// pointer, matching the fake-agent contract.
    #[allow(dead_code)]
    leaf_sha256: String,
    /// Active version observed when this version was first staged. Rollback of
    /// this version restores the pointer to this value when possible.
    previous_active_ref: Option<String>,
    #[allow(dead_code)] // recorded for operator introspection of the reference agent
    lineage_id: Option<String>,
    #[allow(dead_code)] // recorded for operator introspection of the reference agent
    target_id: Option<String>,
}

/// Shared in-memory state: staged routes plus the single active pointer.
/// Every access takes the mutex for the duration of one synchronous critical
/// section; no guard is ever held across an `.await`.
struct AgentSharedState {
    token: SecretBytes,
    staged: HashMap<String, StagedVersion>,
    /// The atomic active pointer: `Some(version_id)` while exactly one route
    /// serves traffic. Switched under one mutex acquisition.
    active: Option<String>,
    /// Monotonic mutation counter surfaced as `resource_version`.
    resource_version: u64,
}

/// Cloneable handle to the reference agent state (embeddable, inspectable).
#[derive(Clone)]
pub struct AgentServerState {
    inner: Arc<Mutex<AgentSharedState>>,
}

impl AgentServerState {
    /// Creates state protected by `token`.
    pub fn new(token: SecretBytes) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AgentSharedState {
                token,
                staged: HashMap::new(),
                active: None,
                resource_version: 0,
            })),
        }
    }

    /// The currently active version id, if any (introspection helper).
    pub fn active_version(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("agent state lock poisoned")
            .active
            .clone()
    }

    /// The staged version ids (introspection helper).
    pub fn staged_versions(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("agent state lock poisoned")
            .staged
            .keys()
            .cloned()
            .collect()
    }
}

impl fmt::Debug for AgentServerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentServerState").finish_non_exhaustive()
    }
}

/// Request body of `POST /stages` (what `HttpAgentSink` sends). PEM bodies
/// are accepted per contract but never persisted by the reference agent.
/// `Debug` is hand-written so the private key can never leak into logs.
#[derive(Deserialize)]
pub struct AgentStageRequest {
    /// Version being staged (idempotency key).
    pub version_id: String,
    /// Owning lineage, if the client sends it.
    #[serde(default)]
    pub lineage_id: Option<String>,
    /// Delivery target, if the client sends it.
    #[serde(default)]
    pub target_id: Option<String>,
    /// Full chain PEM (accepted, not retained).
    #[serde(default)]
    pub fullchain_pem: Option<String>,
    /// Leaf PEM (accepted, not retained).
    #[serde(default)]
    pub cert_pem: Option<String>,
    /// Private key PEM (accepted, never retained in memory).
    #[serde(default)]
    pub private_key_pem: Option<String>,
    /// SHA-256 fingerprint of the leaf DER.
    pub leaf_sha256: String,
}

impl fmt::Debug for AgentStageRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentStageRequest")
            .field("version_id", &self.version_id)
            .field("lineage_id", &self.lineage_id)
            .field("target_id", &self.target_id)
            .field("has_fullchain_pem", &self.fullchain_pem.is_some())
            .field("has_cert_pem", &self.cert_pem.is_some())
            .field("private_key_pem", &"**redacted**")
            .field("leaf_sha256", &self.leaf_sha256)
            .finish()
    }
}

/// Response body of `POST /stages`.
#[derive(Debug, Serialize)]
pub struct AgentStageResponse {
    /// Sink-local staged reference.
    pub staged_ref: String,
    /// Version that was active before this stage, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_active_ref: Option<String>,
    /// Monotonic mutation counter.
    #[serde(default)]
    pub resource_version: u64,
}

/// Response body of `GET /stages/{version}/health`.
#[derive(Debug, Serialize)]
pub struct AgentHealthResponse {
    /// Whether the route is the active one.
    pub healthy: bool,
    /// Human-readable detail, set when unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Builds the reference agent router: authenticated `/stages*` routes plus an
/// unauthenticated `GET /healthz` readiness probe.
pub fn agent_router(state: AgentServerState) -> Router {
    let protected = Router::new()
        .route("/stages", post(stage_handler))
        .route("/stages/{version}/activate", post(activate_handler))
        .route("/stages/{version}/health", get(health_handler))
        .route("/stages/{version}/rollback", post(rollback_handler))
        .route("/stages/{version}", delete(cleanup_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer_token,
        ));
    Router::new()
        .route("/healthz", get(healthz_handler))
        .merge(protected)
        .with_state(state)
}

/// Constant-time byte equality: the accumulated XOR means the comparison
/// cost does not depend on where (or whether) the inputs first differ.
/// Length is checked up front; token *length* is not treated as secret,
/// token *contents* never short-circuit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Bearer-token gate for every `/stages*` route. The expected token is only
/// ever compared in place; neither the presented value nor the configured
/// token is ever logged or included in a response body.
async fn require_bearer_token(
    State(state): State<AgentServerState>,
    request: Request,
    next: Next,
) -> Response {
    let authorized = {
        let shared = state.inner.lock().expect("agent state lock poisoned");
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|presented| constant_time_eq(presented.as_bytes(), shared.token.expose()))
    };
    if authorized {
        next.run(request).await
    } else {
        agent_error(StatusCode::UNAUTHORIZED, "unauthorized")
    }
}

fn agent_error(status: StatusCode, detail: &str) -> Response {
    (status, Json(serde_json::json!({ "detail": detail }))).into_response()
}

async fn healthz_handler() -> &'static str {
    "ok"
}

/// `POST /stages`: idempotent per version; never touches the active pointer.
async fn stage_handler(
    State(state): State<AgentServerState>,
    headers: HeaderMap,
    Json(payload): Json<AgentStageRequest>,
) -> Response {
    let version_id = payload.version_id.trim().to_string();
    let leaf_sha256 = payload.leaf_sha256.trim().to_string();
    if version_id.is_empty() || leaf_sha256.is_empty() {
        return agent_error(
            StatusCode::BAD_REQUEST,
            "version_id and leaf_sha256 are required",
        );
    }
    if let Some(key) = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        && key != version_id
    {
        return agent_error(
            StatusCode::CONFLICT,
            "Idempotency-Key does not match version_id",
        );
    }
    let response = {
        let mut shared = state.inner.lock().expect("agent state lock poisoned");
        let previous_active = shared.active.clone();
        shared.resource_version += 1;
        // Idempotent per version: the first stage wins, re-staging the same
        // version keeps the original fingerprint and never changes active.
        shared
            .staged
            .entry(version_id.clone())
            .or_insert_with(|| StagedVersion {
                leaf_sha256: leaf_sha256.clone(),
                previous_active_ref: previous_active.clone(),
                lineage_id: payload.lineage_id.clone(),
                target_id: payload.target_id.clone(),
            });
        AgentStageResponse {
            staged_ref: format!("agent://{version_id}"),
            previous_active_ref: previous_active,
            resource_version: shared.resource_version,
        }
    };
    (StatusCode::CREATED, Json(response)).into_response()
}

/// `POST /stages/{version}/activate`: atomically moves the single active
/// pointer to `{version}`. The mutex guard spans one synchronous critical
/// section, so concurrent activations serialize and exactly one pointer
/// value survives.
async fn activate_handler(
    State(state): State<AgentServerState>,
    Path(version_id): Path<String>,
) -> Response {
    let mut shared = state.inner.lock().expect("agent state lock poisoned");
    if !shared.staged.contains_key(&version_id) {
        return agent_error(StatusCode::NOT_FOUND, "version not staged");
    }
    shared.active = Some(version_id);
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /stages/{version}/health`: active → healthy, staged-but-inactive →
/// unhealthy, unknown → 404 (the sink reports that as `Unknown`).
async fn health_handler(
    State(state): State<AgentServerState>,
    Path(version_id): Path<String>,
) -> Response {
    let shared = state.inner.lock().expect("agent state lock poisoned");
    match (
        shared.staged.contains_key(&version_id),
        shared.active.as_deref(),
    ) {
        (true, Some(active)) if active == version_id => (
            StatusCode::OK,
            Json(AgentHealthResponse {
                healthy: true,
                detail: None,
            }),
        )
            .into_response(),
        (true, _) => (
            StatusCode::OK,
            Json(AgentHealthResponse {
                healthy: false,
                detail: Some("route exists but is not active".to_string()),
            }),
        )
            .into_response(),
        (false, _) => agent_error(StatusCode::NOT_FOUND, "version not staged"),
    }
}

/// `POST /stages/{version}/rollback`: deactivate the route if it is active.
async fn rollback_handler(
    State(state): State<AgentServerState>,
    Path(version_id): Path<String>,
) -> Response {
    let mut shared = state.inner.lock().expect("agent state lock poisoned");
    let Some(staged) = shared.staged.get(&version_id) else {
        return agent_error(StatusCode::NOT_FOUND, "version not staged");
    };
    let previous_active_ref = staged.previous_active_ref.clone();
    if shared.active.as_deref() == Some(version_id.as_str()) {
        shared.active = previous_active_ref.filter(|previous| shared.staged.contains_key(previous));
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `DELETE /stages/{version}`: remove the staged route; `404` makes repeat
/// cleanups idempotent (`CleanupOutcome::AlreadyClean` on the sink side).
async fn cleanup_handler(
    State(state): State<AgentServerState>,
    Path(version_id): Path<String>,
) -> Response {
    let mut shared = state.inner.lock().expect("agent state lock poisoned");
    if shared.staged.remove(&version_id).is_none() {
        return agent_error(StatusCode::NOT_FOUND, "version not staged");
    }
    if shared.active.as_deref() == Some(version_id.as_str()) {
        shared.active = None;
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Runs the reference agent until SIGINT/SIGTERM, then shuts down gracefully.
pub async fn serve_agent(config: AgentServerConfig) -> Result<(), AgentServerError> {
    let state = AgentServerState::new(config.token);
    serve_with_graceful_shutdown(config.listen, state, shutdown_signal()).await
}

/// Binds `listen`, serves the agent router, and waits for `shutdown` before
/// draining in-flight connections.
pub async fn serve_with_graceful_shutdown(
    listen: SocketAddr,
    state: AgentServerState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), AgentServerError> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| AgentServerError::Bind {
            addr: listen,
            message: error.to_string(),
        })?;
    let bound = listener
        .local_addr()
        .map_err(|error| AgentServerError::Bind {
            addr: listen,
            message: error.to_string(),
        })?;
    tracing::info!("reference delivery agent listening on {bound}");
    axum::serve(listener, agent_router(state))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|error| AgentServerError::Serve(error.to_string()))
}

/// Resolves once SIGINT or (on unix) SIGTERM is received.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TOKEN: &str = "agent-reference-token";

    fn test_state() -> AgentServerState {
        AgentServerState::new(SecretBytes::new(TOKEN.as_bytes().to_vec()))
    }

    async fn spawn_router(state: AgentServerState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, agent_router(state)).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn authed(
        client: &reqwest::Client,
        method: reqwest::Method,
        url: String,
    ) -> reqwest::RequestBuilder {
        client
            .request(method, url)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
    }

    #[test]
    fn constant_time_eq_matches_only_equal_inputs() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn token_ref_accepts_only_env_and_file_forms() {
        assert!(parse_agent_token_ref("env:AGENT_TOKEN").is_ok());
        assert!(parse_agent_token_ref("file:/run/secrets/agent").is_ok());
        // A bare string is itself the secret: rejected, and the error must
        // not echo it back.
        let bare = parse_agent_token_ref("super-secret-bare-token").unwrap_err();
        assert!(
            !bare.to_string().contains("super-secret-bare-token"),
            "error leaked the bare token: {bare}"
        );
        assert!(parse_agent_token_ref("vault:m:p:k").is_err());
        assert!(parse_agent_token_ref("provider:aws:x").is_err());
    }

    #[test]
    fn config_debug_is_redacted() {
        let config = AgentServerConfig::new(
            "127.0.0.1:9460".parse().unwrap(),
            SecretBytes::new(TOKEN.as_bytes().to_vec()),
        );
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(TOKEN), "debug leaked token: {rendered}");
        assert!(rendered.contains("**redacted**"));
    }

    #[tokio::test]
    async fn healthz_is_unauthenticated() {
        let base = spawn_router(test_state()).await;
        let response = client()
            .get(format!("{base}/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stages_reject_missing_or_wrong_bearer() {
        let base = spawn_router(test_state()).await;
        let client = client();
        let no_auth = client
            .post(format!("{base}/stages"))
            .json(&serde_json::json!({"version_id": "v1", "leaf_sha256": "aa"}))
            .send()
            .await
            .unwrap();
        assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);
        let wrong = client
            .get(format!("{base}/stages/v1/health"))
            .header(header::AUTHORIZATION, "Bearer not-the-token")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stage_activate_health_rollback_cleanup_contract() {
        use reqwest::Method;

        let state = test_state();
        let base = spawn_router(state.clone()).await;
        let client = client();

        // Stage v1: idempotent, active pointer untouched.
        for _ in 0..2 {
            let response = authed(&client, Method::POST, format!("{base}/stages"))
                .header("Idempotency-Key", "v1")
                .json(&serde_json::json!({
                    "version_id": "v1",
                    "lineage_id": "lin_1",
                    "target_id": "edge",
                    "leaf_sha256": "aa11",
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["staged_ref"], "agent://v1");
            let resource = body["resource_version"].as_u64().unwrap();
            assert!(resource >= 1);
        }
        assert_eq!(state.active_version(), None);

        // Health before activation: reachable but not serving → unhealthy.
        let health: serde_json::Value =
            authed(&client, Method::GET, format!("{base}/stages/v1/health"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(health["healthy"], false);
        assert_eq!(health["detail"], "route exists but is not active");

        let activated = authed(&client, Method::POST, format!("{base}/stages/v1/activate"))
            .send()
            .await
            .unwrap();
        assert_eq!(activated.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.active_version().as_deref(), Some("v1"));

        // Stage v2 after v1 is active: previous_active_ref records v1, but
        // staging alone still leaves exactly one active pointer.
        let staged_v2 = authed(&client, Method::POST, format!("{base}/stages"))
            .json(&serde_json::json!({"version_id": "v2", "leaf_sha256": "bb22"}))
            .send()
            .await
            .unwrap();
        assert_eq!(staged_v2.status(), StatusCode::CREATED);
        let staged_v2_body: serde_json::Value = staged_v2.json().await.unwrap();
        assert_eq!(staged_v2_body["previous_active_ref"], "v1");
        assert_eq!(state.active_version().as_deref(), Some("v1"));
        assert_eq!(state.staged_versions().len(), 2);

        let activated_v2 = authed(&client, Method::POST, format!("{base}/stages/v2/activate"))
            .send()
            .await
            .unwrap();
        assert_eq!(activated_v2.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.active_version().as_deref(), Some("v2"));

        // The newly activated v2 is healthy; v1 is staged but inactive.
        for (version, expected) in [("v1", false), ("v2", true)] {
            let health: serde_json::Value = authed(
                &client,
                Method::GET,
                format!("{base}/stages/{version}/health"),
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
            assert_eq!(health["healthy"], expected, "version {version}: {health}");
        }

        // Idempotency-Key mismatch is rejected.
        let conflict = authed(&client, Method::POST, format!("{base}/stages"))
            .header("Idempotency-Key", "other")
            .json(&serde_json::json!({"version_id": "v2", "leaf_sha256": "bb22"}))
            .send()
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        // Rollback of v2 restores the previous active v1.
        let rolled = authed(&client, Method::POST, format!("{base}/stages/v2/rollback"))
            .send()
            .await
            .unwrap();
        assert_eq!(rolled.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.active_version().as_deref(), Some("v1"));

        // Cleanup: 204 once, then 404 forever (idempotent AlreadyClean).
        let cleaned = authed(&client, Method::DELETE, format!("{base}/stages/v1"))
            .send()
            .await
            .unwrap();
        assert_eq!(cleaned.status(), StatusCode::NO_CONTENT);
        let again = authed(&client, Method::DELETE, format!("{base}/stages/v1"))
            .send()
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::NOT_FOUND);
        let missing = authed(&client, Method::GET, format!("{base}/stages/v1/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        // Activate/rollback of an unstaged version is 404.
        for path in ["/stages/ghost/activate", "/stages/ghost/rollback"] {
            let response = authed(&client, Method::POST, format!("{base}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    /// Concurrent activations must leave exactly one active version and the
    /// pointer must always name a staged version (atomic switch).
    #[tokio::test]
    async fn concurrent_activation_leaves_exactly_one_active() {
        use reqwest::Method;

        let state = test_state();
        let base = spawn_router(state.clone()).await;
        let client = client();

        for index in 0..16 {
            authed(&client, Method::POST, format!("{base}/stages"))
                .json(&serde_json::json!({
                    "version_id": format!("v{index}"),
                    "leaf_sha256": format!("{index:02x}"),
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }

        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..16 {
            let base = base.clone();
            tasks.spawn(async move {
                let activated = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap()
                    .post(format!("{base}/stages/v{index}/activate"))
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(activated.status(), StatusCode::NO_CONTENT);
            });
        }
        while tasks.join_next().await.is_some() {}

        let active = state.active_version().expect("one version stays active");
        assert!(state.staged_versions().contains(&active));
    }
}
