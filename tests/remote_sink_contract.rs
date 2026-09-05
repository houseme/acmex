//! Remote sink contract tests for the Kubernetes Secret and Vault KV
//! certificate sinks (`src/delivery/k8s_sink.rs` / `src/delivery/vault_sink.rs`).
//!
//! Local axum servers fake the Kubernetes API and Vault KV v2 so the full
//! stage → activate → health → rollback → cleanup lifecycle runs without
//! external systems, including optimistic concurrency (resourceVersion /
//! KV v2 CAS), retryable 5xx and operator-action 403 classifications.
//!
//! The sink sources are mounted directly into this test crate so the
//! implementations compile and run without touching `src/delivery/mod.rs`
//! (module registration and orchestrator wiring are done by the integrator).

#![allow(dead_code)] // contract scaffolding: fault-injection knobs and fixture fields

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use acmex::error::AcmeError;
use acmex::{
    CertificateMaterialBuilder, CertificateVersion, DeliveryRequirement, DeliveryTargetKind,
    IdentifierSet, KeyAlgorithm, KeyId, KeyRef, LineageId, SecretBytes, TargetId, VersionId,
    VersionState,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::Mutex;

// --- source mounting --------------------------------------------------------
// The sinks are written against the library's internal module paths
// (`crate::domain`, `crate::error`, `crate::dns::spec`, `super::` contract
// types). Mounting them at this crate's root with shim modules makes those
// paths resolve inside the test crate: `super::` is the crate root (re-exports
// below) and `crate::` goes through the `domain`/`error`/`dns` shims.

pub use acmex::{
    CertificateMaterial, CertificateMaterialRef, CertificateSink, CleanupOutcome, DeploymentHealth,
    DeploymentSpec, StagedDeployment,
};

mod domain {
    pub use acmex::domain::*;
}

mod error {
    pub use acmex::error::*;
}

mod dns {
    pub mod spec {
        pub use acmex::dns::spec::{SecretRef, SecretResolver};
    }
}

#[path = "../src/delivery/k8s_sink.rs"]
mod k8s_sink;

#[path = "../src/delivery/vault_sink.rs"]
mod vault_sink;

use k8s_sink::{KubernetesAuth, KubernetesSecretConfig, KubernetesSecretSink};
use vault_sink::{VaultAuth, VaultKvConfig, VaultKvSink};

const K8S_TOKEN: &str = "k8s-fake-bearer-token";
const VAULT_TOKEN: &str = "vault-fake-token";
const NAMESPACE: &str = "acmex-tests";
const MOUNT: &str = "secret";

// --- shared fixtures --------------------------------------------------------

fn sample_version(domain: &str) -> (CertificateVersion, String) {
    let certified = rcgen::generate_simple_self_signed([domain.to_string()]).unwrap();
    let version = CertificateVersion {
        id: VersionId::generate(),
        lineage_id: LineageId::generate(),
        identifiers: IdentifierSet::parse([domain]).unwrap(),
        certificate_chain_pem: certified.cert.pem(),
        serial: "01".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2026-04-01T00:00:00Z".into(),
        issued_by: "contract-ca".into(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Issued,
    };
    (version, certified.signing_key.serialize_pem())
}

fn build_material(version: &CertificateVersion, key: String) -> CertificateMaterial {
    CertificateMaterialBuilder::new()
        .require_private_key()
        .build(version, Some(SecretBytes::new(key.into_bytes())))
        .unwrap()
}

fn mat_ref(material: &CertificateMaterial) -> CertificateMaterialRef<'_> {
    CertificateMaterialRef { material }
}

fn k8s_spec(name: &str) -> DeploymentSpec {
    DeploymentSpec {
        target_id: TargetId::new("k8s-target").unwrap(),
        kind: DeliveryTargetKind::KubernetesSecret,
        reference: name.to_string(),
        requirement: DeliveryRequirement::Required,
    }
}

fn vault_spec(path: &str) -> DeploymentSpec {
    DeploymentSpec {
        target_id: TargetId::new("vault-target").unwrap(),
        kind: DeliveryTargetKind::VaultKv,
        reference: path.to_string(),
        requirement: DeliveryRequirement::Required,
    }
}

fn k8s_sink(base_url: &str) -> KubernetesSecretSink {
    KubernetesSecretSink::new(
        KubernetesSecretConfig {
            endpoint: Some(base_url.to_string()),
            namespace: NAMESPACE.to_string(),
            ca_path: None,
            connect_timeout_secs: 2,
            request_timeout_secs: 5,
        },
        KubernetesAuth::Token(K8S_TOKEN.to_string()),
    )
    .unwrap()
}

fn vault_sink(base_url: &str) -> VaultKvSink {
    VaultKvSink::new(
        VaultKvConfig {
            endpoint: base_url.to_string(),
            mount: MOUNT.to_string(),
            namespace: None,
            connect_timeout_secs: 2,
            request_timeout_secs: 5,
        },
        VaultAuth::Token(VAULT_TOKEN.to_string()),
    )
    .unwrap()
}

// --- fake Kubernetes API server ---------------------------------------------

type SecretKey = (String, String);

#[derive(Clone)]
struct FakeSecret {
    resource_version: u64,
    secret_type: String,
    annotations: HashMap<String, String>,
    /// Base64 values exactly as they travel on the wire.
    data: HashMap<String, String>,
}

#[derive(Default)]
struct K8sState {
    secrets: HashMap<SecretKey, FakeSecret>,
    next_resource_version: u64,
    /// Create/replace requests on these secrets answer 403 (RBAC denial).
    forbidden_writes: HashSet<SecretKey>,
    /// Replace requests answer 500 this many more times (server outage).
    fail_replace_500: HashMap<SecretKey, u32>,
    /// Every read of these secrets bumps resourceVersion afterwards, so a
    /// version observed just before is stale by the time it is used.
    bump_version_on_read: HashSet<SecretKey>,
}

impl K8sState {
    fn next_rv(&mut self) -> u64 {
        self.next_resource_version += 1;
        self.next_resource_version
    }
}

fn string_map(value: &serde_json::Value) -> HashMap<String, String> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn secret_body(secret: &FakeSecret) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": secret.secret_type,
        "metadata": {
            "name": "fake",
            "resourceVersion": secret.resource_version.to_string(),
            "annotations": secret.annotations,
        },
        "data": secret.data,
    })
}

fn k8s_status(code: StatusCode, reason: &str, message: &str) -> axum::response::Response {
    (
        code,
        axum::Json(serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "reason": reason,
            "code": code.as_u16(),
            "message": message,
        })),
    )
        .into_response()
}

async fn read_secret(
    State(state): State<Arc<Mutex<K8sState>>>,
    Path((namespace, name)): Path<(String, String)>,
) -> axum::response::Response {
    let mut state = state.lock().await;
    let key = (namespace, name.clone());
    let Some(secret) = state.secrets.get(&key) else {
        return k8s_status(
            StatusCode::NOT_FOUND,
            "NotFound",
            &format!("secrets \"{name}\" not found"),
        );
    };
    let body = secret_body(secret);
    if state.bump_version_on_read.contains(&key)
        && let Some(secret) = state.secrets.get_mut(&key)
    {
        secret.resource_version += 1;
    }
    (StatusCode::OK, axum::Json(body)).into_response()
}

async fn create_secret(
    State(state): State<Arc<Mutex<K8sState>>>,
    Path(namespace): Path<String>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(name) = body["metadata"]["name"].as_str().map(str::to_owned) else {
        return k8s_status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid",
            "metadata.name is required",
        );
    };
    let mut state = state.lock().await;
    let key = (namespace, name.clone());
    if state.forbidden_writes.contains(&key) {
        return k8s_status(
            StatusCode::FORBIDDEN,
            "Forbidden",
            &format!("secrets \"{name}\" is forbidden: User \"acmex\" cannot create resource"),
        );
    }
    if state.secrets.contains_key(&key) {
        return k8s_status(
            StatusCode::CONFLICT,
            "AlreadyExists",
            &format!("secrets \"{name}\" already exists"),
        );
    }
    let secret = FakeSecret {
        resource_version: state.next_rv(),
        secret_type: body["type"].as_str().unwrap_or("Opaque").to_string(),
        annotations: string_map(&body["metadata"]["annotations"]),
        data: string_map(&body["data"]),
    };
    let payload = secret_body(&secret);
    state.secrets.insert(key, secret);
    (StatusCode::CREATED, axum::Json(payload)).into_response()
}

async fn replace_secret(
    State(state): State<Arc<Mutex<K8sState>>>,
    Path((namespace, name)): Path<(String, String)>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    let mut state = state.lock().await;
    let key = (namespace, name.clone());
    if state.forbidden_writes.contains(&key) {
        return k8s_status(
            StatusCode::FORBIDDEN,
            "Forbidden",
            &format!("secrets \"{name}\" is forbidden: User \"acmex\" cannot update resource"),
        );
    }
    if let Some(remaining) = state.fail_replace_500.get_mut(&key)
        && *remaining > 0
    {
        *remaining -= 1;
        return k8s_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "apiserver is overloaded",
        );
    }
    let Some(current_rv) = state
        .secrets
        .get(&key)
        .map(|secret| secret.resource_version)
    else {
        return k8s_status(
            StatusCode::NOT_FOUND,
            "NotFound",
            &format!("secrets \"{name}\" not found"),
        );
    };
    let observed = body["metadata"]["resourceVersion"]
        .as_str()
        .and_then(|rv| rv.parse::<u64>().ok());
    if observed != Some(current_rv) {
        return k8s_status(
            StatusCode::CONFLICT,
            "Conflict",
            "Operation cannot be fulfilled on secrets: the object has been modified; please apply your changes to the latest version and try again",
        );
    }
    let new_rv = state.next_rv();
    let secret = state.secrets.get_mut(&key).expect("checked above");
    secret.secret_type = body["type"].as_str().unwrap_or("Opaque").to_string();
    secret.annotations = string_map(&body["metadata"]["annotations"]);
    secret.data = string_map(&body["data"]);
    secret.resource_version = new_rv;
    let payload = secret_body(secret);
    (StatusCode::OK, axum::Json(payload)).into_response()
}

async fn delete_secret(
    State(state): State<Arc<Mutex<K8sState>>>,
    Path((namespace, name)): Path<(String, String)>,
) -> axum::response::Response {
    let mut state = state.lock().await;
    if state.secrets.remove(&(namespace, name)).is_some() {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({"kind": "Status", "status": "Success"})),
        )
            .into_response()
    } else {
        k8s_status(StatusCode::NOT_FOUND, "NotFound", "secrets not found")
    }
}

async fn spawn_k8s(state: Arc<Mutex<K8sState>>) -> String {
    let app = Router::new()
        .route(
            "/api/v1/namespaces/{namespace}/secrets",
            axum::routing::post(create_secret),
        )
        .route(
            "/api/v1/namespaces/{namespace}/secrets/{name}",
            axum::routing::get(read_secret)
                .put(replace_secret)
                .delete(delete_secret),
        )
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let ok = req
                    .headers()
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value == format!("Bearer {K8S_TOKEN}"));
                if ok {
                    Ok(next.run(req).await)
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            },
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

// --- fake Vault KV v2 server --------------------------------------------------

#[derive(Clone)]
struct VaultVersion {
    version: u64,
    data: serde_json::Map<String, serde_json::Value>,
    destroyed: bool,
}

#[derive(Default)]
struct VaultState {
    /// Keyed by `"<mount>/<path>"`; version history newest last.
    entries: HashMap<String, Vec<VaultVersion>>,
    /// Writes to these paths answer 500 this many more times.
    fail_write_500: HashMap<String, u32>,
}

fn vault_error(code: StatusCode, errors: &[&str]) -> axum::response::Response {
    (code, axum::Json(serde_json::json!({ "errors": errors }))).into_response()
}

async fn vault_write(
    State(state): State<Arc<Mutex<VaultState>>>,
    Path((mount, path)): Path<(String, String)>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    let key = format!("{mount}/{path}");
    let mut state = state.lock().await;
    if let Some(remaining) = state.fail_write_500.get_mut(&key)
        && *remaining > 0
    {
        *remaining -= 1;
        return vault_error(StatusCode::INTERNAL_SERVER_ERROR, &["upstream timed out"]);
    }
    let versions = state.entries.entry(key).or_default();
    let current = versions.last().map(|v| v.version).unwrap_or(0);
    if let Some(cas) = body["options"]["cas"].as_u64()
        && cas != current
    {
        return vault_error(
            StatusCode::BAD_REQUEST,
            &["check-and-set parameter did not match the current version"],
        );
    }
    let data = body["data"].as_object().cloned().unwrap_or_default();
    let version = current + 1;
    versions.push(VaultVersion {
        version,
        data,
        destroyed: false,
    });
    (
        StatusCode::OK,
        axum::Json(
            serde_json::json!({ "data": { "version": version, "created_time": "2026-09-05T00:00:00Z" } }),
        ),
    )
        .into_response()
}

async fn vault_read(
    State(state): State<Arc<Mutex<VaultState>>>,
    Path((mount, path)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let state = state.lock().await;
    let key = format!("{mount}/{path}");
    let Some(versions) = state.entries.get(&key) else {
        return vault_error(StatusCode::NOT_FOUND, &["secret not found"]);
    };
    let found = match params.get("version").and_then(|v| v.parse::<u64>().ok()) {
        Some(want) => versions.iter().find(|v| v.version == want && !v.destroyed),
        None => versions.iter().rev().find(|v| !v.destroyed),
    };
    let Some(entry) = found else {
        return vault_error(StatusCode::NOT_FOUND, &["secret not found"]);
    };
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "data": entry.data,
                "metadata": { "version": entry.version, "destroyed": entry.destroyed },
            }
        })),
    )
        .into_response()
}

async fn vault_delete_metadata(
    State(state): State<Arc<Mutex<VaultState>>>,
    Path((mount, path)): Path<(String, String)>,
) -> axum::response::Response {
    let mut state = state.lock().await;
    // Stricter than real Vault (which answers 204 unconditionally): the fake
    // reports 404 so `AlreadyClean` stays observable.
    if state.entries.remove(&format!("{mount}/{path}")).is_some() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn vault_soft_delete(
    State(state): State<Arc<Mutex<VaultState>>>,
    Path((mount, path)): Path<(String, String)>,
) -> axum::response::Response {
    let mut state = state.lock().await;
    if let Some(versions) = state.entries.get_mut(&format!("{mount}/{path}")) {
        for version in versions.iter_mut() {
            version.destroyed = true;
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn spawn_vault(state: Arc<Mutex<VaultState>>) -> String {
    let app = Router::new()
        .route(
            "/v1/{mount}/data/{*path}",
            axum::routing::put(vault_write).get(vault_read),
        )
        .route(
            "/v1/{mount}/metadata/{*path}",
            axum::routing::delete(vault_delete_metadata),
        )
        .route(
            "/v1/{mount}/delete/{*path}",
            axum::routing::put(vault_soft_delete),
        )
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let ok = req
                    .headers()
                    .get("X-Vault-Token")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value == VAULT_TOKEN);
                if ok {
                    Ok(next.run(req).await)
                } else {
                    // Vault answers 403 for missing capabilities.
                    Err(StatusCode::FORBIDDEN)
                }
            },
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

// --- Kubernetes Secret sink contract -----------------------------------------

#[tokio::test]
async fn kubernetes_secret_sink_full_lifecycle() {
    let state = Arc::new(Mutex::new(K8sState::default()));
    let base_url = spawn_k8s(state.clone()).await;
    let sink = k8s_sink(&base_url);
    let spec = k8s_spec("acmex-lifecycle-tls");

    let (v1, key1) = sample_version("lifecycle-one.example.com");
    let material1 = build_material(&v1, key1.clone());
    let staged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    assert_eq!(staged1.resource_version, 0, "nothing active before staging");
    assert!(staged1.previous_active_ref.is_none());
    // Stage is idempotent: the same staging secret is reused.
    let restaged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    assert_eq!(restaged1.staged_ref, staged1.staged_ref);

    // Before activation nothing serves the material, but the API is
    // reachable → Unknown, not Unhealthy.
    assert!(matches!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Unknown(_)
    ));

    sink.activate(&staged1).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // Wire-level contract: TLS type, annotations and base64 payload.
    {
        let state = state.lock().await;
        let secret = state
            .secrets
            .get(&(NAMESPACE.to_string(), "acmex-lifecycle-tls".to_string()))
            .unwrap();
        assert_eq!(secret.secret_type, "kubernetes.io/tls");
        assert_eq!(secret.annotations["acmex.acme/version"], v1.id.as_str());
        assert_eq!(secret.annotations["acmex.acme/managed-by"], "acmex");
        assert_eq!(
            secret.annotations["acmex.acme/leaf-sha256"],
            material1.leaf_sha256
        );
        assert_eq!(
            STANDARD.decode(&secret.data["tls.key"]).unwrap(),
            key1.as_bytes()
        );
        assert_eq!(
            STANDARD.decode(&secret.data["tls.crt"]).unwrap(),
            material1.fullchain_pem.as_bytes()
        );
    }

    // A second version stages without touching the active secret.
    let (v2, key2) = sample_version("lifecycle-two.example.com");
    let material2 = build_material(&v2, key2);
    let staged2 = sink.stage(&spec, &v2, mat_ref(&material2)).await.unwrap();
    assert!(staged2.previous_active_ref.is_some());
    assert!(staged2.resource_version > 0, "CAS base is the active rv");
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy,
        "stage must not switch traffic"
    );

    sink.activate(&staged2).await.unwrap();
    assert_eq!(
        sink.health_check(&staged2).await.unwrap(),
        DeploymentHealth::Healthy
    );
    assert!(matches!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));
    // Activate is idempotent.
    sink.activate(&staged2).await.unwrap();
    assert_eq!(
        sink.health_check(&staged2).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // Rollback restores the previous version's content.
    sink.rollback(&staged2).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );
    assert!(matches!(
        sink.health_check(&staged2).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));
    // Rollback is idempotent.
    sink.rollback(&staged2).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // Cleanup removes the staging secret exactly once.
    assert_eq!(
        sink.cleanup(&staged2).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert_eq!(
        sink.cleanup(&staged2).await.unwrap(),
        CleanupOutcome::AlreadyClean
    );
}

#[tokio::test]
async fn kubernetes_secret_sink_replace_conflict_is_retryable() {
    let state = Arc::new(Mutex::new(K8sState::default()));
    let base_url = spawn_k8s(state.clone()).await;
    let sink = k8s_sink(&base_url);
    let spec = k8s_spec("acmex-contested-tls");

    let (v1, key1) = sample_version("contested-one.example.com");
    let material1 = build_material(&v1, key1);
    let staged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    sink.activate(&staged1).await.unwrap();

    // Every read makes the observed resourceVersion stale, so the guarded
    // replace must lose the race.
    state
        .lock()
        .await
        .bump_version_on_read
        .insert((NAMESPACE.to_string(), "acmex-contested-tls".to_string()));

    let (v2, key2) = sample_version("contested-two.example.com");
    let material2 = build_material(&v2, key2);
    let staged2 = sink.stage(&spec, &v2, mat_ref(&material2)).await.unwrap();
    let err = sink.activate(&staged2).await.unwrap_err();
    assert!(matches!(err, AcmeError::Conflict(_)), "got: {err}");
    // Error messages carry status and names, never key material.
    assert!(!err.to_string().contains("PRIVATE KEY"), "got: {err}");
}

#[tokio::test]
async fn kubernetes_secret_sink_forbidden_write_is_operator_action() {
    let state = Arc::new(Mutex::new(K8sState::default()));
    let base_url = spawn_k8s(state.clone()).await;
    let sink = k8s_sink(&base_url);
    let spec = k8s_spec("acmex-forbidden-tls");
    state
        .lock()
        .await
        .forbidden_writes
        .insert((NAMESPACE.to_string(), "acmex-forbidden-tls".to_string()));

    let (v1, key1) = sample_version("forbidden.example.com");
    let material1 = build_material(&v1, key1);
    let staged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    let err = sink.activate(&staged1).await.unwrap_err();
    assert!(
        matches!(err, AcmeError::Configuration(_)),
        "403 must classify as operator-action-required configuration error, got: {err}"
    );
    assert!(err.to_string().contains("operator"), "got: {err}");
}

#[tokio::test]
async fn kubernetes_secret_sink_server_outage_is_retryable_transport() {
    let state = Arc::new(Mutex::new(K8sState::default()));
    let base_url = spawn_k8s(state.clone()).await;
    let sink = k8s_sink(&base_url);
    let spec = k8s_spec("acmex-outage-tls");
    let staging_key = (
        NAMESPACE.to_string(),
        "staging-acmex-outage-tls".to_string(),
    );

    let (v1, key1) = sample_version("outage.example.com");
    let material1 = build_material(&v1, key1);
    let staged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();

    // The next re-stage replace hits a 500 → retryable Transport class.
    state.lock().await.fail_replace_500.insert(staging_key, 1);
    let err = sink
        .stage(&spec, &v1, mat_ref(&material1))
        .await
        .unwrap_err();
    assert!(matches!(err, AcmeError::Transport(_)), "got: {err}");

    // The same call succeeds after the outage clears (idempotent retry).
    sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    sink.activate(&staged1).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );
}

#[tokio::test]
async fn kubernetes_secret_sink_unreachable_is_unknown_health() {
    // Bind then drop a port to get an address nothing listens on.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let sink = k8s_sink(&format!("http://{addr}"));
    let staged = StagedDeployment {
        kind: DeliveryTargetKind::KubernetesSecret,
        target_id: TargetId::new("k8s").unwrap(),
        version_id: VersionId::generate(),
        staged_ref: format!("k8s://{NAMESPACE}/staging-acmex-tls"),
        previous_active_ref: None,
        leaf_sha256: "00".to_string(),
        resource_version: 0,
    };
    // Transient outages are Unknown, never Unhealthy (no rollback trigger).
    assert!(matches!(
        sink.health_check(&staged).await.unwrap(),
        DeploymentHealth::Unknown(_)
    ));
}

// --- Vault KV sink contract ---------------------------------------------------

#[tokio::test]
async fn vault_kv_sink_full_lifecycle() {
    let state = Arc::new(Mutex::new(VaultState::default()));
    let base_url = spawn_vault(state.clone()).await;
    let sink = vault_sink(&base_url);
    let spec = vault_spec("certs/lifecycle.example.com");

    let (v1, key1) = sample_version("vault-one.example.com");
    let material1 = build_material(&v1, key1.clone());
    let staged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    assert_eq!(staged1.resource_version, 0, "nothing active before staging");
    assert!(staged1.previous_active_ref.is_none());
    // Stage is idempotent: the same staging path is reused.
    let restaged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    assert_eq!(restaged1.staged_ref, staged1.staged_ref);

    assert!(matches!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Unknown(_)
    ));

    // Activate uses cas=0 (create-only) for the first version.
    sink.activate(&staged1).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );
    {
        let state = state.lock().await;
        let entry = state
            .entries
            .get(&format!("{MOUNT}/certs/lifecycle.example.com"))
            .unwrap();
        assert_eq!(entry.len(), 1);
        assert_eq!(entry[0].version, 1);
        assert_eq!(
            entry[0].data["certificate"].as_str().unwrap(),
            material1.cert_pem
        );
        assert_eq!(
            entry[0].data["fullchain"].as_str().unwrap(),
            material1.fullchain_pem
        );
        assert_eq!(entry[0].data["private_key"].as_str().unwrap(), key1);
        let metadata: serde_json::Value =
            serde_json::from_str(entry[0].data["metadata"].as_str().unwrap()).unwrap();
        assert_eq!(metadata["version_id"].as_str().unwrap(), v1.id.as_str());
        assert_eq!(
            metadata["leaf_sha256"].as_str().unwrap(),
            material1.leaf_sha256
        );
    }

    // A second version stages without touching the active entry.
    let (v2, key2) = sample_version("vault-two.example.com");
    let material2 = build_material(&v2, key2);
    let staged2 = sink.stage(&spec, &v2, mat_ref(&material2)).await.unwrap();
    assert_eq!(
        staged2.resource_version, 1,
        "the previous active version is the CAS base"
    );
    assert!(staged2.previous_active_ref.is_some());
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy,
        "stage must not switch traffic"
    );

    // Activate CAS-writes: cas=1 only applies while version 1 is current.
    sink.activate(&staged2).await.unwrap();
    assert_eq!(
        sink.health_check(&staged2).await.unwrap(),
        DeploymentHealth::Healthy
    );
    assert!(matches!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));
    {
        let state = state.lock().await;
        let entry = state
            .entries
            .get(&format!("{MOUNT}/certs/lifecycle.example.com"))
            .unwrap();
        assert_eq!(entry.len(), 2);
        assert_eq!(entry[1].version, 2);
        assert_eq!(
            entry[1].data["certificate"].as_str().unwrap(),
            material2.cert_pem
        );
    }

    // Rollback rewrites the stage-time version under a fresh CAS guard.
    sink.rollback(&staged2).await.unwrap();
    {
        let state = state.lock().await;
        let entry = state
            .entries
            .get(&format!("{MOUNT}/certs/lifecycle.example.com"))
            .unwrap();
        assert_eq!(entry.len(), 3, "rollback appends a restore version");
        assert_eq!(
            entry[2].data["certificate"].as_str().unwrap(),
            material1.cert_pem,
            "rollback restores the previous certificate"
        );
    }
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );
    assert!(matches!(
        sink.health_check(&staged2).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));
    // Rollback is idempotent.
    sink.rollback(&staged2).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // Cleanup removes the staging path exactly once.
    assert_eq!(
        sink.cleanup(&staged2).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert_eq!(
        sink.cleanup(&staged2).await.unwrap(),
        CleanupOutcome::AlreadyClean
    );
}

#[tokio::test]
async fn vault_kv_sink_cas_conflict_is_retryable() {
    let state = Arc::new(Mutex::new(VaultState::default()));
    let base_url = spawn_vault(state.clone()).await;
    let sink = vault_sink(&base_url);
    let spec = vault_spec("certs/contested.example.com");

    let (v1, key1) = sample_version("contested-vault-one.example.com");
    let material1 = build_material(&v1, key1);
    let staged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    sink.activate(&staged1).await.unwrap();

    let (v2, key2) = sample_version("contested-vault-two.example.com");
    let material2 = build_material(&v2, key2);
    let staged2 = sink.stage(&spec, &v2, mat_ref(&material2)).await.unwrap();
    assert_eq!(staged2.resource_version, 1);

    // An external writer bumps the active entry to version 2 while we staged
    // against version 1: the CAS-guarded activate must refuse to overwrite.
    {
        let mut state = state.lock().await;
        let entry = state
            .entries
            .get_mut(&format!("{MOUNT}/certs/contested.example.com"))
            .unwrap();
        entry.push(VaultVersion {
            version: 2,
            data: serde_json::Map::new(),
            destroyed: false,
        });
    }

    let err = sink.activate(&staged2).await.unwrap_err();
    assert!(matches!(err, AcmeError::Conflict(_)), "got: {err}");
    assert!(!err.to_string().contains("PRIVATE KEY"), "got: {err}");
}

#[tokio::test]
async fn vault_kv_sink_forbidden_token_is_operator_action() {
    let state = Arc::new(Mutex::new(VaultState::default()));
    let base_url = spawn_vault(state).await;
    let sink = VaultKvSink::new(
        VaultKvConfig {
            endpoint: base_url,
            mount: MOUNT.to_string(),
            namespace: None,
            connect_timeout_secs: 2,
            request_timeout_secs: 5,
        },
        VaultAuth::Token("wrong-token".to_string()),
    )
    .unwrap();

    let (v1, key1) = sample_version("forbidden-vault.example.com");
    let material1 = build_material(&v1, key1);
    let err = sink
        .stage(
            &vault_spec("certs/forbidden.example.com"),
            &v1,
            mat_ref(&material1),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, AcmeError::Configuration(_)),
        "403 must classify as operator-action-required configuration error, got: {err}"
    );
    assert!(err.to_string().contains("operator"), "got: {err}");
}

#[tokio::test]
async fn vault_kv_sink_server_outage_is_retryable_transport() {
    let state = Arc::new(Mutex::new(VaultState::default()));
    let base_url = spawn_vault(state.clone()).await;
    let sink = vault_sink(&base_url);
    let spec = vault_spec("certs/outage.example.com");
    state
        .lock()
        .await
        .fail_write_500
        .insert(format!("{MOUNT}/certs/outage.example.com-staging"), 1);

    let (v1, key1) = sample_version("vault-outage.example.com");
    let material1 = build_material(&v1, key1);
    let err = sink
        .stage(&spec, &v1, mat_ref(&material1))
        .await
        .unwrap_err();
    assert!(matches!(err, AcmeError::Transport(_)), "got: {err}");

    // The same call succeeds after the outage clears (idempotent retry).
    let staged1 = sink.stage(&spec, &v1, mat_ref(&material1)).await.unwrap();
    sink.activate(&staged1).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );
}

#[tokio::test]
async fn vault_kv_sink_unreachable_is_unknown_health() {
    // Bind then drop a port to get an address nothing listens on.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let sink = vault_sink(&format!("http://{addr}"));
    let staged = StagedDeployment {
        kind: DeliveryTargetKind::VaultKv,
        target_id: TargetId::new("vault").unwrap(),
        version_id: VersionId::generate(),
        staged_ref: format!("vault://{MOUNT}/certs/acmex.example.com-staging"),
        previous_active_ref: None,
        leaf_sha256: "00".to_string(),
        resource_version: 0,
    };
    // Transient outages are Unknown, never Unhealthy (no rollback trigger).
    assert!(matches!(
        sink.health_check(&staged).await.unwrap(),
        DeploymentHealth::Unknown(_)
    ));
}

// --- shared contract ----------------------------------------------------------

#[tokio::test]
async fn sinks_reject_foreign_target_kinds() {
    let k8s_base = spawn_k8s(Arc::new(Mutex::new(K8sState::default()))).await;
    let vault_base = spawn_vault(Arc::new(Mutex::new(VaultState::default()))).await;
    let k8s = k8s_sink(&k8s_base);
    let vault = vault_sink(&vault_base);

    let (version, key) = sample_version("foreign.example.com");
    let material = build_material(&version, key);
    let spec = DeploymentSpec {
        target_id: TargetId::new("fs").unwrap(),
        kind: DeliveryTargetKind::File,
        reference: "/tmp".to_string(),
        requirement: DeliveryRequirement::Required,
    };

    let k8s_err = k8s
        .stage(&spec, &version, mat_ref(&material))
        .await
        .unwrap_err();
    let vault_err = vault
        .stage(&spec, &version, mat_ref(&material))
        .await
        .unwrap_err();
    assert!(
        matches!(k8s_err, AcmeError::InvalidInput(_)),
        "got: {k8s_err}"
    );
    assert!(
        matches!(vault_err, AcmeError::InvalidInput(_)),
        "got: {vault_err}"
    );
}

#[test]
fn auth_debug_redacts_tokens() {
    let k8s_auth = KubernetesAuth::Token("k8s-super-secret".to_string());
    let vault_auth = VaultAuth::Token("vault-super-secret".to_string());
    let k8s_debug = format!("{k8s_auth:?}");
    let vault_debug = format!("{vault_auth:?}");
    assert!(!k8s_debug.contains("k8s-super-secret"), "got: {k8s_debug}");
    assert!(k8s_debug.contains("redacted"), "got: {k8s_debug}");
    assert!(
        !vault_debug.contains("vault-super-secret"),
        "got: {vault_debug}"
    );
    assert!(vault_debug.contains("redacted"), "got: {vault_debug}");
}
