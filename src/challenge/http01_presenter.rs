//! HTTP-01 presenter with concurrent tokens, shared listener support and
//! RFC 8738 IP-aware observation endpoints.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::response::IntoResponse;
use axum::{Router, extract::Path, http::StatusCode, routing::get};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

use super::ChallengePresenter;
use super::edge::{HttpChallengeEdge, HttpChallengeRoute, HttpRouteLease, HttpRouteState};
use super::presenter::{CleanupOutcome, Observation, PrepareChallenge};
use crate::challenge::ChallengeSession;
use crate::domain::challenge::{ChallengeLease, ChallengeLeaseLocator, ChallengeLeaseState};
use crate::error::{AcmeError, Result};
use crate::types::{ChallengeType, Identifier};

/// Concurrent token to key-authorization registry. Lookups are exact matches.
#[derive(Default)]
pub struct TokenRegistry {
    tokens: RwLock<HashMap<String, String>>,
}

impl TokenRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces a token.
    pub async fn insert(&self, token: &str, key_authorization: &str) {
        self.tokens
            .write()
            .await
            .insert(token.to_string(), key_authorization.to_string());
    }

    /// Removes a token; returns whether it existed.
    pub async fn remove(&self, token: &str) -> bool {
        self.tokens.write().await.remove(token).is_some()
    }

    /// Whether a token is registered.
    pub async fn contains(&self, token: &str) -> bool {
        self.tokens.read().await.contains_key(token)
    }

    /// Looks up the exact key authorization for a token.
    pub async fn lookup(&self, token: &str) -> Option<String> {
        self.tokens.read().await.get(token).cloned()
    }

    /// Number of registered tokens.
    pub async fn len(&self) -> usize {
        self.tokens.read().await.len()
    }

    /// Whether no tokens are registered.
    pub async fn is_empty(&self) -> bool {
        self.tokens.read().await.is_empty()
    }
}

/// HTTP-01 presenter backed by a local or remote edge.
pub struct Http01Presenter {
    edge: Arc<dyn HttpChallengeEdge>,
    listener: Option<Arc<LocalHttpListener>>,
    external_observation: bool,
}

impl Http01Presenter {
    /// Creates a presenter backed by an edge agent.
    pub fn with_edge(edge: Arc<dyn HttpChallengeEdge>) -> Self {
        Self {
            edge,
            listener: None,
            external_observation: false,
        }
    }

    /// Enables a best-effort GET against the public challenge URL during
    /// observation, after the edge reports the route as serving.
    pub fn with_external_observation(mut self, enabled: bool) -> Self {
        self.external_observation = enabled;
        self
    }

    /// Creates a presenter with one shared in-process HTTP listener.
    pub async fn with_local_listener(listen_addr: SocketAddr) -> Result<Self> {
        let registry = Arc::new(TokenRegistry::new());
        let listener = Arc::new(LocalHttpListener::bind(listen_addr, Arc::clone(&registry)).await?);
        let edge = Arc::new(LocalHttpEdge::new(Arc::clone(&registry)));
        Ok(Self {
            edge,
            listener: Some(listener),
            external_observation: false,
        })
    }

    /// The bound local address, if this presenter owns a local listener.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.as_ref().map(|listener| listener.local_addr)
    }

    /// Builds a local URL for tests and diagnostics.
    pub fn local_challenge_url(&self, token: &str) -> Option<String> {
        self.local_addr()
            .map(|addr| format!("http://{addr}/.well-known/acme-challenge/{token}"))
    }
}

/// Shared local HTTP-01 listener.
pub struct LocalHttpListener {
    local_addr: SocketAddr,
    _handle: tokio::task::JoinHandle<()>,
}

impl LocalHttpListener {
    async fn bind(listen_addr: SocketAddr, registry: Arc<TokenRegistry>) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr).await.map_err(|err| {
            AcmeError::transport(format!(
                "[OPERATOR_ACTION_REQUIRED] cannot bind HTTP-01 listener at {listen_addr}: {err}; \
                 configure an HTTP edge agent, ingress route or port permission"
            ))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|err| AcmeError::transport(format!("read HTTP-01 local address: {err}")))?;
        let app = Router::new()
            .route("/.well-known/acme-challenge/{token}", get(handle_challenge))
            .with_state(registry);
        let handle = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                tracing::warn!(error = %err, "HTTP-01 local listener stopped");
            }
        });
        Ok(Self {
            local_addr,
            _handle: handle,
        })
    }
}

async fn handle_challenge(
    Path(token): Path<String>,
    axum::extract::State(registry): axum::extract::State<Arc<TokenRegistry>>,
) -> std::result::Result<axum::response::Response, StatusCode> {
    match registry.lookup(&token).await {
        Some(key_authorization) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            key_authorization,
        )
            .into_response()),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Local listener edge adapter. Route id is the session id; token lives only in memory.
struct LocalHttpEdge {
    registry: Arc<TokenRegistry>,
    routes: Mutex<HashMap<String, String>>,
}

impl LocalHttpEdge {
    fn new(registry: Arc<TokenRegistry>) -> Self {
        Self {
            registry,
            routes: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl HttpChallengeEdge for LocalHttpEdge {
    fn agent_id(&self) -> &str {
        "local-http-listener"
    }

    async fn install(&self, route: HttpChallengeRoute) -> Result<HttpRouteLease> {
        let route_id = route.idempotency_key.clone();
        let token_hash = ChallengeSession::hash_token(&route.token);
        self.registry
            .insert(&route.token, &route.key_authorization)
            .await;
        self.routes
            .lock()
            .await
            .insert(route_id.clone(), route.token);
        Ok(HttpRouteLease {
            agent_id: self.agent_id().to_string(),
            route_id,
            token_hash,
        })
    }

    async fn inspect(&self, lease: &HttpRouteLease) -> Result<HttpRouteState> {
        let token = self.routes.lock().await.get(&lease.route_id).cloned();
        let serving = match token {
            Some(token) if ChallengeSession::hash_token(&token) == lease.token_hash => {
                self.registry.contains(&token).await
            }
            _ => false,
        };
        Ok(HttpRouteState {
            serving,
            ttl_secs: None,
        })
    }

    async fn remove(&self, lease: &HttpRouteLease) -> Result<CleanupOutcome> {
        let token = self.routes.lock().await.remove(&lease.route_id);
        match token {
            Some(token) => {
                self.registry.remove(&token).await;
                Ok(CleanupOutcome::Cleaned)
            }
            None => Ok(CleanupOutcome::AlreadyAbsent),
        }
    }
}

/// Builds the ACME HTTP-01 observation URL. IP identifiers are contacted
/// directly; IPv6 literals are bracketed for RFC 3986 URI syntax.
pub fn http01_url(identifier: &Identifier, token: &str) -> String {
    let host = match identifier {
        Identifier::Dns(name) => name.to_wire_value(),
        Identifier::Ip(std::net::IpAddr::V4(addr)) => addr.to_string(),
        Identifier::Ip(std::net::IpAddr::V6(addr)) => format!("[{addr}]"),
    };
    format!("http://{host}/.well-known/acme-challenge/{token}")
}

/// Returns the Host header value expected for HTTP-01 observation.
pub fn http01_host_header(identifier: &Identifier) -> String {
    match identifier {
        Identifier::Dns(name) => name.to_wire_value(),
        Identifier::Ip(std::net::IpAddr::V4(addr)) => addr.to_string(),
        Identifier::Ip(std::net::IpAddr::V6(addr)) => format!("[{addr}]"),
    }
}

#[async_trait]
impl ChallengePresenter for Http01Presenter {
    fn kind(&self) -> ChallengeType {
        ChallengeType::Http01
    }

    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease> {
        if request.session.challenge_type != ChallengeType::Http01 {
            return Err(AcmeError::invalid_input(format!(
                "HTTP-01 presenter cannot prepare {:?}",
                request.session.challenge_type
            )));
        }
        if request.session.identifier.is_wildcard() {
            return Err(AcmeError::invalid_input(
                "HTTP-01 cannot validate wildcard DNS identifiers",
            ));
        }

        let token = request
            .key_authorization
            .split('.')
            .next()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| AcmeError::invalid_input("key authorization is missing token"))?
            .to_string();
        let token_hash = ChallengeSession::hash_token(&token);
        let route_lease = self
            .edge
            .install(HttpChallengeRoute {
                idempotency_key: request.session.id.clone(),
                token: token.clone(),
                key_authorization: request.key_authorization,
                ttl_secs: 3600,
            })
            .await?;

        let now = jiff::Timestamp::now();
        Ok(ChallengeLease {
            id: crate::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id,
            identifier: request.session.identifier.clone(),
            challenge_type: ChallengeType::Http01,
            locator: ChallengeLeaseLocator::Http {
                agent_id: route_lease.agent_id,
                route_id: route_lease.route_id,
                token_hash,
                endpoint: http01_url(&request.session.identifier, &token),
            },
            created_at: now,
            expires_at: now.checked_add(jiff::Span::new().hours(1)).unwrap_or(now),
            state: ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation> {
        let ChallengeLeaseLocator::Http {
            agent_id,
            route_id,
            token_hash,
            endpoint,
        } = &lease.locator
        else {
            return Ok(Observation::Propagated);
        };

        let edge_state = self
            .edge
            .inspect(&HttpRouteLease {
                agent_id: agent_id.clone(),
                route_id: route_id.clone(),
                token_hash: token_hash.clone(),
            })
            .await?;
        if !edge_state.serving {
            return Ok(Observation::NotYet {
                retry_after: Duration::from_secs(2),
            });
        }

        if let Some(listener) = &self.listener {
            let token = extract_token(endpoint);
            let local_endpoint = format!(
                "http://{}/.well-known/acme-challenge/{token}",
                listener.local_addr
            );
            return observe_http_endpoint(local_endpoint).await;
        }

        if self.external_observation {
            return observe_http_endpoint(endpoint.clone()).await;
        }

        Ok(Observation::Propagated)
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome> {
        let ChallengeLeaseLocator::Http {
            agent_id,
            route_id,
            token_hash,
            ..
        } = &lease.locator
        else {
            return Ok(CleanupOutcome::AlreadyAbsent);
        };
        self.edge
            .remove(&HttpRouteLease {
                agent_id: agent_id.clone(),
                route_id: route_id.clone(),
                token_hash: token_hash.clone(),
            })
            .await
    }
}

async fn observe_http_endpoint(endpoint: String) -> Result<Observation> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| AcmeError::transport(format!("build HTTP-01 observer: {err}")))?;
    match client.get(endpoint).send().await {
        Ok(response) if response.status().is_success() => Ok(Observation::Propagated),
        Ok(_) | Err(_) => Ok(Observation::NotYet {
            retry_after: Duration::from_secs(3),
        }),
    }
}

fn extract_token(endpoint: &str) -> &str {
    endpoint.rsplit('/').next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::ChallengeSessionState;
    use crate::domain::OperationId;

    fn session(identifier: Identifier) -> ChallengeSession {
        ChallengeSession {
            id: "session-http".to_string(),
            operation_id: OperationId::generate(),
            authorization_url: "https://ca.example/authz/1".to_string(),
            challenge_url: "https://ca.example/challenge/1".to_string(),
            identifier,
            challenge_type: ChallengeType::Http01,
            token_hash: ChallengeSession::hash_token("token-a"),
            state: ChallengeSessionState::Selected,
            lease_id: None,
            deadline: jiff::Timestamp::now()
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap(),
            last_propagation_check_at: None,
            last_propagation_status: None,
            last_ca_poll_at: None,
            last_ca_status: None,
            last_error: None,
        }
    }

    #[test]
    fn http01_url_forms() {
        let dns = Identifier::try_dns("example.com").unwrap();
        assert_eq!(
            http01_url(&dns, "tok"),
            "http://example.com/.well-known/acme-challenge/tok"
        );
        assert_eq!(http01_host_header(&dns), "example.com");

        let v4 = Identifier::try_ip("192.0.2.1").unwrap();
        assert_eq!(
            http01_url(&v4, "tok"),
            "http://192.0.2.1/.well-known/acme-challenge/tok"
        );
        assert_eq!(http01_host_header(&v4), "192.0.2.1");

        let v6 = Identifier::try_ip("2001:db8::1").unwrap();
        assert_eq!(
            http01_url(&v6, "tok"),
            "http://[2001:db8::1]/.well-known/acme-challenge/tok"
        );
        assert_eq!(http01_host_header(&v6), "[2001:db8::1]");
    }

    #[tokio::test]
    async fn token_registry_exact_match() {
        let registry = TokenRegistry::new();
        registry.insert("token-a", "token-a.fingerprint-a").await;
        registry.insert("token-ab", "token-ab.fingerprint-b").await;

        assert_eq!(
            registry.lookup("token-a").await,
            Some("token-a.fingerprint-a".to_string())
        );
        assert_eq!(registry.lookup("token-").await, None);
        assert!(registry.remove("token-a").await);
        assert!(!registry.remove("token-a").await);
        assert_eq!(registry.len().await, 1);
    }

    #[tokio::test]
    async fn local_listener_serves_concurrent_exact_tokens_and_cleans_one() {
        let presenter = Http01Presenter::with_local_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let lease_a = presenter
            .prepare(PrepareChallenge {
                session: session(Identifier::try_dns("example.com").unwrap()),
                key_authorization: "token-a.thumbprint-a".to_string(),
            })
            .await
            .unwrap();
        let mut second = session(Identifier::try_dns("www.example.com").unwrap());
        second.id = "session-http-b".to_string();
        let lease_b = presenter
            .prepare(PrepareChallenge {
                session: second,
                key_authorization: "token-ab.thumbprint-b".to_string(),
            })
            .await
            .unwrap();

        let url_a = presenter.local_challenge_url("token-a").unwrap();
        let body_a = reqwest::get(url_a).await.unwrap().text().await.unwrap();
        assert_eq!(body_a, "token-a.thumbprint-a");
        let url_b = presenter.local_challenge_url("token-ab").unwrap();
        let body_b = reqwest::get(url_b).await.unwrap().text().await.unwrap();
        assert_eq!(body_b, "token-ab.thumbprint-b");

        assert_eq!(
            presenter.observe(&lease_a).await.unwrap(),
            Observation::Propagated
        );
        assert_eq!(
            presenter.cleanup(&lease_a).await.unwrap(),
            CleanupOutcome::Cleaned
        );
        assert_eq!(
            reqwest::get(presenter.local_challenge_url("token-a").unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            reqwest::get(presenter.local_challenge_url("token-ab").unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            presenter.cleanup(&lease_b).await.unwrap(),
            CleanupOutcome::Cleaned
        );
    }

    #[tokio::test]
    async fn wildcard_dns_is_rejected() {
        let presenter =
            Http01Presenter::with_edge(Arc::new(super::super::edge::FakeHttpEdge::new("edge")));
        let err = presenter
            .prepare(PrepareChallenge {
                session: session(Identifier::try_dns("*.example.com").unwrap()),
                key_authorization: "token.thumbprint".to_string(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("wildcard"));
    }
}
