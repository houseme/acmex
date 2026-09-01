//! HTTP/TLS edge ports for challenge routing.
//!
//! Production deployments usually terminate HTTP and TLS at an ingress,
//! proxy, load balancer or remote agent. These ports let challenge presenters
//! install precise, short-lived validation routes without the central
//! orchestrator owning port 80 or 443.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::presenter::CleanupOutcome;
use crate::challenge::ChallengeSession;
use crate::error::Result;

/// An HTTP-01 route to install at an edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpChallengeRoute {
    /// Idempotency key, normally the challenge session id.
    pub idempotency_key: String,
    /// The exact HTTP-01 challenge token.
    pub token: String,
    /// The key authorization served for this token.
    pub key_authorization: String,
    /// Route TTL; edges should expire stale routes if the owner vanishes.
    pub ttl_secs: u64,
}

/// A persisted handle on an installed HTTP edge route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRouteLease {
    /// Which edge/agent owns the route.
    pub agent_id: String,
    /// Route identifier within the agent.
    pub route_id: String,
    /// SHA-256 token hash; diagnostics and leases never persist raw tokens.
    pub token_hash: String,
}

/// State of an installed HTTP route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRouteState {
    /// Whether the route currently serves the expected content.
    pub serving: bool,
    /// Remaining TTL, if the agent reports it.
    pub ttl_secs: Option<u64>,
}

/// Installs and manages HTTP-01 routes at a network edge.
#[async_trait]
pub trait HttpChallengeEdge: Send + Sync {
    /// The edge agent identity.
    fn agent_id(&self) -> &str;

    /// Installs a route. Reusing the same idempotency key returns the same route id.
    async fn install(&self, route: HttpChallengeRoute) -> Result<HttpRouteLease>;

    /// Inspects a previously installed route.
    async fn inspect(&self, lease: &HttpRouteLease) -> Result<HttpRouteState>;

    /// Removes a route. Absence is an idempotent success.
    async fn remove(&self, lease: &HttpRouteLease) -> Result<CleanupOutcome>;
}

/// A TLS-ALPN-01 route to install at an edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsChallengeRoute {
    /// Idempotency key, normally the challenge session id.
    pub idempotency_key: String,
    /// SNI name to match. RFC 8738 IP identifiers use reverse DNS names here.
    pub sni: String,
    /// DER-encoded validation certificate.
    pub certificate_der: Vec<u8>,
    /// DER-encoded private key matching the validation certificate.
    pub private_key_der: Vec<u8>,
    /// SHA-256 fingerprint of the validation certificate.
    pub fingerprint: String,
    /// Route TTL; edges should expire stale routes if the owner vanishes.
    pub ttl_secs: u64,
}

/// A persisted handle on an installed TLS edge route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRouteLease {
    /// Which edge/agent owns the route.
    pub agent_id: String,
    /// Route identifier within the agent.
    pub route_id: String,
    /// SNI name the edge route matches.
    pub sni: String,
    /// SHA-256 fingerprint of the validation certificate.
    pub fingerprint: String,
}

/// State of an installed TLS route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRouteState {
    /// Whether the route currently serves the expected validation certificate.
    pub serving: bool,
    /// Remaining TTL, if the agent reports it.
    pub ttl_secs: Option<u64>,
}

/// Installs and manages TLS-ALPN-01 routes at a network edge.
#[async_trait]
pub trait TlsChallengeEdge: Send + Sync {
    /// The edge agent identity.
    fn agent_id(&self) -> &str;

    /// Installs a route. Reusing the same idempotency key returns the same route id.
    async fn install(&self, route: TlsChallengeRoute) -> Result<TlsRouteLease>;

    /// Inspects a previously installed route.
    async fn inspect(&self, lease: &TlsRouteLease) -> Result<TlsRouteState>;

    /// Removes a route. Absence is an idempotent success.
    async fn remove(&self, lease: &TlsRouteLease) -> Result<CleanupOutcome>;
}

/// An in-memory HTTP edge agent for tests and single-process deployments.
#[derive(Default)]
pub struct FakeHttpEdge {
    agent_id: String,
    routes: Mutex<HashMap<String, HttpChallengeRoute>>,
}

impl FakeHttpEdge {
    /// Creates a fake HTTP edge with the given identity.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            routes: Mutex::new(HashMap::new()),
        }
    }

    /// Returns all installed routes.
    pub async fn routes(&self) -> Vec<HttpChallengeRoute> {
        self.routes.lock().await.values().cloned().collect()
    }
}

#[async_trait]
impl HttpChallengeEdge for FakeHttpEdge {
    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    async fn install(&self, route: HttpChallengeRoute) -> Result<HttpRouteLease> {
        let route_id = route.idempotency_key.clone();
        let token_hash = ChallengeSession::hash_token(&route.token);
        self.routes.lock().await.insert(route_id.clone(), route);
        Ok(HttpRouteLease {
            agent_id: self.agent_id.clone(),
            route_id,
            token_hash,
        })
    }

    async fn inspect(&self, lease: &HttpRouteLease) -> Result<HttpRouteState> {
        let routes = self.routes.lock().await;
        Ok(match routes.get(&lease.route_id) {
            Some(route) if ChallengeSession::hash_token(&route.token) == lease.token_hash => {
                HttpRouteState {
                    serving: true,
                    ttl_secs: Some(route.ttl_secs),
                }
            }
            _ => HttpRouteState {
                serving: false,
                ttl_secs: None,
            },
        })
    }

    async fn remove(&self, lease: &HttpRouteLease) -> Result<CleanupOutcome> {
        Ok(
            if self.routes.lock().await.remove(&lease.route_id).is_some() {
                CleanupOutcome::Cleaned
            } else {
                CleanupOutcome::AlreadyAbsent
            },
        )
    }
}

/// An in-memory TLS edge agent for tests and single-process deployments.
#[derive(Default)]
pub struct FakeTlsEdge {
    agent_id: String,
    routes: Mutex<HashMap<String, TlsChallengeRoute>>,
}

impl FakeTlsEdge {
    /// Creates a fake TLS edge with the given identity.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            routes: Mutex::new(HashMap::new()),
        }
    }

    /// Returns all installed routes.
    pub async fn routes(&self) -> Vec<TlsChallengeRoute> {
        self.routes.lock().await.values().cloned().collect()
    }
}

#[async_trait]
impl TlsChallengeEdge for FakeTlsEdge {
    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    async fn install(&self, route: TlsChallengeRoute) -> Result<TlsRouteLease> {
        let route_id = route.idempotency_key.clone();
        let lease = TlsRouteLease {
            agent_id: self.agent_id.clone(),
            route_id: route_id.clone(),
            sni: route.sni.clone(),
            fingerprint: route.fingerprint.clone(),
        };
        self.routes.lock().await.insert(route_id, route);
        Ok(lease)
    }

    async fn inspect(&self, lease: &TlsRouteLease) -> Result<TlsRouteState> {
        let routes = self.routes.lock().await;
        Ok(match routes.get(&lease.route_id) {
            Some(route) if route.sni == lease.sni && route.fingerprint == lease.fingerprint => {
                TlsRouteState {
                    serving: true,
                    ttl_secs: Some(route.ttl_secs),
                }
            }
            _ => TlsRouteState {
                serving: false,
                ttl_secs: None,
            },
        })
    }

    async fn remove(&self, lease: &TlsRouteLease) -> Result<CleanupOutcome> {
        Ok(
            if self.routes.lock().await.remove(&lease.route_id).is_some() {
                CleanupOutcome::Cleaned
            } else {
                CleanupOutcome::AlreadyAbsent
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_http_edge_is_idempotent_and_precise() {
        let edge = FakeHttpEdge::new("http-edge");
        let route = HttpChallengeRoute {
            idempotency_key: "session-1".to_string(),
            token: "token-a".to_string(),
            key_authorization: "token-a.thumbprint".to_string(),
            ttl_secs: 30,
        };

        let lease = edge.install(route.clone()).await.unwrap();
        assert_eq!(lease.route_id, "session-1");
        assert!(edge.inspect(&lease).await.unwrap().serving);

        let wrong_hash = HttpRouteLease {
            token_hash: ChallengeSession::hash_token("other-token"),
            ..lease.clone()
        };
        assert!(!edge.inspect(&wrong_hash).await.unwrap().serving);

        let lease_again = edge.install(route).await.unwrap();
        assert_eq!(lease, lease_again);
        assert_eq!(edge.routes().await.len(), 1);

        assert_eq!(edge.remove(&lease).await.unwrap(), CleanupOutcome::Cleaned);
        assert_eq!(
            edge.remove(&lease).await.unwrap(),
            CleanupOutcome::AlreadyAbsent
        );
    }

    #[tokio::test]
    async fn fake_tls_edge_matches_sni_and_fingerprint() {
        let edge = FakeTlsEdge::new("tls-edge");
        let route = TlsChallengeRoute {
            idempotency_key: "session-1".to_string(),
            sni: "example.com".to_string(),
            certificate_der: vec![1, 2, 3],
            private_key_der: vec![4, 5, 6],
            fingerprint: "fp-a".to_string(),
            ttl_secs: 30,
        };

        let lease = edge.install(route).await.unwrap();
        assert!(edge.inspect(&lease).await.unwrap().serving);

        let wrong_sni = TlsRouteLease {
            sni: "other.example".to_string(),
            ..lease.clone()
        };
        assert!(!edge.inspect(&wrong_sni).await.unwrap().serving);

        assert_eq!(edge.remove(&lease).await.unwrap(), CleanupOutcome::Cleaned);
        assert_eq!(
            edge.remove(&lease).await.unwrap(),
            CleanupOutcome::AlreadyAbsent
        );
    }
}
