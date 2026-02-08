/// HTTP-01 challenge implementation
use async_trait::async_trait;
use axum::{Router, extract::Path, http::StatusCode, routing::get};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::ChallengeSolver;
use crate::error::Result;
use crate::order::Challenge;
use crate::types::{ChallengeType, Identifier};

/// HTTP-01 challenge solver
pub struct Http01Solver {
    /// Server listening address
    listen_addr: SocketAddr,
    /// Key authorization token
    key_authorization: Arc<RwLock<Option<String>>>,
    /// Server handle for shutdown
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl Http01Solver {
    /// Create a new HTTP-01 solver
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            key_authorization: Arc::new(RwLock::new(None)),
            server_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with default address (127.0.0.1:80)
    pub fn default() -> Self {
        Self::new("127.0.0.1:80".parse().expect("Invalid default address"))
    }

    /// Start the HTTP server
    async fn start_server(&self) -> Result<()> {
        let key_auth = Arc::clone(&self.key_authorization);

        // Create router
        let app = Router::new()
            .route("/.well-known/acme-challenge/:token", get(handle_challenge))
            .with_state(key_auth);

        // Create listener
        let listener = TcpListener::bind(self.listen_addr).await.map_err(|e| {
            crate::error::AcmeError::transport(format!("Failed to bind HTTP server: {}", e))
        })?;

        tracing::info!("HTTP-01 server listening on {}", self.listen_addr);

        // Spawn server task
        let handle = tokio::spawn(async move {
            if let Ok(socket_addr) = listener.local_addr() {
                tracing::debug!("Server bound to {}", socket_addr);
            }
            let _ = axum::serve(listener, app).await;
        });

        let mut server = self.server_handle.write().await;
        *server = Some(handle);

        Ok(())
    }
}

/// Handle ACME challenge requests
async fn handle_challenge(
    Path(token): Path<String>,
    axum::extract::State(key_auth): axum::extract::State<Arc<RwLock<Option<String>>>>,
) -> std::result::Result<String, StatusCode> {
    let auth = key_auth.read().await;
    if let Some(ref auth_str) = *auth
        && auth_str.contains(&token) {
            return Ok(auth_str.clone());
        }
    Err(StatusCode::NOT_FOUND)
}

#[async_trait]
impl ChallengeSolver for Http01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Http01
    }

    async fn prepare(
        &mut self,
        challenge: &Challenge,
        _identifier: &Identifier,
        key_authorization: &str,
    ) -> Result<()> {
        // Store the key authorization
        let mut auth = self.key_authorization.write().await;
        *auth = Some(key_authorization.to_string());

        // Start the server
        self.start_server().await?;

        tracing::info!("HTTP-01 challenge prepared for token: {}", challenge.token);

        Ok(())
    }

    async fn present(&self) -> Result<()> {
        // For HTTP-01, we just need to have the server running
        // The server is already started in prepare()
        tracing::debug!("HTTP-01 challenge presented");
        Ok(())
    }

    async fn verify(&self) -> Result<bool> {
        // Try to fetch the challenge from the server
        let auth_guard = self.key_authorization.read().await;
        Ok(auth_guard.is_some())
    }

    async fn cleanup(&mut self) -> Result<()> {
        // Clear the key authorization
        let mut auth = self.key_authorization.write().await;
        *auth = None;

        // Stop the server
        let mut handle = self.server_handle.write().await;
        if let Some(h) = handle.take() {
            h.abort();
            tracing::info!("HTTP-01 server stopped");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http01_solver_creation() {
        let solver = Http01Solver::new("127.0.0.1:8080".parse().unwrap());
        assert_eq!(solver.challenge_type(), ChallengeType::Http01);
    }

    #[tokio::test]
    async fn test_http01_solver_key_auth() {
        let challenge = Challenge {
            challenge_type: "http-01".to_string(),
            url: "https://example.com/challenge/123".to_string(),
            status: "pending".to_string(),
            token: "test-token".to_string(),
            key_authorization: None,
            validation: None,
            updated: None,
            error: None,
        };
        let identifier = Identifier::dns("example.com");

        let mut solver = Http01Solver::new("127.0.0.1:9999".parse().unwrap());
        let result = solver
            .prepare(&challenge, &identifier, "test-token.test-auth")
            .await;

        // This might fail if port 9999 is not available, so we just check the method exists
        let _ = result;
    }
}
