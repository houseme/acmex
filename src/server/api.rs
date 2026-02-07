/// REST API server implementation
use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use super::health::{HealthCheck, health_handler};
use super::webhook::{WebhookHandler, webhook_handler};
use crate::AcmeClient;
use crate::error::Result;
use crate::notifications::WebhookManager;

/// Server state
#[derive(Clone)]
pub struct AppState {
    /// ACME client
    pub client: Option<Arc<AcmeClient>>,
    /// Health check
    pub health: Arc<HealthCheck>,
    /// Webhook handler
    pub webhook: Arc<WebhookHandler>,
}

/// Start the API server
pub async fn start_server(
    addr: SocketAddr,
    client: Option<Arc<AcmeClient>>,
    webhook_manager: Arc<WebhookManager>,
) -> Result<()> {
    let health = Arc::new(HealthCheck::new());
    let webhook = Arc::new(WebhookHandler::new(webhook_manager));

    let state = AppState {
        client,
        health: health.clone(),
        webhook,
    };

    // Build router
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/webhook", post(webhook_handler))
        // Add more routes here
        .with_state(state);

    // Create listener
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        crate::error::AcmeError::transport(format!("Failed to bind API server: {}", e))
    })?;

    tracing::info!("API server listening on {}", addr);

    // Start server
    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::AcmeError::transport(format!("Server error: {}", e)))?;

    Ok(())
}

// Implement FromRef for sub-states to allow extracting specific parts of state
impl axum::extract::FromRef<AppState> for Arc<HealthCheck> {
    fn from_ref(state: &AppState) -> Self {
        state.health.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<WebhookHandler> {
    fn from_ref(state: &AppState) -> Self {
        state.webhook.clone()
    }
}
