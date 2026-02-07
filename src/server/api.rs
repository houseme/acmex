/// REST API server implementation
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use super::account::{create_account, deactivate_account, get_account, update_account};
use super::auth::api_key_auth;
use super::certificate::{
    get_certificate, list_certificates, renew_certificate, revoke_certificate,
};
use super::health::{health_handler, HealthCheck};
use super::order::{create_order, get_order, list_orders};
use super::webhook::{webhook_handler, WebhookHandler};
use crate::error::Result;
use crate::notifications::WebhookManager;
use crate::AcmeClient;

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
    let api_routes = Router::new()
        // Account routes
        .route("/accounts", post(create_account))
        .route(
            "/accounts/:id",
            get(get_account)
                .patch(update_account)
                .delete(deactivate_account),
        )
        // Order routes
        .route("/orders", get(list_orders).post(create_order))
        .route("/orders/:id", get(get_order))
        // Certificate routes
        .route("/certificates", get(list_certificates))
        .route("/certificates/:id", get(get_certificate))
        .route("/certificates/:id/renew", post(renew_certificate))
        .route("/certificates/:id/revoke", post(revoke_certificate))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api_key_auth,
        ));

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/webhook", post(webhook_handler))
        .nest("/api", api_routes)
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
