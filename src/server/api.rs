/// REST API server implementation
use axum::{
    Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::account::{create_account, deactivate_account, get_account, update_account};
use super::auth::api_key_auth;
use super::certificate::{
    get_certificate, list_certificates, renew_certificate, revoke_certificate,
};
use super::health::{HealthCheck, health_handler};
use super::order::{create_order, get_order, list_orders, trigger_full_renewal};
use super::webhook::{WebhookHandler, webhook_handler};
use crate::AcmeClient;
use crate::config::Config;
use crate::error::Result;
use crate::notifications::WebhookManager;
use crate::orchestrator::OrchestrationStatus;
use crate::scheduler::RenewalScheduler;
// Use the trait
use crate::storage::StorageBackend;

/// Information about an asynchronous task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub status: OrchestrationStatus,
    pub domains: Vec<String>,
}

/// Server state
#[derive(Clone)]
pub struct AppState {
    /// Global configuration
    pub config: Arc<Config>,
    /// ACME client
    pub client: Option<Arc<AcmeClient>>,
    /// Storage backend
    pub storage: Option<Arc<dyn StorageBackend>>,
    /// Health check
    pub health: Arc<HealthCheck>,
    /// Webhook handler
    pub webhook: Arc<WebhookHandler>,
    /// Async tasks tracker
    pub tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    /// Authorized API keys
    pub api_keys: Arc<Vec<String>>,
    /// Renewal scheduler
    pub scheduler: Option<Arc<dyn RenewalScheduler>>, // Use dyn trait
}

/// Start the API server
pub async fn start_server(
    addr: SocketAddr,
    config: Arc<Config>,
    client: Option<Arc<AcmeClient>>,
    storage: Option<Arc<dyn StorageBackend>>,
    webhook_manager: Arc<WebhookManager>,
    scheduler: Option<Arc<dyn RenewalScheduler>>, // Use dyn trait
) -> Result<()> {
    let health = Arc::new(HealthCheck::new());
    let webhook = Arc::new(WebhookHandler::new(webhook_manager));
    let tasks = Arc::new(RwLock::new(HashMap::new()));

    // Load API keys from environment variable ACMEX_API_KEYS (comma separated)
    let api_keys_str =
        std::env::var("ACMEX_API_KEYS").unwrap_or_else(|_| "secret-admin-key".to_string());
    let api_keys: Vec<String> = api_keys_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    let api_keys = Arc::new(api_keys);

    let state = AppState {
        config,
        client,
        storage,
        health: health.clone(),
        webhook,
        tasks,
        api_keys,
        scheduler,
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
        .route("/orders/renew-all", post(trigger_full_renewal))
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
