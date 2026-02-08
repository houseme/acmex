/// REST API server implementation for AcmeX.
/// This module provides the Axum-based web server that exposes endpoints for
/// account management, certificate ordering, and system health monitoring.
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
use crate::storage::StorageBackend;

/// Information about an asynchronous orchestration task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    /// The current status of the task (e.g., InProgress, Completed, Failed).
    pub status: OrchestrationStatus,
    /// The domains associated with this task.
    pub domains: Vec<String>,
}

/// Shared application state for the API server.
#[derive(Clone)]
pub struct AppState {
    /// Global system configuration.
    pub config: Arc<Config>,
    /// Shared ACME client instance.
    pub client: Option<Arc<AcmeClient>>,
    /// Pluggable storage backend.
    pub storage: Option<Arc<dyn StorageBackend>>,
    /// Health monitoring component.
    pub health: Arc<HealthCheck>,
    /// Webhook notification handler.
    pub webhook: Arc<WebhookHandler>,
    /// Thread-safe tracker for background tasks.
    pub tasks: Arc<RwLock<HashMap<String, TaskInfo>>>,
    /// List of authorized API keys for authentication.
    pub api_keys: Arc<Vec<String>>,
    /// The certificate renewal scheduler.
    pub scheduler: Option<Arc<dyn RenewalScheduler>>,
}

/// Starts the REST API server on the specified address.
///
/// This function initializes the router, applies middleware (like API key auth),
/// and starts the Axum server loop.
pub async fn start_server(
    addr: SocketAddr,
    config: Arc<Config>,
    client: Option<Arc<AcmeClient>>,
    storage: Option<Arc<dyn StorageBackend>>,
    webhook_manager: Arc<WebhookManager>,
    scheduler: Option<Arc<dyn RenewalScheduler>>,
) -> Result<()> {
    tracing::info!("Initializing AcmeX API server on {}", addr);

    let health = Arc::new(HealthCheck::new());
    let webhook = Arc::new(WebhookHandler::new(webhook_manager));
    let tasks = Arc::new(RwLock::new(HashMap::new()));

    // Load API keys from environment variable ACMEX_API_KEYS (comma separated)
    let api_keys_str = std::env::var("ACMEX_API_KEYS").unwrap_or_else(|_| {
        tracing::warn!("ACMEX_API_KEYS not set, using default insecure key");
        "secret-admin-key".to_string()
    });
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

    // Define API routes with authentication middleware
    let api_routes = Router::new()
        // Account management endpoints
        .route("/accounts", post(create_account))
        .route(
            "/accounts/:id",
            get(get_account)
                .patch(update_account)
                .delete(deactivate_account),
        )
        // Order and renewal endpoints
        .route("/orders", get(list_orders).post(create_order))
        .route("/orders/renew-all", post(trigger_full_renewal))
        .route("/orders/:id", get(get_order))
        // Certificate management endpoints
        .route("/certificates", get(list_certificates))
        .route("/certificates/:id", get(get_certificate))
        .route("/certificates/:id/renew", post(renew_certificate))
        .route("/certificates/:id/revoke", post(revoke_certificate))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api_key_auth,
        ));

    // Combine all routes
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/webhook", post(webhook_handler))
        .nest("/api", api_routes)
        .with_state(state);

    // Bind and serve
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        tracing::error!("Failed to bind to address {}: {}", addr, e);
        crate::error::AcmeError::transport(format!("Failed to bind API server: {}", e))
    })?;

    tracing::info!("AcmeX API server is now listening on http://{}", addr);

    axum::serve(listener, app).await.map_err(|e| {
        tracing::error!("Axum server error: {}", e);
        crate::error::AcmeError::transport(format!("Server error: {}", e))
    })?;

    Ok(())
}

// Axum state extraction implementations
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
