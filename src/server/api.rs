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
use crate::application::{ApplicationServiceBuilder, CertificateApplication, CertificateQuery};
use crate::config::Config;
use crate::error::Result;
use crate::notifications::WebhookManager;
use crate::orchestrator::OrchestrationStatus;
use crate::renewal::{ControllerRenewalScheduler, RenewalController, RenewalControllerConfig};
use crate::repository::RepositorySet;
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
    /// v0.9 aggregate repositories used by Application Service and API v1.
    pub repositories: Option<RepositorySet>,
    /// Mutating lifecycle use cases.
    pub application: Option<Arc<dyn CertificateApplication>>,
    /// Query-side lifecycle projections.
    pub query: Option<Arc<dyn CertificateQuery>>,
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

    let (application_service, repositories) = ApplicationServiceBuilder::from_config(&config)
        .await?
        .build()?;
    let query: Arc<dyn CertificateQuery> = application_service.clone();
    let application: Arc<dyn CertificateApplication> = application_service;
    let scheduler = scheduler.or_else(|| {
        let controller = RenewalController::new(
            repositories.clone(),
            application.clone(),
            RenewalControllerConfig::default(),
        );
        Some(Arc::new(ControllerRenewalScheduler::new(controller)) as Arc<dyn RenewalScheduler>)
    });

    // Load API keys from environment variable ACMEX_API_KEYS (comma separated).
    // Without explicit credentials only the unauthenticated health route is
    // exposed; management APIs are not mounted with a default key.
    let api_keys: Vec<String> = std::env::var("ACMEX_API_KEYS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let api_keys = Arc::new(api_keys);
    let api_enabled = !api_keys.is_empty();

    let scheduler_loop = scheduler.clone();
    let check_interval = config
        .renewal_check_interval()
        .max(std::time::Duration::from_secs(1));
    if let Some(scheduler) = scheduler_loop {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                if let Err(err) = scheduler.run_once().await {
                    tracing::error!("renewal controller scan failed: {err}");
                }
            }
        });
    }

    let state = AppState {
        config,
        client,
        storage,
        health: health.clone(),
        webhook,
        tasks,
        api_keys,
        scheduler,
        repositories: Some(repositories),
        application: Some(application),
        query: Some(query),
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
    let api_v1_routes = super::api_v1::routes().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        api_key_auth,
    ));

    // Combine all routes
    let mut app = Router::new().route("/health", get(health_handler));
    if !api_enabled {
        tracing::warn!("ACMEX_API_KEYS not set; management API routes are disabled");
    } else {
        app = app
            .route("/webhook", post(webhook_handler))
            .nest("/api", api_routes)
            .nest("/api/v1", api_v1_routes);
    }
    let app = app.with_state(state);

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
