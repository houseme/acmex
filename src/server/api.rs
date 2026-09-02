/// REST API server implementation for AcmeX.
/// This module provides the Axum-based web server that exposes endpoints for
/// account management, certificate ordering, and system health monitoring.
use axum::{
    Router,
    body::Body,
    http::{HeaderValue, header::HeaderName},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::account::{create_account, deactivate_account, get_account, update_account};
use super::auth::{ApiKeySet, Authorizer, PermissionAuthorizer, api_key_auth};
use super::certificate::{
    get_certificate, list_certificates, renew_certificate, revoke_certificate,
};
use super::health::{HealthCheck, diagnostics_handler, health_handler, ready_handler};
use super::order::{create_order, get_order, list_orders, trigger_full_renewal};
use super::webhook::{WebhookHandler, webhook_handler};
use crate::AcmeClient;
use crate::application::{
    ApplicationServiceBuilder, CertificateApplication, CertificateQuery,
    RepositoryCertificateApplication,
};
use crate::config::Config;
use crate::error::Result;
use crate::notifications::WebhookManager;
use crate::orchestrator::OrchestrationStatus;
use crate::renewal::{ControllerRenewalScheduler, RenewalController, RenewalControllerConfig};
use crate::repository::RepositorySet;
use crate::scheduler::RenewalScheduler;
use crate::storage::StorageBackend;

/// Legacy `/api` removal horizon. T21 owns the final release decision and
/// must update this value if the v0.9/v0.10 release path changes.
pub const LEGACY_API_SUNSET_HTTP_DATE: &str = "Wed, 31 Mar 2027 23:59:59 GMT";
const LEGACY_API_MIGRATION_LINK: &str = "</docs/API_V1_MIGRATION.md>; rel=\"deprecation\"";

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
    pub api_keys: Arc<ApiKeySet>,
    /// Authorization policy for management API permissions.
    pub authorizer: Arc<dyn Authorizer>,
    /// The certificate renewal scheduler.
    pub scheduler: Option<Arc<dyn RenewalScheduler>>,
    /// v0.9 aggregate repositories used by Application Service and API v1.
    pub repositories: Option<RepositorySet>,
    /// Mutating lifecycle use cases.
    pub application: Option<Arc<dyn CertificateApplication>>,
    /// Query-side lifecycle projections.
    pub query: Option<Arc<dyn CertificateQuery>>,
}

/// Adds RFC 8594-style deprecation metadata to every legacy `/api`
/// response. New lifecycle capabilities are mounted under `/api/v1`; this
/// layer is only applied to the older task/order/certificate/account
/// compatibility surface.
pub async fn add_legacy_api_deprecation_headers(
    request: axum::extract::Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("deprecation"),
        HeaderValue::from_static("true"),
    );
    headers.insert(
        HeaderName::from_static("sunset"),
        HeaderValue::from_static(LEGACY_API_SUNSET_HTTP_DATE),
    );
    headers.insert(
        HeaderName::from_static("link"),
        HeaderValue::from_static(LEGACY_API_MIGRATION_LINK),
    );
    response
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

    let (_, repositories) = ApplicationServiceBuilder::from_config(&config)
        .await?
        .build()?;

    // Shared metrics registry: observed by the ACME transport and exposed on
    // the dedicated scrape listener (see `metrics_endpoint`).
    let metrics: crate::metrics::SharedMetrics = Arc::new(crate::metrics::MetricsRegistry::new());
    super::metrics_endpoint::spawn_from_config(&config, metrics.clone());

    let api_repositories = repositories.clone().observe_errors(metrics.clone());
    let application_service = Arc::new(RepositoryCertificateApplication::new(
        api_repositories.clone(),
    ));
    let query: Arc<dyn CertificateQuery> = application_service.clone();
    let application: Arc<dyn CertificateApplication> = application_service;

    // The durable workflow worker: real executors (CA backend, challenge
    // presenters, key provider, deployment orchestration) advancing queued
    // operations. Assembly failures (e.g. unreadable key store) are logged,
    // not fatal: the API stays up while the loop is down.
    match super::worker::spawn_from_config(
        &config,
        repositories.clone(),
        metrics.clone(),
        super::worker::WorkflowWorkerSettings {
            http01_listen: config
                .challenge
                .http01
                .as_ref()
                .map(|http| http.listen_addr.clone()),
            secret_store_dir: super::worker::default_secret_store_dir(&config),
            ..Default::default()
        },
    )
    .await
    {
        Ok(handle) => {
            tokio::spawn(async move {
                if handle.await.is_err() {
                    tracing::error!("workflow worker task terminated unexpectedly");
                }
            });
        }
        Err(err) => {
            tracing::error!(error = %err, "workflow worker not started");
        }
    }

    let scheduler = scheduler.or_else(|| {
        // Key-free RFC 9773 ARI provider over the metrics-instrumented
        // transport (shared assembly with the CLI daemon).
        let ari = super::worker::build_ari_provider(&config, metrics.clone());
        let controller = RenewalController::new(
            repositories.clone(),
            application.clone(),
            RenewalControllerConfig::default(),
        )
        .with_ari_provider(ari)
        .with_metrics(metrics.clone());
        Some(Arc::new(ControllerRenewalScheduler::new(controller)) as Arc<dyn RenewalScheduler>)
    });

    // Load API keys from environment variable ACMEX_API_KEYS (comma separated).
    // Without explicit credentials only the unauthenticated health route is
    // exposed; management APIs are not mounted with a default key.
    let api_keys = std::env::var("ACMEX_API_KEYS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let api_keys = Arc::new(ApiKeySet::from_plaintext_keys(api_keys));
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
        authorizer: Arc::new(PermissionAuthorizer),
        scheduler,
        repositories: Some(api_repositories),
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
        .route("/diagnostics", get(diagnostics_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api_key_auth,
        ))
        .layer(middleware::from_fn(add_legacy_api_deprecation_headers));
    let api_v1_routes = super::api_v1::routes().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        api_key_auth,
    ));

    // Combine all routes
    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler));
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

/// Maps a configured CA name to a low-cardinality metric label
/// (alphanumerics plus `-`/`_`; everything else collapses to `_`).
pub(crate) fn sanitize_ca_label(ca: &str) -> String {
    let cleaned: String = ca
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "custom".to_string()
    } else {
        cleaned
    }
}

impl axum::extract::FromRef<AppState> for Arc<WebhookHandler> {
    fn from_ref(state: &AppState) -> Self {
        state.webhook.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_ca_label;

    #[test]
    fn ca_labels_stay_low_cardinality() {
        assert_eq!(sanitize_ca_label("letsencrypt"), "letsencrypt");
        assert_eq!(sanitize_ca_label("Let's Encrypt"), "let_s_encrypt");
        assert_eq!(
            sanitize_ca_label("https://ca.example.com/dir"),
            "https___ca_example_com_dir"
        );
        assert_eq!(sanitize_ca_label(""), "custom");
    }
}
