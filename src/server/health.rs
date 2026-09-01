/// Health check implementation
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::AcmeError;
use crate::metrics::HealthStatus;
use crate::server::api::AppState;

/// Health check response
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Version
    pub version: String,
    /// Uptime in seconds
    pub uptime: u64,
    /// Component status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub checks: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsResponse {
    pub repository_backend: String,
    pub scheduler_configured: bool,
    pub pending_outbox: usize,
    pub cleanup_pending: usize,
    pub configured_metrics: &'static [&'static str],
}

/// Health check handler
pub struct HealthCheck {
    /// Start time
    start_time: std::time::Instant,
    /// Component status
    components: Arc<RwLock<std::collections::HashMap<String, HealthStatus>>>,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCheck {
    /// Create a new health check handler
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            components: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a component
    pub async fn register_component(&self, name: &str, status: HealthStatus) {
        let mut components = self.components.write().await;
        components.insert(name.to_string(), status);
    }

    /// Update component status
    pub async fn update_status(&self, name: &str, status: HealthStatus) {
        let mut components = self.components.write().await;
        if let Some(s) = components.get_mut(name) {
            *s = status;
        }
    }

    /// Get health status
    pub async fn get_status(&self) -> HealthResponse {
        let components = self.components.read().await;
        let component_map: std::collections::HashMap<String, String> = components
            .iter()
            .map(|(k, v)| (k.clone(), format!("{:?}", v)))
            .collect();

        let overall_status = if components
            .values()
            .any(|s| matches!(s, HealthStatus::Unhealthy))
        {
            "unhealthy"
        } else if components
            .values()
            .any(|s| matches!(s, HealthStatus::Degraded))
        {
            "degraded"
        } else {
            "healthy"
        };

        HealthResponse {
            status: overall_status.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: self.start_time.elapsed().as_secs(),
            components: Some(component_map),
        }
    }
}

/// Axum handler for health check
pub async fn health_handler(
    axum::extract::State(health): axum::extract::State<Arc<HealthCheck>>,
) -> impl IntoResponse {
    let status = health.get_status().await;

    let code = match status.status.as_str() {
        "healthy" => StatusCode::OK,
        "degraded" => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };

    (code, Json(status))
}

/// Readiness check for load balancers. It intentionally returns coarse
/// dependency names and avoids secret values or provider-specific reasons.
pub async fn ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut checks = std::collections::HashMap::new();
    let mut ready = true;

    match state.config.validate() {
        Ok(()) => {
            checks.insert("configuration".to_string(), "ready".to_string());
        }
        Err(_) => {
            checks.insert("configuration".to_string(), "not_ready".to_string());
            ready = false;
        }
    }

    if state.repositories.is_some() {
        checks.insert("repository".to_string(), "ready".to_string());
    } else {
        checks.insert("repository".to_string(), "not_ready".to_string());
        ready = false;
    }

    if state.scheduler.is_some() {
        checks.insert("worker".to_string(), "ready".to_string());
    } else {
        checks.insert("worker".to_string(), "not_configured".to_string());
    }

    if state.api_keys.is_empty() {
        checks.insert("management_credentials".to_string(), "missing".to_string());
        ready = false;
    } else {
        checks.insert("management_credentials".to_string(), "ready".to_string());
    }

    let body = ReadinessResponse {
        status: if ready { "ready" } else { "not_ready" }.to_string(),
        checks,
    };
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}

/// Authenticated operational diagnostics. This is intentionally separate
/// from readiness so external dependency flaps do not eject all API pods.
pub async fn diagnostics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let result = async {
        let repositories = state
            .repositories
            .as_ref()
            .ok_or_else(|| AcmeError::configuration("repository is not configured"))?;
        let pending_outbox = repositories.outbox.list_pending(1000).await?.len();
        let cleanup_pending = repositories
            .challenge_leases
            .list_needing_cleanup()
            .await?
            .len();
        Ok::<_, AcmeError>(DiagnosticsResponse {
            repository_backend: state.config.repository.backend.clone(),
            scheduler_configured: state.scheduler.is_some(),
            pending_outbox,
            cleanup_pending,
            configured_metrics: crate::metrics::MetricsRegistry::registered_metric_names(),
        })
    }
    .await;

    match result {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "unavailable"})),
        )
            .into_response(),
    }
}
