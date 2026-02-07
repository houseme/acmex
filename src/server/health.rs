/// Health check implementation
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::metrics::HealthStatus;

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

/// Health check handler
pub struct HealthCheck {
    /// Start time
    start_time: std::time::Instant,
    /// Component status
    components: Arc<RwLock<std::collections::HashMap<String, HealthStatus>>>,
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

        let overall_status = if components.values().any(|s| matches!(s, HealthStatus::Unhealthy)) {
            "unhealthy"
        } else if components.values().any(|s| matches!(s, HealthStatus::Degraded)) {
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
