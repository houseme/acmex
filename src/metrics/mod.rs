/// Metrics and health endpoints
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use std::sync::Arc;

/// Health status for the service
#[derive(Debug, Clone, Copy)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Metrics registry wrapper
pub struct MetricsRegistry {
    registry: Registry,
    pub requests_total: IntCounter,
    pub renewals_total: IntCounter,
    pub certs_managed: IntGauge,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let registry = Registry::new();
        let requests_total = IntCounter::new("acmex_requests_total", "Total requests").unwrap();
        let renewals_total = IntCounter::new("acmex_renewals_total", "Total renewals").unwrap();
        let certs_managed = IntGauge::new("acmex_certs_managed", "Managed cert count").unwrap();

        registry.register(Box::new(requests_total.clone())).unwrap();
        registry.register(Box::new(renewals_total.clone())).unwrap();
        registry.register(Box::new(certs_managed.clone())).unwrap();

        Self {
            registry,
            requests_total,
            renewals_total,
            certs_managed,
        }
    }

    pub fn gather_text(&self) -> String {
        let encoder = TextEncoder::new();
        let mf = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&mf, &mut buffer).unwrap();
        String::from_utf8_lossy(&buffer).to_string()
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check response
pub fn health_status(status: HealthStatus) -> (&'static str, u16) {
    match status {
        HealthStatus::Healthy => ("ok", 200),
        HealthStatus::Degraded => ("degraded", 200),
        HealthStatus::Unhealthy => ("unhealthy", 503),
    }
}

/// Shared metrics type
pub type SharedMetrics = Arc<MetricsRegistry>;
