/// Metrics and health endpoints
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
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
    pub operations_total: IntCounterVec,
    pub operation_step_duration_seconds: HistogramVec,
    pub acme_requests_total: IntCounterVec,
    pub acme_request_duration_seconds: HistogramVec,
    pub bad_nonce_total: IntCounterVec,
    pub challenge_propagation_seconds: HistogramVec,
    pub challenge_cleanup_pending: IntGaugeVec,
    pub renewal_due: IntGaugeVec,
    pub renewal_failures_total: IntCounterVec,
    pub certificate_seconds_to_expiry: IntGaugeVec,
    pub deployment_total: IntCounterVec,
    pub outbox_pending: IntGaugeVec,
    pub repository_errors_total: IntCounterVec,
}

impl MetricsRegistry {
    pub fn registered_metric_names() -> &'static [&'static str] {
        &[
            "acmex_operations_total",
            "acmex_operation_step_duration_seconds",
            "acmex_acme_requests_total",
            "acmex_acme_request_duration_seconds",
            "acmex_bad_nonce_total",
            "acmex_challenge_propagation_seconds",
            "acmex_challenge_cleanup_pending",
            "acmex_renewal_due",
            "acmex_renewal_failures_total",
            "acmex_certificate_seconds_to_expiry",
            "acmex_deployment_total",
            "acmex_outbox_pending",
            "acmex_repository_errors_total",
        ]
    }

    pub fn new() -> Self {
        let registry = Registry::new();
        let requests_total = IntCounter::new("acmex_requests_total", "Total requests").unwrap();
        let renewals_total = IntCounter::new("acmex_renewals_total", "Total renewals").unwrap();
        let certs_managed = IntGauge::new("acmex_certs_managed", "Managed cert count").unwrap();
        let operations_total = IntCounterVec::new(
            Opts::new("acmex_operations_total", "Certificate lifecycle operations"),
            &["kind", "result", "error_class"],
        )
        .unwrap();
        let operation_step_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "acmex_operation_step_duration_seconds",
                "Operation step duration",
            ),
            &["workflow_step", "result", "error_class"],
        )
        .unwrap();
        let acme_requests_total = IntCounterVec::new(
            Opts::new("acmex_acme_requests_total", "ACME requests"),
            &["ca", "result", "error_class"],
        )
        .unwrap();
        let acme_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "acmex_acme_request_duration_seconds",
                "ACME request duration",
            ),
            &["ca", "result", "error_class"],
        )
        .unwrap();
        let bad_nonce_total = IntCounterVec::new(
            Opts::new("acmex_bad_nonce_total", "ACME bad nonce responses"),
            &["ca"],
        )
        .unwrap();
        let challenge_propagation_seconds = HistogramVec::new(
            HistogramOpts::new(
                "acmex_challenge_propagation_seconds",
                "Challenge propagation duration",
            ),
            &["challenge_type", "provider_type", "result"],
        )
        .unwrap();
        let challenge_cleanup_pending = IntGaugeVec::new(
            Opts::new(
                "acmex_challenge_cleanup_pending",
                "Challenge resources awaiting cleanup",
            ),
            &["challenge_type", "provider_type"],
        )
        .unwrap();
        let renewal_due = IntGaugeVec::new(
            Opts::new("acmex_renewal_due", "Renewals due by priority"),
            &["ca", "priority"],
        )
        .unwrap();
        let renewal_failures_total = IntCounterVec::new(
            Opts::new("acmex_renewal_failures_total", "Renewal failures"),
            &["ca", "error_class"],
        )
        .unwrap();
        let certificate_seconds_to_expiry = IntGaugeVec::new(
            Opts::new(
                "acmex_certificate_seconds_to_expiry",
                "Seconds until managed certificate expiry",
            ),
            &["ca", "state"],
        )
        .unwrap();
        let deployment_total = IntCounterVec::new(
            Opts::new("acmex_deployment_total", "Deployment attempts"),
            &["sink_type", "result", "error_class"],
        )
        .unwrap();
        let outbox_pending = IntGaugeVec::new(
            Opts::new("acmex_outbox_pending", "Pending outbox events"),
            &["event_type"],
        )
        .unwrap();
        let repository_errors_total = IntCounterVec::new(
            Opts::new("acmex_repository_errors_total", "Repository errors"),
            &["backend", "error_class"],
        )
        .unwrap();

        registry.register(Box::new(requests_total.clone())).unwrap();
        registry.register(Box::new(renewals_total.clone())).unwrap();
        registry.register(Box::new(certs_managed.clone())).unwrap();
        registry
            .register(Box::new(operations_total.clone()))
            .unwrap();
        registry
            .register(Box::new(operation_step_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(acme_requests_total.clone()))
            .unwrap();
        registry
            .register(Box::new(acme_request_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(bad_nonce_total.clone()))
            .unwrap();
        registry
            .register(Box::new(challenge_propagation_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(challenge_cleanup_pending.clone()))
            .unwrap();
        registry.register(Box::new(renewal_due.clone())).unwrap();
        registry
            .register(Box::new(renewal_failures_total.clone()))
            .unwrap();
        registry
            .register(Box::new(certificate_seconds_to_expiry.clone()))
            .unwrap();
        registry
            .register(Box::new(deployment_total.clone()))
            .unwrap();
        registry.register(Box::new(outbox_pending.clone())).unwrap();
        registry
            .register(Box::new(repository_errors_total.clone()))
            .unwrap();

        Self {
            registry,
            requests_total,
            renewals_total,
            certs_managed,
            operations_total,
            operation_step_duration_seconds,
            acme_requests_total,
            acme_request_duration_seconds,
            bad_nonce_total,
            challenge_propagation_seconds,
            challenge_cleanup_pending,
            renewal_due,
            renewal_failures_total,
            certificate_seconds_to_expiry,
            deployment_total,
            outbox_pending,
            repository_errors_total,
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

/// Validates labels against the T11 low-cardinality convention.
pub fn validate_metric_label(label: &str, value: &str) -> bool {
    const FORBIDDEN_LABELS: &[&str] = &["operation_id", "domain", "identifier", "serial"];
    const ALLOWED_LABELS: &[&str] = &[
        "backend",
        "ca",
        "challenge_type",
        "error_class",
        "event_type",
        "provider_type",
        "priority",
        "result",
        "sink_type",
        "state",
        "workflow_step",
        "kind",
    ];
    !FORBIDDEN_LABELS.contains(&label)
        && ALLOWED_LABELS.contains(&label)
        && !value.starts_with("op_")
        && (label == "event_type" || !value.contains('.'))
        && !value.contains("-----BEGIN")
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

pub mod events;

pub use events::{AcmeEvent, AuditEvent, AuditOutcome, EventAuditor};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t11_metrics_are_registered() {
        let names = MetricsRegistry::registered_metric_names();
        for expected in [
            "acmex_operations_total",
            "acmex_operation_step_duration_seconds",
            "acmex_acme_requests_total",
            "acmex_bad_nonce_total",
            "acmex_challenge_propagation_seconds",
            "acmex_outbox_pending",
            "acmex_repository_errors_total",
        ] {
            assert!(names.contains(&expected), "missing metric {expected}");
        }
    }

    #[test]
    fn metric_label_validator_blocks_high_cardinality_values() {
        assert!(validate_metric_label("ca", "letsencrypt"));
        assert!(!validate_metric_label("operation_id", "op_abc"));
        assert!(!validate_metric_label("ca", "example.com"));
        assert!(!validate_metric_label("serial", "00ff"));
    }
}
