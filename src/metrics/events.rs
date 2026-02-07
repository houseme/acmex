use serde::Serialize;
use tracing::info;

/// ACME significant events for auditing
#[derive(Debug, Serialize)]
pub enum AcmeEvent {
    AccountCreated {
        email: String,
    },
    AccountKeyRollover,
    OrderCreated {
        domains: Vec<String>,
    },
    ChallengeSolved {
        domain: String,
        challenge_type: String,
    },
    CertificateIssued {
        domains: Vec<String>,
    },
    CertificateRevoked {
        serial: String,
    },
}

/// Audit logger for ACME events
pub struct EventAuditor;

impl EventAuditor {
    /// Track a significant event
    pub fn track_event(event: AcmeEvent) {
        let event_json = serde_json::to_string(&event).unwrap_or_default();
        info!(target: "acmex_audit", event = %event_json, "ACME event occurred");
    }
}
