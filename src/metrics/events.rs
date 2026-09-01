use crate::application::ActorContext;
use crate::error::Result;
use crate::repository::{RepositorySet, Revision};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
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

    /// Persist a structured audit event through the durable outbox.
    pub async fn track_audit(repositories: &RepositorySet, event: AuditEvent) -> Result<u64> {
        let event_id = event.event_id();
        repositories
            .outbox
            .append("audit.event", serde_json::to_value(event)?, Some(event_id))
            .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
}

/// Structured audit record. Sensitive values must be represented as hashes
/// or references by callers before they reach this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub actor: String,
    pub tenant_id: String,
    pub action: String,
    pub resource: String,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub outcome: AuditOutcome,
    pub error_code: Option<String>,
    pub before_revision: Option<Revision>,
    pub after_revision: Option<Revision>,
    pub timestamp: Timestamp,
    pub source: Option<String>,
    pub summary_hash: Option<String>,
}

impl AuditEvent {
    pub fn success(
        actor: &ActorContext,
        action: impl Into<String>,
        resource: impl Into<String>,
        operation_id: Option<String>,
        after_revision: Option<Revision>,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            actor: actor.subject.clone(),
            tenant_id: actor.tenant_id.as_str().to_string(),
            action: action.into(),
            resource: resource.into(),
            request_id: actor.request_id.clone(),
            operation_id,
            outcome: AuditOutcome::Success,
            error_code: None,
            before_revision: None,
            after_revision,
            timestamp,
            source: actor.source.clone(),
            summary_hash: None,
        }
    }

    pub fn event_id(&self) -> String {
        let op = self.operation_id.as_deref().unwrap_or("none");
        format!(
            "audit:{}:{}:{}:{}",
            self.tenant_id,
            self.action.replace('/', "_"),
            self.resource.replace('/', "_"),
            op
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::Permission;
    use crate::domain::TenantId;

    #[test]
    fn audit_event_uses_structured_safe_fields() {
        let actor = ActorContext::new(
            TenantId::default_tenant(),
            "api-key:reader",
            vec!["api".to_string()],
            vec![Permission::IntentRead],
            Some("req-1".to_string()),
            Some("test".to_string()),
        );
        let event = AuditEvent::success(
            &actor,
            "key.export",
            "key/ref:sha256:abc",
            None,
            Some(7),
            Timestamp::now(),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("api-key:reader"));
        assert!(!json.contains("private-key-pem"));
    }
}
