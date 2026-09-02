//! Challenge sessions: one independent validation lifecycle per
//! authorization/challenge.
//!
//! A session replaces the legacy "one mutable solver per challenge type"
//! model: every authorization gets its own [`ChallengeSession`] whose
//! external resource is tracked by a [`ChallengeLease`] (T02) and whose
//! state transitions are validated here. `Valid` and `Cleaned` are two
//! independent dimensions — a validated challenge still must be cleaned.

use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use crate::domain::identifiers::Identifier;
use crate::domain::ids::{ChallengeLeaseId, OperationId};
use crate::types::ChallengeType;

/// Lifecycle state of a challenge session.
///
/// ```text
/// Selected → Preparing → Prepared → Observing → Propagated
///         → Acknowledged → Processing → Valid
/// any → Failed/Cancelled
/// Prepared..Valid → CleanupPending → Cleaned/CleanupFailed
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeSessionState {
    /// Planned, nothing created yet.
    Selected,
    /// External resource creation in flight (crash marker).
    Preparing,
    /// External resource exists (lease persisted).
    Prepared,
    /// Observing external propagation.
    Observing,
    /// Propagation confirmed by the observer.
    Propagated,
    /// CA told to validate (challenge POSTed).
    Acknowledged,
    /// CA is validating.
    Processing,
    /// CA marked the authorization valid.
    Valid,
    /// Terminally failed.
    Failed,
    /// Cancelled with the owning operation.
    Cancelled,
    /// Cleanup scheduled (independent of the session's own outcome).
    CleanupPending,
    /// External resource removed.
    Cleaned,
    /// Cleanup failed; retried independently and alerted.
    CleanupFailed,
}

impl ChallengeSessionState {
    /// Stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Preparing => "preparing",
            Self::Prepared => "prepared",
            Self::Observing => "observing",
            Self::Propagated => "propagated",
            Self::Acknowledged => "acknowledged",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::CleanupPending => "cleanup_pending",
            Self::Cleaned => "cleaned",
            Self::CleanupFailed => "cleanup_failed",
        }
    }

    /// Whether the external resource exists and needs eventual cleanup.
    pub fn needs_cleanup(&self) -> bool {
        matches!(
            self,
            Self::Prepared
                | Self::Observing
                | Self::Propagated
                | Self::Acknowledged
                | Self::Processing
                | Self::Valid
                | Self::CleanupPending
                | Self::CleanupFailed
        )
    }
}

/// One authorization's validation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeSession {
    /// Unique session identity.
    pub id: String,
    /// Owning operation.
    pub operation_id: OperationId,
    /// The authorization being fulfilled.
    pub authorization_url: String,
    /// The chosen challenge resource URL.
    pub challenge_url: String,
    /// The identifier under validation.
    pub identifier: Identifier,
    /// Challenge family.
    pub challenge_type: ChallengeType,
    /// SHA-256 of the challenge token (raw tokens are never persisted).
    pub token_hash: String,
    /// Current state.
    pub state: ChallengeSessionState,
    /// The lease tracking the external resource, once created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<ChallengeLeaseId>,
    /// Absolute deadline for reaching `Propagated`.
    pub deadline: Timestamp,
    /// Last time AcmeX observed the external challenge resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_propagation_check_at: Option<Timestamp>,
    /// Last propagation observation outcome, using stable API words
    /// (`not_yet`, `propagated`, `timeout`, `error`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_propagation_status: Option<String>,
    /// Last time AcmeX polled the CA authorization resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ca_poll_at: Option<Timestamp>,
    /// Last CA authorization status observed from the resource body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ca_status: Option<String>,
    /// Classified last error, if any (no token or key authorization).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl ChallengeSession {
    /// SHA-256 hex of a challenge token.
    pub fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Whether the propagation deadline has passed.
    pub fn is_past_deadline(&self, now: Timestamp) -> bool {
        now >= self.deadline
    }

    /// Records a propagation observation without changing lifecycle state.
    pub fn record_propagation_check(&mut self, checked_at: Timestamp, status: impl Into<String>) {
        self.last_propagation_check_at = Some(checked_at);
        self.last_propagation_status = Some(status.into());
    }

    /// Records a CA authorization poll without changing lifecycle state.
    pub fn record_ca_poll(&mut self, polled_at: Timestamp, status: impl Into<String>) {
        self.last_ca_poll_at = Some(polled_at);
        self.last_ca_status = Some(status.into());
    }

    /// Validates and applies a state transition.
    pub fn transition(&self, next: ChallengeSessionState) -> Result<ChallengeSession, String> {
        use ChallengeSessionState as S;
        let legal = matches!(
            (self.state, next),
            (S::Selected, S::Preparing)
                | (S::Selected, S::Failed)
                | (S::Selected, S::Cancelled)
                | (S::Preparing, S::Prepared)
                | (S::Preparing, S::Failed)
                | (S::Prepared, S::Observing)
                | (S::Prepared, S::Failed)
                | (S::Observing, S::Propagated)
                | (S::Observing, S::Observing)
                | (S::Observing, S::Failed)
                | (S::Propagated, S::Acknowledged)
                | (S::Propagated, S::Failed)
                | (S::Acknowledged, S::Processing)
                | (S::Acknowledged, S::Failed)
                | (S::Processing, S::Valid)
                | (S::Processing, S::Processing)
                | (S::Processing, S::Failed)
                | (_, S::Cancelled)
                | (_, S::CleanupPending)
                | (S::CleanupPending, S::Cleaned)
                | (S::CleanupPending, S::CleanupFailed)
                | (S::Cleaned, S::Cleaned)
        );
        if !legal {
            return Err(format!(
                "illegal challenge session transition {:?} -> {:?}",
                self.state, next
            ));
        }
        let mut next_session = self.clone();
        next_session.state = next;
        Ok(next_session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> ChallengeSession {
        ChallengeSession {
            id: "chs_test".to_string(),
            operation_id: OperationId::generate(),
            authorization_url: "https://acme.example/authz/1".to_string(),
            challenge_url: "https://acme.example/challenge/1".to_string(),
            identifier: Identifier::try_dns("example.com").unwrap(),
            challenge_type: ChallengeType::Dns01,
            token_hash: ChallengeSession::hash_token("token-1"),
            state: ChallengeSessionState::Selected,
            lease_id: None,
            deadline: Timestamp::now()
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap(),
            last_propagation_check_at: None,
            last_propagation_status: None,
            last_ca_poll_at: None,
            last_ca_status: None,
            last_error: None,
        }
    }

    #[test]
    fn happy_path_transitions() {
        let s = session()
            .transition(ChallengeSessionState::Preparing)
            .unwrap()
            .transition(ChallengeSessionState::Prepared)
            .unwrap()
            .transition(ChallengeSessionState::Observing)
            .unwrap()
            .transition(ChallengeSessionState::Propagated)
            .unwrap()
            .transition(ChallengeSessionState::Acknowledged)
            .unwrap()
            .transition(ChallengeSessionState::Processing)
            .unwrap()
            .transition(ChallengeSessionState::Valid)
            .unwrap();
        assert!(s.state.needs_cleanup(), "valid sessions still need cleanup");
    }

    #[test]
    fn illegal_transitions_rejected() {
        let s = session();
        assert!(s.transition(ChallengeSessionState::Valid).is_err());
        assert!(s.transition(ChallengeSessionState::Prepared).is_err());

        let prepared = s
            .transition(ChallengeSessionState::Preparing)
            .unwrap()
            .transition(ChallengeSessionState::Prepared)
            .unwrap();
        // Cannot jump from Prepared straight to Processing.
        assert!(
            prepared
                .transition(ChallengeSessionState::Processing)
                .is_err()
        );
        // Cleanup is reachable from any resource-holding state.
        assert!(
            prepared
                .transition(ChallengeSessionState::CleanupPending)
                .is_ok()
        );
    }

    #[test]
    fn cleanup_failure_is_retriable() {
        let s = session()
            .transition(ChallengeSessionState::Preparing)
            .unwrap()
            .transition(ChallengeSessionState::Prepared)
            .unwrap()
            .transition(ChallengeSessionState::CleanupPending)
            .unwrap()
            .transition(ChallengeSessionState::CleanupFailed)
            .unwrap();
        assert!(s.transition(ChallengeSessionState::CleanupPending).is_ok());
        assert!(s.transition(ChallengeSessionState::Cleaned).is_err());
    }

    #[test]
    fn token_hash_is_stable_and_token_not_stored() {
        let s = session();
        assert_eq!(s.token_hash, ChallengeSession::hash_token("token-1"));
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("token-1"), "raw tokens must never persist");
    }
}
