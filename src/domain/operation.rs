//! Durable operation model (identity and kind only in T01).
//!
//! T03 (`Durable Workflow Engine`) turns these types into the full
//! step-based state machine with leases, retries and compensation. T01
//! freezes the *identity* vocabulary so repositories (T02) and CA handles
//! (T04) can reference operations without depending on the engine.

use serde::{Deserialize, Serialize};

use super::ids::{LineageId, OperationId, VersionId};

/// What an operation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Initial certificate issuance for an intent.
    Issue,
    /// Renewal of an existing lineage.
    Renew,
    /// Revocation of a certificate version.
    Revoke,
    /// Deployment of a certificate version to delivery targets.
    Deploy,
    /// Cleanup of challenge resources left behind by another operation.
    ChallengeCleanup,
}

impl OperationKind {
    /// Stable wire name (API-facing, never the Rust debug form).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
            Self::Deploy => "deploy",
            Self::ChallengeCleanup => "challenge_cleanup",
        }
    }
}

/// The resources an operation acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSubject {
    /// The lineage this operation is about, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<LineageId>,
    /// The certificate version this operation is about, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<VersionId>,
}

/// A reference to an operation returned by application services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRef {
    /// The operation identity.
    pub id: OperationId,
    /// What kind of operation it is.
    pub kind: OperationKind,
    /// The subject resources.
    pub subject: OperationSubject,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_wire_names_are_stable() {
        assert_eq!(OperationKind::Issue.as_str(), "issue");
        assert_eq!(
            OperationKind::ChallengeCleanup.as_str(),
            "challenge_cleanup"
        );
        let json = serde_json::to_string(&OperationKind::Renew).unwrap();
        assert_eq!(json, "\"renew\"");
    }
}
