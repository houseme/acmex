//! Challenge lease model: recoverable, cleanable external challenge state.
//!
//! A [`ChallengeLease`] is persisted as soon as an external validation
//! resource (DNS TXT record, HTTP route, TLS route) is created, so that any
//! process — after crash, restart or takeover — can find and remove exactly
//! the resources this operation created. Locators are typed per challenge
//! family and never carry credentials or raw tokens (only hashes).

use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use super::identifiers::Identifier;
use super::ids::{ChallengeLeaseId, OperationId};
use crate::types::ChallengeType;

/// Typed identity of an external challenge resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ChallengeLeaseLocator {
    /// A DNS TXT record held by a provider.
    Dns {
        /// Provider instance that created the record.
        provider_id: String,
        /// Zone apex the record lives in.
        zone: String,
        /// Full record name (`_acme-challenge.example.com`).
        record_name: String,
        /// Provider record ID, when the API exposes one.
        #[serde(skip_serializing_if = "Option::is_none")]
        record_id: Option<String>,
        /// Hash of the TXT value this lease created — exact deletion target
        /// when multiple TXT records coexist.
        value_hash: String,
    },
    /// An HTTP-01 route served locally or by an edge agent.
    Http {
        /// Agent/router serving the route (`local`, edge agent id...).
        agent_id: String,
        /// Route identifier within the agent.
        route_id: String,
        /// Hash of the token (never the token itself).
        token_hash: String,
        /// Where the challenge is observable.
        endpoint: String,
    },
    /// A TLS-ALPN-01 route.
    Tls {
        /// Agent/router serving the route.
        agent_id: String,
        /// Route identifier within the agent.
        route_id: String,
        /// SNI name the route matches (reverse name for IPs, RFC 8738).
        sni: String,
        /// Fingerprint of the validation certificate.
        fingerprint: String,
    },
}

impl ChallengeLeaseLocator {
    /// The challenge family this locator belongs to.
    pub fn challenge_type(&self) -> ChallengeType {
        match self {
            Self::Dns { .. } => ChallengeType::Dns01,
            Self::Http { .. } => ChallengeType::Http01,
            Self::Tls { .. } => ChallengeType::TlsAlpn01,
        }
    }
}

/// Lifecycle state of a challenge lease.
///
/// Cleanup state is tracked on the lease itself so it survives the owning
/// operation reaching any terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeLeaseState {
    /// External resource exists; validation may be in progress.
    Active,
    /// Resource should be removed as soon as possible.
    CleanupPending,
    /// Resource removed (or confirmed absent).
    Cleaned,
    /// Cleanup failed and is being retried; alerts after too many attempts.
    CleanupFailed,
}

impl ChallengeLeaseState {
    /// Stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::CleanupPending => "cleanup_pending",
            Self::Cleaned => "cleaned",
            Self::CleanupFailed => "cleanup_failed",
        }
    }

    /// Terminal lease states.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Cleaned)
    }
}

/// A persisted handle on an external challenge resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeLease {
    /// Unique lease identity.
    pub id: ChallengeLeaseId,
    /// Owning operation.
    pub operation_id: OperationId,
    /// The identifier being validated.
    pub identifier: Identifier,
    /// Challenge family (derived from the locator, kept for queries).
    pub challenge_type: ChallengeType,
    /// Where the external resource lives and how to remove it.
    pub locator: ChallengeLeaseLocator,
    /// Lease creation time.
    pub created_at: Timestamp,
    /// Absolute expiry; the resource must not outlive this.
    pub expires_at: Timestamp,
    /// Lifecycle state.
    pub state: ChallengeLeaseState,
    /// Cleanup attempt counter.
    #[serde(default)]
    pub cleanup_attempts: u32,
    /// Last cleanup error (classified code), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_cleanup_error: Option<String>,
    /// When cleanup completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleaned_at: Option<Timestamp>,
}

impl ChallengeLease {
    /// Whether the lease is expired at the given time.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// Whether this lease needs cleanup attention.
    pub fn needs_cleanup(&self) -> bool {
        matches!(
            self.state,
            ChallengeLeaseState::Active | ChallengeLeaseState::CleanupPending
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_lease() -> ChallengeLease {
        ChallengeLease {
            id: ChallengeLeaseId::generate(),
            operation_id: OperationId::generate(),
            identifier: Identifier::try_dns("example.com").unwrap(),
            challenge_type: ChallengeType::Dns01,
            locator: ChallengeLeaseLocator::Dns {
                provider_id: "cloudflare-prod".to_string(),
                zone: "example.com".to_string(),
                record_name: "_acme-challenge.example.com".to_string(),
                record_id: Some("rec-123".to_string()),
                value_hash: "abc123".to_string(),
            },
            created_at: Timestamp::now(),
            expires_at: Timestamp::now()
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap(),
            state: ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        }
    }

    #[test]
    fn lease_json_roundtrip() {
        let lease = dns_lease();
        let json = serde_json::to_string(&lease).unwrap();
        assert!(!json.contains("token"));
        assert!(!json.contains("credential"));
        let back: ChallengeLease = serde_json::from_str(&json).unwrap();
        assert_eq!(lease, back);
    }

    #[test]
    fn locator_challenge_type_is_derived() {
        let lease = dns_lease();
        assert_eq!(lease.locator.challenge_type(), ChallengeType::Dns01);
    }

    #[test]
    fn expiry_and_cleanup_predicates() {
        let lease = dns_lease();
        assert!(!lease.is_expired(lease.created_at));
        assert!(lease.is_expired(lease.expires_at));
        assert!(lease.needs_cleanup());
    }
}
