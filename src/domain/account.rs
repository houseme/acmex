//! Persisted CA account model.
//!
//! An ACME account is identified by (tenant, CA directory identity, key).
//! The account URL — once returned by the CA — is persisted immediately so
//! restarts reuse it instead of re-registering (roadmap T04 builds the
//! session on top of this record).

use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use super::certificate::KeyRef;
use super::ids::TenantId;

/// Status of a stored account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Registered and usable.
    Active,
    /// Deactivated at the CA.
    Deactivated,
    /// Revoked by the CA.
    Revoked,
}

/// A persisted ACME account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    /// Composite identity (`<tenant>:<ca_id>`); repository-assigned.
    pub id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Logical CA identity (config `ca_id`).
    pub ca_id: String,
    /// Directory URL the account belongs to.
    pub directory_url: String,
    /// Account URL returned by the CA; `None` until first registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_url: Option<String>,
    /// Reference to the account key (never key material).
    pub key_ref: KeyRef,
    /// Contact URIs (`mailto:...`).
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Whether the CA required EAB for this account.
    #[serde(default)]
    pub eab_bound: bool,
    /// Account status.
    pub status: AccountStatus,
    /// Creation time.
    pub created_at: Timestamp,
    /// Last update time.
    pub updated_at: Timestamp,
}

impl AccountRecord {
    /// Computes the repository identity for an account.
    pub fn compute_id(tenant_id: &TenantId, ca_id: &str) -> String {
        format!("{}:{}", tenant_id, ca_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeyAlgorithm, KeyId, TenantId};

    #[test]
    fn account_json_roundtrip() {
        let account = AccountRecord {
            id: AccountRecord::compute_id(&TenantId::default_tenant(), "letsencrypt"),
            tenant_id: TenantId::default_tenant(),
            ca_id: "letsencrypt".to_string(),
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            account_url: Some(
                "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1".to_string(),
            ),
            key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
            contacts: vec!["mailto:admin@example.com".to_string()],
            eab_bound: false,
            status: AccountStatus::Active,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        };
        let json = serde_json::to_string(&account).unwrap();
        // Key material must never appear in the stored form.
        assert!(!json.contains("BEGIN PRIVATE"));
        let back: AccountRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(account, back);
    }
}
