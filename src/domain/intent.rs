//! `CertificateIntent`: the upstream's desired state for a logical
//! certificate.
//!
//! An intent is *not* an ACME order. It is the durable statement of "this
//! tenant wants a certificate for these identifiers, under these policies,
//! renewed this way and delivered there". Orders, challenges and versions
//! are derived from it by later pipeline stages.

use serde::{Deserialize, Serialize};

use super::identifiers::IdentifierSet;
use super::ids::{IntentId, TenantId};
use super::policy::{CaPolicy, DeliveryTarget, KeyPolicy, RenewalPolicy, ValidationPolicy};
use crate::error::{AcmeError, Result};

/// The upstream's desired state for one logical certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateIntent {
    /// Unique identity of this intent.
    pub id: IntentId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The identifiers the certificate must cover (non-empty, deduplicated,
    /// canonically ordered).
    pub identifiers: IdentifierSet,
    /// CA selection and profile policy.
    #[serde(default)]
    pub ca_policy: CaPolicy,
    /// Validation/challenge policy.
    #[serde(default)]
    pub validation_policy: ValidationPolicy,
    /// Private key policy.
    #[serde(default)]
    pub key_policy: KeyPolicy,
    /// Renewal policy.
    #[serde(default)]
    pub renewal_policy: RenewalPolicy,
    /// Downstream delivery targets.
    #[serde(default)]
    pub delivery_targets: Vec<DeliveryTarget>,
    /// Idempotency key supplied by the caller; identical key + payload must
    /// resolve to the same intent.
    #[serde(default)]
    pub idempotency_key: String,
    /// Monotonic counter incremented on every mutation; used with CAS to
    /// detect concurrent updates.
    #[serde(default)]
    pub generation: u64,
}

impl CertificateIntent {
    /// Validates the intent invariants.
    ///
    /// * identifiers must be non-empty (enforced by [`IdentifierSet`]);
    /// * wildcard DNS identifiers must not be combined with other
    ///   identifiers (CAs reject such orders);
    /// * every delivery target must be uniquely identified;
    /// * an external-CSR key policy must not request key export;
    /// * an explicit CA policy must be contained in the allowed set when
    ///   both are given.
    pub fn validate(&self) -> Result<()> {
        if self.identifiers.is_empty() {
            return Err(AcmeError::InvalidInput(
                "intent requires at least one identifier".to_string(),
            ));
        }
        if self.identifiers.contains_wildcard() && self.identifiers.len() > 1 {
            return Err(AcmeError::InvalidInput(format!(
                "wildcard identifier cannot be combined with other identifiers ({} given)",
                self.identifiers.len()
            )));
        }
        if self.key_policy.mode == super::policy::KeyManagementMode::ExternalCsr
            && self.key_policy.exportable
        {
            return Err(AcmeError::InvalidInput(
                "external-CSR keys are never exportable".to_string(),
            ));
        }
        if let (Some(ca), allowed) = (&self.ca_policy.ca_id, &self.ca_policy.allowed_cas)
            && !allowed.is_empty()
            && !allowed.contains(ca)
        {
            return Err(AcmeError::InvalidInput(format!(
                "pinned CA `{ca}` is not in the allowed CA set"
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for target in &self.delivery_targets {
            if !seen.insert(target.id.clone()) {
                return Err(AcmeError::InvalidInput(format!(
                    "duplicate delivery target id `{}`",
                    target.id
                )));
            }
        }
        for target in &self.delivery_targets {
            if let DeliveryRequirement::Quorum(n) = target.requirement
                && (n == 0 || n > self.delivery_targets.len())
            {
                return Err(AcmeError::InvalidInput(format!(
                    "delivery quorum {n} is out of range for {} targets",
                    self.delivery_targets.len()
                )));
            }
        }
        Ok(())
    }

    /// A stable hash of the request semantics (identifiers + policies),
    /// used for idempotency comparisons.
    pub fn request_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        hex::encode(hasher.finalize())
    }
}

use super::policy::DeliveryRequirement;

/// Outcome of creating an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum IntentCreation {
    /// A new intent was created.
    Created(IntentId),
    /// An existing intent with the same idempotency key was returned.
    Existing(IntentId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::identifiers::Identifier;
    use crate::domain::policy::{DeliveryRequirement, DeliveryTargetKind, KeyManagementMode};

    fn base_intent() -> CertificateIntent {
        CertificateIntent {
            id: IntentId::generate(),
            tenant_id: TenantId::default_tenant(),
            identifiers: IdentifierSet::parse(["example.com"]).unwrap(),
            ca_policy: CaPolicy::default(),
            validation_policy: ValidationPolicy::default(),
            key_policy: KeyPolicy::default(),
            renewal_policy: RenewalPolicy::default(),
            delivery_targets: Vec::new(),
            idempotency_key: "idem-1".to_string(),
            generation: 1,
        }
    }

    #[test]
    fn valid_intent_passes_validation() {
        base_intent().validate().unwrap();
    }

    #[test]
    fn wildcard_with_other_identifiers_rejected() {
        let mut intent = base_intent();
        intent.identifiers = IdentifierSet::new(vec![
            Identifier::try_dns("*.example.com").unwrap(),
            Identifier::try_dns("www.example.org").unwrap(),
        ])
        .unwrap();
        assert!(intent.validate().is_err());
    }

    #[test]
    fn lone_wildcard_is_accepted() {
        let mut intent = base_intent();
        intent.identifiers = IdentifierSet::parse(["*.example.com"]).unwrap();
        intent.validate().unwrap();
    }

    #[test]
    fn external_csr_must_not_be_exportable() {
        let mut intent = base_intent();
        intent.key_policy.mode = KeyManagementMode::ExternalCsr;
        intent.key_policy.exportable = true;
        assert!(intent.validate().is_err());
    }

    #[test]
    fn duplicate_delivery_targets_rejected() {
        let mut intent = base_intent();
        let target = DeliveryTarget::new("web", DeliveryTargetKind::File, "/etc/certs").unwrap();
        intent.delivery_targets = vec![target.clone(), target];
        assert!(intent.validate().is_err());
    }

    #[test]
    fn pinned_ca_must_be_allowed() {
        let mut intent = base_intent();
        intent.ca_policy.ca_id = Some("letsencrypt".to_string());
        intent.ca_policy.allowed_cas = vec!["zerossl".to_string()];
        assert!(intent.validate().is_err());
    }

    #[test]
    fn intent_json_roundtrip() {
        let intent = base_intent();
        let json = serde_json::to_string(&intent).unwrap();
        let back: CertificateIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(intent, back);
    }

    #[test]
    fn quorum_bounds_are_checked() {
        let mut intent = base_intent();
        intent.delivery_targets = vec![
            DeliveryTarget {
                id: crate::domain::TargetId::new("a").unwrap(),
                kind: DeliveryTargetKind::File,
                reference: "/a".to_string(),
                requirement: DeliveryRequirement::Quorum(2),
            },
            DeliveryTarget {
                id: crate::domain::TargetId::new("b").unwrap(),
                kind: DeliveryTargetKind::File,
                reference: "/b".to_string(),
                requirement: DeliveryRequirement::Required,
            },
        ];
        intent.validate().unwrap();

        intent.delivery_targets.truncate(1);
        assert!(intent.validate().is_err());
    }
}
