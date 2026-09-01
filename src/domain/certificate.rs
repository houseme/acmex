//! Logical certificates (`CertificateLineage`) and immutable issuance
//! results (`CertificateVersion`).
//!
//! A *lineage* is one continuously-maintained logical certificate (all
//! renewals of the same intent); a *version* is one immutable issuance.
//! Renewal never overwrites a version — it creates a new one and atomically
//! moves the lineage's `active_version_id` pointer.
//!
//! Private keys are referenced through [`KeyRef`] rather than embedded, so
//! the domain model never carries key material.

use serde::{Deserialize, Serialize};

use super::identifiers::IdentifierSet;
use super::ids::{IntentId, KeyId, LineageId, TenantId, VersionId};
use super::policy::{KeyAlgorithm, KeyManagementMode};
use crate::error::{AcmeError, Result};

/// A reference to a key held by a KeyProvider.
///
/// Contains only addressing metadata — never key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyRef {
    /// Which provider holds the key (`software`, `vault`, ...).
    pub provider: String,
    /// Provider-scoped key identity.
    pub key_id: KeyId,
    /// Algorithm of the referenced key.
    pub algorithm: KeyAlgorithm,
    /// Whether the provider may export the private key.
    pub exportable: bool,
}

impl KeyRef {
    /// A non-exportable software key reference.
    pub fn software(key_id: KeyId, algorithm: KeyAlgorithm) -> Self {
        Self {
            provider: "software".to_string(),
            key_id,
            algorithm,
            exportable: false,
        }
    }
}

/// Lifecycle state of a certificate version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionState {
    /// Issued and persisted, not yet deployed anywhere.
    Issued,
    /// Currently the lineage's active version.
    Active,
    /// Replaced by a newer active version; kept for rollback/audit.
    Superseded,
    /// Revoked at the CA.
    Revoked,
}

impl VersionState {
    /// Stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
        }
    }
}

/// One immutable issued certificate.
///
/// Versions are never mutated after persistence except for the explicitly
/// allowed state transitions in [`CertificateVersion::transition`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateVersion {
    /// Unique identity of this version.
    pub id: VersionId,
    /// The lineage this version belongs to.
    pub lineage_id: LineageId,
    /// The exact identifier set this certificate covers.
    pub identifiers: IdentifierSet,
    /// PEM-encoded leaf + intermediates.
    pub certificate_chain_pem: String,
    /// Issued serial number (hex).
    pub serial: String,
    /// Validity start (RFC 3339).
    pub not_before: String,
    /// Validity end (RFC 3339).
    pub not_after: String,
    /// Issuing CA identity.
    pub issued_by: String,
    /// Certificate profile, if requested/observed.
    #[serde(default)]
    pub profile: Option<String>,
    /// Reference to the private key (never key material itself).
    pub key_ref: KeyRef,
    /// Which version this one replaces, if any.
    #[serde(default)]
    pub replaces: Option<VersionId>,
    /// Which version superseded this one, if any.
    #[serde(default)]
    pub superseded_by: Option<VersionId>,
    /// Lifecycle state.
    pub state: VersionState,
}

impl CertificateVersion {
    /// Allowed state transitions. Enforced centrally so repositories and
    /// services cannot drift.
    pub fn transition(&self, next: VersionState) -> Result<CertificateVersion> {
        let allowed = matches!(
            (self.state, next),
            (VersionState::Issued, VersionState::Active)
                | (VersionState::Active, VersionState::Superseded)
                | (VersionState::Issued, VersionState::Revoked)
                | (VersionState::Active, VersionState::Revoked)
                | (VersionState::Superseded, VersionState::Revoked)
                | (VersionState::Active, VersionState::Active)
                | (VersionState::Issued, VersionState::Issued)
        );
        if !allowed {
            return Err(AcmeError::InvalidInput(format!(
                "illegal certificate version transition {:?} -> {:?}",
                self.state, next
            )));
        }
        let mut next_version = self.clone();
        next_version.state = next;
        Ok(next_version)
    }

    /// Marks this version as superseded by `successor`.
    pub fn superseded_by(self, successor: VersionId) -> Result<Self> {
        let mut next = self.transition(VersionState::Superseded)?;
        next.superseded_by = Some(successor);
        Ok(next)
    }
}

/// A logical certificate: the continuously-renewed entity created from one
/// intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateLineage {
    /// Unique identity of the lineage.
    pub id: LineageId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The intent this lineage fulfils.
    pub intent_id: IntentId,
    /// Canonical identifier set; must match every version's set exactly.
    pub identifiers: IdentifierSet,
    /// The version currently serving traffic, switched atomically on
    /// deployment success.
    #[serde(default)]
    pub active_version_id: Option<VersionId>,
    // History is discoverable via the version repository; the lineage only
    // keeps the active pointer.
}

impl CertificateLineage {
    /// Creates a new lineage for an intent.
    pub fn new(
        id: LineageId,
        tenant_id: TenantId,
        intent_id: IntentId,
        identifiers: IdentifierSet,
    ) -> Self {
        Self {
            id,
            tenant_id,
            intent_id,
            identifiers,
            active_version_id: None,
        }
    }

    /// Whether a given version may be activated for this lineage.
    ///
    /// The identifier set must match exactly — a version covering more or
    /// fewer identifiers than the lineage is never activated.
    pub fn can_activate(&self, version: &CertificateVersion) -> bool {
        version.lineage_id == self.id && version.identifiers == self.identifiers
    }

    /// Activates a version, returning the updated lineage.
    ///
    /// Callers must persist the result through a compare-and-set so
    /// concurrent activations are rejected (see T02 repositories).
    pub fn activate_version(&self, version: &CertificateVersion) -> Result<CertificateLineage> {
        if !self.can_activate(version) {
            return Err(AcmeError::InvalidInput(format!(
                "version `{}` cannot be activated for lineage `{}` (identifier mismatch or foreign lineage)",
                version.id, self.id
            )));
        }
        if version.state != VersionState::Active {
            return Err(AcmeError::InvalidInput(format!(
                "version `{}` must reach state `active` before activation, found `{:?}`",
                version.id, version.state
            )));
        }
        let mut next = self.clone();
        next.active_version_id = Some(version.id.clone());
        Ok(next)
    }
}

/// Compatibility helper: how a legacy `CertificateBundle` maps into the new
/// model (one lineage, one version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedBundle {
    /// The lineage created for the bundle.
    pub lineage: CertificateLineage,
    /// The (sole) version created for the bundle.
    pub version: CertificateVersion,
    /// The key reference under which the legacy private key was stored.
    pub key_ref: KeyRef,
    /// The management mode implied by the import.
    pub key_mode: KeyManagementMode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{IntentId, LineageId, TenantId, VersionId};

    fn sample_version(state: VersionState, identifiers: IdentifierSet) -> CertificateVersion {
        CertificateVersion {
            id: VersionId::generate(),
            lineage_id: LineageId::generate(),
            identifiers,
            certificate_chain_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
                .to_string(),
            serial: "00ff".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2026-04-01T00:00:00Z".to_string(),
            issued_by: "letsencrypt-staging".to_string(),
            profile: None,
            key_ref: KeyRef::software(super::super::KeyId::generate(), KeyAlgorithm::EcP256),
            replaces: None,
            superseded_by: None,
            state,
        }
    }

    fn sample_lineage(identifiers: IdentifierSet) -> CertificateLineage {
        CertificateLineage::new(
            LineageId::generate(),
            TenantId::default_tenant(),
            IntentId::generate(),
            identifiers,
        )
    }

    #[test]
    fn versions_are_immutable_but_transition() {
        let ids = IdentifierSet::parse(["example.com"]).unwrap();
        let v = sample_version(VersionState::Issued, ids);
        assert_eq!(
            v.transition(VersionState::Active).unwrap().state,
            VersionState::Active
        );
        // Original untouched.
        assert_eq!(v.state, VersionState::Issued);
        // Illegal: superseded cannot become active again.
        let active = v.transition(VersionState::Active).unwrap();
        let superseded = active.transition(VersionState::Superseded).unwrap();
        assert!(superseded.transition(VersionState::Active).is_err());
        assert!(superseded.transition(VersionState::Issued).is_err());
    }

    #[test]
    fn version_state_wire_names_are_stable() {
        assert_eq!(VersionState::Issued.as_str(), "issued");
        assert_eq!(VersionState::Active.as_str(), "active");
        assert_eq!(VersionState::Superseded.as_str(), "superseded");
        assert_eq!(VersionState::Revoked.as_str(), "revoked");
    }

    #[test]
    fn lineage_requires_matching_identifiers_to_activate() {
        let ids = IdentifierSet::parse(["example.com"]).unwrap();
        let lineage = sample_lineage(ids.clone());
        let mut version = sample_version(VersionState::Active, ids.clone());
        version.lineage_id = lineage.id.clone();
        lineage.activate_version(&version).unwrap();

        let other_ids = IdentifierSet::parse(["other.example.org"]).unwrap();
        let mut foreign = sample_version(VersionState::Active, other_ids);
        foreign.lineage_id = lineage.id.clone();
        assert!(lineage.activate_version(&foreign).is_err());
    }

    #[test]
    fn lineage_rejects_non_active_version() {
        let ids = IdentifierSet::parse(["example.com"]).unwrap();
        let lineage = sample_lineage(ids.clone());
        let mut version = sample_version(VersionState::Issued, ids);
        version.lineage_id = lineage.id.clone();
        assert!(lineage.activate_version(&version).is_err());
    }

    #[test]
    fn superseded_by_sets_pointer() {
        let ids = IdentifierSet::parse(["example.com"]).unwrap();
        let mut active = sample_version(VersionState::Active, ids);
        let successor = VersionId::generate();
        active.lineage_id = LineageId::generate();
        let superseded = active.superseded_by(successor.clone()).unwrap();
        assert_eq!(superseded.superseded_by, Some(successor));
        assert_eq!(superseded.state, VersionState::Superseded);
    }

    #[test]
    fn lineage_and_version_json_roundtrip() {
        let ids = IdentifierSet::parse(["example.com", "*.example.org"]).unwrap();
        let lineage = sample_lineage(ids.clone());
        let mut version = sample_version(VersionState::Issued, ids);
        version.lineage_id = lineage.id.clone();
        let json = serde_json::to_string(&(lineage.clone(), version.clone())).unwrap();
        let (l2, v2): (CertificateLineage, CertificateVersion) =
            serde_json::from_str(&json).unwrap();
        assert_eq!(l2, lineage);
        assert_eq!(v2, version);
    }

    #[test]
    fn key_ref_carries_no_key_material() {
        let key_ref = KeyRef::software(super::super::KeyId::generate(), KeyAlgorithm::EcP256);
        let json = serde_json::to_string(&key_ref).unwrap();
        assert!(!json.to_lowercase().contains("private"));
        assert!(!json.contains("BEGIN"));
    }
}
