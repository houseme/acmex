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
    /// Verification evidence captured before this immutable version was
    /// persisted. This report contains only public certificate metadata and
    /// sanitized diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_report: Option<CertificateVerificationReport>,
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

/// Stable status for one verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateVerificationStatus {
    /// The check ran and passed.
    #[default]
    Pass,
    /// The check ran and failed.
    Fail,
    /// The check was intentionally skipped by a documented policy.
    NotChecked,
}

impl CertificateVerificationStatus {
    /// Whether this status blocks certificate acceptance.
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Fail)
    }
}

/// Overall verification decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateVerificationConclusion {
    /// The certificate may be persisted and activated by later gates.
    #[default]
    Accepted,
    /// The certificate is terminally rejected.
    Rejected,
}

/// One named check inside a [`CertificateVerificationReport`].
///
/// `check` is a stable, machine-readable identifier (e.g. `san_exact`);
/// `detail` carries human context and must never contain key material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CertificateVerificationCheck {
    /// Stable check name (`chain_parsed`, `san_exact`, `validity_window`, ...).
    pub check: String,
    /// Whether the check passed, failed, or was explicitly skipped.
    pub status: CertificateVerificationStatus,
    /// Optional human-readable context (no secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Stable error code for a failed check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl CertificateVerificationCheck {
    /// Creates a passing check.
    pub fn pass(check: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CertificateVerificationStatus::Pass,
            detail: None,
            error_code: None,
        }
    }

    /// Creates a failed check.
    pub fn fail(
        check: impl Into<String>,
        error_code: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            check: check.into(),
            status: CertificateVerificationStatus::Fail,
            detail: Some(detail.into()),
            error_code: Some(error_code.into()),
        }
    }

    /// Creates an explicitly skipped check.
    pub fn not_checked(check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CertificateVerificationStatus::NotChecked,
            detail: Some(detail.into()),
            error_code: None,
        }
    }
}

impl<'de> Deserialize<'de> for CertificateVerificationCheck {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(alias = "name")]
            check: String,
            #[serde(default)]
            status: Option<CertificateVerificationStatus>,
            #[serde(default)]
            passed: Option<bool>,
            #[serde(default)]
            detail: Option<String>,
            #[serde(default)]
            error_code: Option<String>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let status = wire.status.unwrap_or(match wire.passed {
            Some(false) => CertificateVerificationStatus::Fail,
            _ => CertificateVerificationStatus::Pass,
        });
        Ok(Self {
            check: wire.check,
            status,
            detail: wire.detail,
            error_code: wire.error_code,
        })
    }
}

/// The strict acceptance report produced when an issued chain is verified
/// against its intent (roadmap T07): which checks ran, the observed
/// validity window, serial and issuer. Persisted as the
/// `VerifyCertificate` step output so the evidence survives restarts and
/// audits — a certificate is only persisted when the report is accepted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertificateVerificationReport {
    /// Wire schema version. Starts at 1 for the v0.10.0 public surface.
    #[serde(default = "default_verification_report_schema_version")]
    pub schema_version: u32,
    /// Overall verifier decision.
    #[serde(default)]
    pub conclusion: CertificateVerificationConclusion,
    /// Stable terminal error code when `conclusion = rejected`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Whether the SAN set exactly matches the intent identifiers.
    pub identifiers_exact_match: bool,
    /// Observed validity start (RFC 3339).
    pub not_before: String,
    /// Observed validity end (RFC 3339).
    pub not_after: String,
    /// Leaf serial (hex).
    pub serial: String,
    /// Issuing CA identity, when known from the intent's CA policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
    /// Requested profile, when the intent pinned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The individual checks with their outcomes.
    pub checks: Vec<CertificateVerificationCheck>,
}

impl CertificateVerificationReport {
    /// Builds the public report from observed certificate metadata and checks.
    pub fn new(
        identifiers_exact_match: bool,
        not_before: String,
        not_after: String,
        serial: String,
        ca: Option<String>,
        profile: Option<String>,
        checks: Vec<CertificateVerificationCheck>,
    ) -> Self {
        let rejected = checks.iter().any(|check| check.status.is_failure());
        Self {
            schema_version: default_verification_report_schema_version(),
            conclusion: if rejected {
                CertificateVerificationConclusion::Rejected
            } else {
                CertificateVerificationConclusion::Accepted
            },
            error_code: rejected.then(|| {
                crate::domain::error_codes::CERTIFICATE_VERIFICATION_FAILED
                    .as_str()
                    .to_string()
            }),
            identifiers_exact_match,
            not_before,
            not_after,
            serial,
            ca,
            profile,
            checks,
        }
    }

    /// Whether every recorded check ran and passed.
    pub fn all_passed(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == CertificateVerificationStatus::Pass)
    }

    /// Whether this report accepted the certificate.
    pub fn accepted(&self) -> bool {
        self.conclusion == CertificateVerificationConclusion::Accepted
    }

    /// The names of the failed checks (diagnostics).
    pub fn failed_checks(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|check| check.status.is_failure())
            .map(|check| check.check.as_str())
            .collect()
    }
}

fn default_verification_report_schema_version() -> u32 {
    1
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
            verification_report: None,
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
    fn verification_check_reads_legacy_name_passed_shape() {
        let check: CertificateVerificationCheck = serde_json::from_value(serde_json::json!({
            "name": "san_exact",
            "passed": false,
            "detail": "mismatch"
        }))
        .unwrap();
        assert_eq!(check.check, "san_exact");
        assert_eq!(check.status, CertificateVerificationStatus::Fail);
        assert_eq!(check.detail.as_deref(), Some("mismatch"));
    }

    #[test]
    fn verification_report_serializes_versioned_public_shape() {
        let report = CertificateVerificationReport::new(
            true,
            "2026-01-01T00:00:00Z".to_string(),
            "2026-02-01T00:00:00Z".to_string(),
            "01".to_string(),
            Some("test-ca".to_string()),
            Some("shortlived".to_string()),
            vec![
                CertificateVerificationCheck::pass("san_exact"),
                CertificateVerificationCheck::not_checked(
                    "profile_compliance",
                    "CA did not advertise profiles",
                ),
            ],
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["conclusion"], "accepted");
        assert_eq!(json["checks"][0]["check"], "san_exact");
        assert_eq!(json["checks"][0]["status"], "pass");
        assert_eq!(json["checks"][1]["status"], "not-checked");
        assert!(json["checks"][0].get("passed").is_none());
        assert!(report.accepted());
        assert!(!report.all_passed());
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
