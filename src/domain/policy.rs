//! Certificate policies and the challenge compatibility matrix.
//!
//! Policies are the declarative part of a [`CertificateIntent`]: which CA to
//! use, which validation paths are acceptable, how keys are managed, when to
//! renew and where the certificate must be delivered. The compatibility
//! matrix below is a *pure function* over [`Identifier`]s so that illegal
//! combinations (e.g. wildcard + HTTP-01, IP + DNS-01) are rejected before
//! any external side effect such as an ACME order is created.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{AcmeError, Result};
use crate::types::ChallengeType;

use super::identifiers::{Identifier, IdentifierKind};

/// A set of ACME challenge types, kept sorted for stable serialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ChallengeSet(BTreeSet<ChallengeType>);

impl ChallengeSet {
    /// Builds a set from an iterator of challenge types.
    pub fn new<I: IntoIterator<Item = ChallengeType>>(items: I) -> Self {
        Self(items.into_iter().collect())
    }

    /// All challenge types this crate understands.
    pub fn all() -> Self {
        Self::new([
            ChallengeType::Http01,
            ChallengeType::Dns01,
            ChallengeType::TlsAlpn01,
        ])
    }

    pub fn contains(&self, item: ChallengeType) -> bool {
        self.0.contains(&item)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = ChallengeType> + '_ {
        self.0.iter().copied()
    }

    /// Intersection with another set.
    pub fn intersection(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    /// Parses from wire strings (`http-01`, `dns-01`, `tls-alpn-01`).
    pub fn parse<I, S>(items: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = BTreeSet::new();
        for item in items {
            let parsed: ChallengeType = item
                .as_ref()
                .parse()
                .map_err(|err| AcmeError::InvalidInput(err))?;
            set.insert(parsed);
        }
        Ok(Self(set))
    }
}

/// Which CA(s) an intent may be issued by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CaPolicy {
    /// Pin the intent to a single configured CA (by `ca_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_id: Option<String>,
    /// CA ids allowed for issuance; empty means "any configured CA".
    #[serde(default)]
    pub allowed_cas: Vec<String>,
    /// Target CA environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<CaEnvironment>,
    /// Requested certificate profile (e.g. short-lived); must be offered by
    /// the CA, never inferred from the CSR.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Whether falling back to another allowed CA is permitted.
    #[serde(default)]
    pub allow_fallback: bool,
}

impl Default for CaPolicy {
    fn default() -> Self {
        Self {
            ca_id: None,
            allowed_cas: Vec::new(),
            environment: None,
            profile: None,
            allow_fallback: false,
        }
    }
}

/// CA environment selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaEnvironment {
    /// Production CA endpoint.
    Production,
    /// Staging CA endpoint.
    Staging,
}

/// How domain/IP validation may be performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidationPolicy {
    /// Challenge types the caller is willing to perform. Empty means "any
    /// compatible type" (the planner then picks by preference order).
    #[serde(default)]
    pub allowed_challenges: ChallengeSet,
    /// Selector for a configured DNS provider instance (DNS-01).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_provider: Option<String>,
    /// Selector for a configured HTTP/TLS edge agent (HTTP-01/TLS-ALPN-01).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_agent: Option<String>,
    /// Propagation observation settings.
    #[serde(default)]
    pub propagation: PropagationPolicy,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            allowed_challenges: ChallengeSet::default(),
            dns_provider: None,
            edge_agent: None,
            propagation: PropagationPolicy::default(),
        }
    }
}

/// DNS propagation observation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PropagationPolicy {
    /// Overall propagation observation timeout.
    #[serde(with = "duration_secs", default = "default_propagation_timeout")]
    pub timeout: Duration,
    /// Minimum fraction of authoritative nameservers that must serve the
    /// expected value before the challenge is acknowledged.
    #[serde(default = "default_authoritative_quorum")]
    pub authoritative_quorum: Quorum,
    /// Number of independent recursive resolvers that must observe the value.
    #[serde(default = "default_recursive_quorum")]
    pub recursive_quorum: usize,
}

/// Fraction/quorum requirement over a set of endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Quorum {
    /// All observed endpoints must agree.
    All,
    /// At least `n` endpoints must agree.
    AtLeast(usize),
}

impl Default for PropagationPolicy {
    fn default() -> Self {
        Self {
            timeout: default_propagation_timeout(),
            authoritative_quorum: default_authoritative_quorum(),
            recursive_quorum: default_recursive_quorum(),
        }
    }
}

fn default_propagation_timeout() -> Duration {
    Duration::from_secs(600)
}

fn default_authoritative_quorum() -> Quorum {
    Quorum::All
}

fn default_recursive_quorum() -> usize {
    1
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(value.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(value: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(value)?))
    }
}

mod option_duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(
        value: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(duration) => serializer.serialize_some(&duration.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(value: D) -> Result<Option<Duration>, D::Error> {
        let raw = Option::<u64>::deserialize(value)?;
        Ok(raw.map(Duration::from_secs))
    }
}

/// How the certificate private key is managed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyPolicy {
    /// Key algorithm requested from the KeyProvider.
    pub algorithm: KeyAlgorithm,
    /// Managed by AcmeX or supplied externally as a CSR.
    pub mode: KeyManagementMode,
    /// Renewal key handling.
    #[serde(default)]
    pub rotation: KeyRotationPolicy,
    /// Whether the private key may be exported through the API.
    #[serde(default)]
    pub exportable: bool,
}

impl Default for KeyPolicy {
    fn default() -> Self {
        Self {
            algorithm: KeyAlgorithm::EcP256,
            mode: KeyManagementMode::Managed,
            rotation: KeyRotationPolicy::Reuse,
            exportable: false,
        }
    }
}

/// Supported certificate key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    /// ECDSA P-256 (default).
    EcP256,
    /// ECDSA P-384.
    EcP384,
    /// RSA 2048.
    Rsa2048,
    /// RSA 4096.
    Rsa4096,
    /// Ed25519.
    Ed25519,
}

/// Who holds the certificate private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyManagementMode {
    /// AcmeX generates and stores the key via a KeyProvider.
    Managed,
    /// The caller supplies a CSR; AcmeX never sees the private key.
    ExternalCsr,
}

/// Key handling across renewals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationPolicy {
    /// Reuse the previous version's key.
    #[default]
    Reuse,
    /// Generate a fresh key on every renewal.
    RotateEachRenewal,
}

/// When a certificate becomes eligible for renewal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RenewalPolicy {
    /// Prefer RFC 9773 ARI suggested windows when the CA offers them.
    #[serde(default = "default_true")]
    pub prefer_ari: bool,
    /// Fraction of the certificate lifetime after which renewal starts
    /// (fallback when ARI is unavailable). Default 2/3.
    #[serde(default = "default_lifetime_fraction")]
    pub fallback_lifetime_fraction: f64,
    /// Legacy fixed renew-before window; compatibility only, never the sole
    /// strategy when `fallback_lifetime_fraction` applies.
    #[serde(
        default,
        with = "option_duration_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub fixed_renew_before: Option<Duration>,
    /// Minimum time that must remain between the selected renewal point and
    /// `not_after` so operators always keep a reaction window.
    #[serde(with = "duration_secs", default = "default_safety_margin")]
    pub min_safety_margin: Duration,
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        Self {
            prefer_ari: default_true(),
            fallback_lifetime_fraction: default_lifetime_fraction(),
            fixed_renew_before: None,
            min_safety_margin: default_safety_margin(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_lifetime_fraction() -> f64 {
    2.0 / 3.0
}

fn default_safety_margin() -> Duration {
    Duration::from_secs(3 * 24 * 3600)
}

/// A downstream delivery target attached to an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeliveryTarget {
    /// Identifier of the configured target.
    pub id: super::TargetId,
    /// Target kind (`file`, `kubernetes_secret`, ...).
    #[serde(rename = "type")]
    pub kind: DeliveryTargetKind,
    /// Opaque reference resolved by the sink registry (path, secret name...).
    pub reference: String,
    /// Whether this target blocks certificate activation.
    #[serde(default)]
    pub requirement: DeliveryRequirement,
}

impl DeliveryTarget {
    /// Creates a required target of the given kind.
    pub fn new(
        id: impl Into<String>,
        kind: DeliveryTargetKind,
        reference: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            id: super::TargetId::new(id)?,
            kind,
            reference: reference.into(),
            requirement: DeliveryRequirement::Required,
        })
    }
}

/// Kinds of downstream delivery targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryTargetKind {
    /// Local filesystem layout.
    File,
    /// Kubernetes TLS Secret.
    KubernetesSecret,
    /// HashiCorp Vault KV entry.
    VaultKv,
    /// Generic authenticated webhook agent.
    Webhook,
}

/// Whether a delivery target gates certificate activation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryRequirement {
    /// Activation waits until this target is healthy.
    #[default]
    Required,
    /// Activation waits for at least N of the quorum group.
    Quorum(usize),
    /// Failures alert but never block activation.
    BestEffort,
}

/// Challenge types compatible with an identifier, per the target matrix:
///
/// | Identifier | HTTP-01 | DNS-01 | TLS-ALPN-01 |
/// |---|---:|---:|---:|
/// | DNS | ✓ | ✓ | ✓ |
/// | Wildcard DNS | ✗ | ✓ | ✗ |
/// | IPv4 / IPv6 | ✓ | ✗ | ✓ |
pub fn compatible_challenges(identifier: &Identifier) -> ChallengeSet {
    match identifier.kind() {
        IdentifierKind::Dns => ChallengeSet::all(),
        IdentifierKind::WildcardDns => ChallengeSet::new([ChallengeType::Dns01]),
        IdentifierKind::Ipv4 | IdentifierKind::Ipv6 => {
            ChallengeSet::new([ChallengeType::Http01, ChallengeType::TlsAlpn01])
        }
    }
}

/// One identifier's slice of a validation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationPlanItem {
    /// The identifier being validated.
    pub identifier: Identifier,
    /// Challenge types still acceptable for this identifier, in preference
    /// order (DNS-01 < HTTP-01 < TLS-ALPN-01 when all are allowed).
    pub allowed: Vec<ChallengeType>,
    /// Why other compatible types were excluded, for diagnostics.
    pub exclusions: Vec<ChallengeExclusion>,
}

/// Records why a compatible challenge type was excluded by policy or CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeExclusion {
    /// The excluded challenge type.
    pub challenge: ChallengeType,
    /// Why it was excluded.
    pub reason: ExclusionReason,
}

/// Reason a challenge type is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    /// The identifier type is incompatible with the challenge (RFC 8555/8738).
    IncompatibleWithIdentifier,
    /// The caller's validation policy disallows it.
    DisallowedByPolicy,
    /// The CA did not offer it for this authorization.
    NotOfferedByCa,
}

/// A per-identifier validation plan, validated before any order is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationPlan {
    /// One item per distinct identifier.
    pub items: Vec<ValidationPlanItem>,
}

impl ValidationPlan {
    /// The identifiers covered by this plan.
    pub fn identifiers(&self) -> Vec<&Identifier> {
        self.items.iter().map(|i| &i.identifier).collect()
    }

    /// `true` when every identifier has at least one allowed challenge.
    pub fn is_satisfiable(&self) -> bool {
        self.items.iter().all(|i| !i.allowed.is_empty())
    }
}

/// Preference order used when multiple challenge types are viable.
fn challenge_preference() -> [ChallengeType; 3] {
    // DNS-01 covers wildcards and needs no inbound ports; HTTP-01 is the most
    // widely deployed; TLS-ALPN-01 last as it requires port 443 control.
    [
        ChallengeType::Dns01,
        ChallengeType::Http01,
        ChallengeType::TlsAlpn01,
    ]
}

/// Validates that every identifier has at least one challenge type that is
/// (a) compatible with the identifier kind, (b) allowed by the validation
/// policy and (c) offered by the CA.
///
/// Returns a policy error naming the offending identifier otherwise; this
/// check must run *before* any ACME order is created.
pub fn validate_order_policy(
    identifiers: &[Identifier],
    offered: &ChallengeSet,
    policy: &ValidationPolicy,
) -> Result<ValidationPlan> {
    if identifiers.is_empty() {
        return Err(AcmeError::InvalidInput(
            "at least one identifier is required".to_string(),
        ));
    }

    let policy_allowed = if policy.allowed_challenges.is_empty() {
        ChallengeSet::all()
    } else {
        policy.allowed_challenges.clone()
    };

    let mut items = Vec::with_capacity(identifiers.len());
    for identifier in identifiers {
        let compatible = compatible_challenges(identifier);
        let mut allowed = Vec::new();
        let mut exclusions = Vec::new();

        for challenge in challenge_preference() {
            if !compatible.contains(challenge) {
                exclusions.push(ChallengeExclusion {
                    challenge,
                    reason: ExclusionReason::IncompatibleWithIdentifier,
                });
                continue;
            }
            if !policy_allowed.contains(challenge) {
                exclusions.push(ChallengeExclusion {
                    challenge,
                    reason: ExclusionReason::DisallowedByPolicy,
                });
                continue;
            }
            if !offered.contains(challenge) {
                exclusions.push(ChallengeExclusion {
                    challenge,
                    reason: ExclusionReason::NotOfferedByCa,
                });
                continue;
            }
            allowed.push(challenge);
        }

        if allowed.is_empty() {
            let reason = exclusions
                .iter()
                .find(|e| e.reason == ExclusionReason::DisallowedByPolicy)
                .map(|e| e.reason)
                .unwrap_or(ExclusionReason::IncompatibleWithIdentifier);
            return Err(AcmeError::InvalidInput(format!(
                "no compatible challenge for identifier `{identifier}` ({}): {}",
                identifier.acme_type(),
                exclusion_summary(reason)
            )));
        }

        items.push(ValidationPlanItem {
            identifier: identifier.clone(),
            allowed,
            exclusions,
        });
    }

    Ok(ValidationPlan { items })
}

fn exclusion_summary(reason: ExclusionReason) -> &'static str {
    match reason {
        ExclusionReason::IncompatibleWithIdentifier => {
            "identifier kind is incompatible with all allowed challenges (e.g. wildcard requires dns-01, ip cannot use dns-01)"
        }
        ExclusionReason::DisallowedByPolicy => {
            "validation policy disallows all compatible challenges"
        }
        ExclusionReason::NotOfferedByCa => "the CA does not offer any compatible challenge",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns(name: &str) -> Identifier {
        Identifier::try_dns(name).unwrap()
    }

    fn ip(addr: &str) -> Identifier {
        Identifier::try_ip(addr).unwrap()
    }

    #[test]
    fn compatibility_matrix_matches_target() {
        let plain = dns("example.com");
        assert!(compatible_challenges(&plain).contains(ChallengeType::Http01));
        assert!(compatible_challenges(&plain).contains(ChallengeType::Dns01));
        assert!(compatible_challenges(&plain).contains(ChallengeType::TlsAlpn01));

        let wild = dns("*.example.com");
        assert!(!compatible_challenges(&wild).contains(ChallengeType::Http01));
        assert!(compatible_challenges(&wild).contains(ChallengeType::Dns01));
        assert!(!compatible_challenges(&wild).contains(ChallengeType::TlsAlpn01));

        for id in [ip("192.0.2.1"), ip("2001:db8::1")] {
            assert!(compatible_challenges(&id).contains(ChallengeType::Http01));
            assert!(!compatible_challenges(&id).contains(ChallengeType::Dns01));
            assert!(compatible_challenges(&id).contains(ChallengeType::TlsAlpn01));
        }
    }

    #[test]
    fn plan_allows_everything_when_unrestricted() {
        let plan = validate_order_policy(
            &[dns("example.com")],
            &ChallengeSet::all(),
            &ValidationPolicy::default(),
        )
        .unwrap();
        assert!(plan.is_satisfiable());
        assert_eq!(plan.items[0].allowed[0], ChallengeType::Dns01);
    }

    #[test]
    fn rejects_wildcard_with_http_only_policy() {
        let policy = ValidationPolicy {
            allowed_challenges: ChallengeSet::new([ChallengeType::Http01]),
            ..ValidationPolicy::default()
        };
        let err = validate_order_policy(&[dns("*.example.com")], &ChallengeSet::all(), &policy)
            .unwrap_err();
        assert!(err.to_string().contains("*.example.com"));
    }

    #[test]
    fn rejects_ip_with_dns_only_policy() {
        let policy = ValidationPolicy {
            allowed_challenges: ChallengeSet::new([ChallengeType::Dns01]),
            ..ValidationPolicy::default()
        };
        assert!(validate_order_policy(&[ip("192.0.2.1")], &ChallengeSet::all(), &policy).is_err());
        assert!(
            validate_order_policy(&[ip("2001:db8::1")], &ChallengeSet::all(), &policy).is_err()
        );
    }

    #[test]
    fn rejects_when_ca_does_not_offer_compatible_challenge() {
        let offered = ChallengeSet::new([ChallengeType::Dns01]);
        // Plain domain with an HTTP-only policy and a DNS-only CA: nothing left.
        let policy = ValidationPolicy {
            allowed_challenges: ChallengeSet::new([ChallengeType::Http01]),
            ..ValidationPolicy::default()
        };
        assert!(validate_order_policy(&[dns("example.com")], &offered, &policy).is_err());
    }

    #[test]
    fn per_identifier_plan_items() {
        let plan = validate_order_policy(
            &[dns("*.example.com"), ip("192.0.2.1")],
            &ChallengeSet::all(),
            &ValidationPolicy::default(),
        )
        .unwrap();
        assert_eq!(plan.items.len(), 2);
        assert_eq!(plan.items[0].allowed, vec![ChallengeType::Dns01]);
        assert_eq!(
            plan.items[1].allowed,
            vec![ChallengeType::Http01, ChallengeType::TlsAlpn01]
        );
        // Incompatible exclusions are recorded for diagnostics.
        assert!(
            plan.items[0]
                .exclusions
                .iter()
                .any(|e| e.challenge == ChallengeType::Http01
                    && e.reason == ExclusionReason::IncompatibleWithIdentifier)
        );
    }

    #[test]
    fn rejects_empty_identifier_list() {
        assert!(
            validate_order_policy(&[], &ChallengeSet::all(), &ValidationPolicy::default()).is_err()
        );
    }

    #[test]
    fn challenge_set_parses_wire_strings() {
        let set = ChallengeSet::parse(["http-01", "dns-01"]).unwrap();
        assert!(set.contains(ChallengeType::Http01));
        assert!(!set.contains(ChallengeType::TlsAlpn01));
        assert!(ChallengeSet::parse(["bogus"]).is_err());
    }

    #[test]
    fn policies_survive_json_roundtrip() {
        let intent_policy = ValidationPolicy {
            allowed_challenges: ChallengeSet::new([ChallengeType::Dns01]),
            dns_provider: Some("cloudflare-prod".to_string()),
            edge_agent: None,
            propagation: PropagationPolicy::default(),
        };
        let json = serde_json::to_string(&intent_policy).unwrap();
        let back: ValidationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(intent_policy, back);

        let renewal = RenewalPolicy::default();
        let back: RenewalPolicy = serde_json::from_str(&renewal_json()).unwrap();
        assert_eq!(renewal, back);
    }

    fn renewal_json() -> String {
        serde_json::to_string(&RenewalPolicy::default()).unwrap()
    }

    #[test]
    fn policy_defaults_are_sane() {
        let renewal = RenewalPolicy::default();
        assert!(renewal.prefer_ari);
        assert!((renewal.fallback_lifetime_fraction - 2.0 / 3.0).abs() < f64::EPSILON);
        assert_eq!(
            renewal.min_safety_margin,
            Duration::from_secs(3 * 24 * 3600)
        );

        let key = KeyPolicy::default();
        assert_eq!(key.algorithm, KeyAlgorithm::EcP256);
        assert_eq!(key.mode, KeyManagementMode::Managed);
        assert!(!key.exportable);
    }
}
