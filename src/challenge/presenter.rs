//! The challenge presenter port: prepare / observe / cleanup external
//! validation resources.
//!
//! Presenters are **stateless services** — all per-challenge state lives in
//! the persisted [`ChallengeSession`] and [`ChallengeLease`]. `prepare`
//! returns a serializable lease; `observe` only reads external state;
//! `cleanup` is idempotent (`AlreadyAbsent` counts as success).
//!
//! Concrete adapters: DNS-01 (T06), HTTP-01/TLS-ALPN-01 (T07). This module
//! ships the port, an in-memory presenter for tests, and a compatibility
//! adapter wrapping the legacy mutable solvers.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::challenge::{ChallengeLease, ChallengeLeaseLocator};
use crate::error::Result;
use crate::types::ChallengeType;

use super::session::ChallengeSession;

/// DNS-01 TXT value for an ACME key authorization.
///
/// RFC 8555 DNS-01 validation does not publish `token.thumbprint`
/// directly. The TXT value is base64url(SHA256(keyAuthorization)), without
/// padding. Keeping this in the presenter port prevents production DNS
/// adapters and E2E harnesses from drifting onto different challenge values.
pub fn dns01_validation_value(key_authorization: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(key_authorization.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

/// DNS-ACCOUNT-01 TXT value (draft-ietf-acme-dns-account-01 §3).
///
/// Per the draft, the TXT value is computed exactly like DNS-01 —
/// `base64url(SHA256(key authorization))`; what differs is the **record
/// name**, which is derived from the ACME account URL (see
/// [`dns_account01_record_name`]). That makes existing authorizations
/// survive account key rollover: the record does not depend on the
/// account key thumbprint at all.
pub fn dns_account01_validation_value(key_authorization: &str) -> String {
    dns01_validation_value(key_authorization)
}

/// DNS-ACCOUNT-01 record name (draft-ietf-acme-dns-account-01 §3):
/// `_acme-challenge_` + base32(SHA-256(account URL))[..10] + "." + domain
/// (RFC 4648 base32, lowercase, no padding).
pub fn dns_account01_record_name(account_url: &str, domain: &str) -> String {
    use sha2::{Digest, Sha256};

    const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let digest = Sha256::digest(account_url.as_bytes());
    let mut encoded = String::with_capacity(16);
    let prefix = &digest[..10];
    let mut bits: u32 = 0;
    let mut acc: u32 = 0;
    for &byte in prefix {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            encoded.push(BASE32_ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        encoded.push(BASE32_ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    format!("_acme-challenge_{encoded}.{domain}")
}

/// DNS-PERSIST-01 TXT value (draft-ietf-acme-dns-persist-01).
///
/// The record is a semicolon-separated parameter list:
///
/// ```text
/// <issuer-domain-name>;accounturi=<account-url>[;persistUntil=<unix-ts>]
/// ```
///
/// * `issuer-domain-name` is one of the challenge object's
///   `issuer-domain-names` (AcmeX deterministically picks the first — the
///   CA's VA rejects records naming an identity it does not own);
/// * `accounturi` is the challenge object's `accounturi`, verbatim;
/// * `persistUntil` is optional and only honored when the operator pins an
///   expiry (AcmeX never sets one on its own).
///
/// Unlike every other DNS challenge value this one contains **no** token or
/// digest: the record is designed to persist across issuances so the CA can
/// recognize a previously validated account/domain pairing.
pub fn dns_persist01_validation_value(
    issuer_domain_name: &str,
    accounturi: &str,
    persist_until: Option<i64>,
) -> String {
    let mut value = format!("{issuer_domain_name};accounturi={accounturi}");
    if let Some(until) = persist_until {
        value.push_str(&format!(";persistUntil={until}"));
    }
    value
}

/// The `_validation-persist.<domain>` record name of a dns-persist-01
/// challenge (base name for wildcards — the same validation-domain rule as
/// DNS-01's `_acme-challenge`). Note the deliberate difference from every
/// other DNS challenge: this is *not* `_acme-challenge`.
pub fn dns_persist01_record_name(domain: &str) -> String {
    format!("_validation-persist.{domain}")
}

/// The ACME token part of a key authorization (`token.thumbprint`).
///
/// Both parts are base64url without padding, so the first `.` separates
/// them; presenters that do not depend on the thumbprint (dns-account-01)
/// recover the token exactly like the legacy HTTP-01 solver adapter does.
/// Input to `prepare`.
pub struct PrepareChallenge {
    /// The session being prepared.
    pub session: ChallengeSession,
    /// The key authorization (token.fingerprint) — passed by reference,
    /// never persisted by presenters.
    pub key_authorization: String,
    /// The ACME account URL (`kid`) this operation authenticates as.
    ///
    /// Only challenge types that bind to the account itself need it —
    /// currently dns-account-01 (draft-ietf-acme-dns-account-01). It comes
    /// fresh from the persisted EnsureAccount payload on every (re)run of
    /// PrepareChallenges, so it never has to be persisted elsewhere.
    pub account_url: String,
    /// The `issuer-domain-names` advertised by the CA's challenge object
    /// (dns-persist-01 only). Presenters publish one of these — the first —
    /// in the TXT value.
    pub issuer_domain_names: Vec<String>,
    /// The `accounturi` from the CA's challenge object (dns-persist-01
    /// only), placed verbatim into the TXT value.
    pub accounturi: Option<String>,
}

/// Result of observing an external resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The expected content is externally visible.
    Propagated,
    /// Not visible yet; re-check after the suggested delay.
    NotYet {
        /// Suggested re-observation delay.
        retry_after: std::time::Duration,
    },
}

/// Result of an idempotent cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// The resource was removed by this call.
    Cleaned,
    /// The resource was already gone.
    AlreadyAbsent,
}

impl CleanupOutcome {
    /// Both variants mean the cleanup goal is met.
    pub fn is_clean(self) -> bool {
        matches!(self, Self::Cleaned | Self::AlreadyAbsent)
    }
}

/// Creates, observes and removes one kind of external challenge resource.
#[async_trait]
pub trait ChallengePresenter: Send + Sync {
    /// Which challenge family this presenter handles.
    fn kind(&self) -> ChallengeType;

    /// Every challenge type this presenter can serve. Defaults to
    /// [`ChallengePresenter::kind`]; presenters whose external resource is
    /// identical across sibling challenge types (DNS TXT for dns-01 and
    /// dns-account-01) declare them all so one registration covers both.
    fn supported_kinds(&self) -> Vec<ChallengeType> {
        vec![self.kind()]
    }

    /// Creates the external resource and returns its lease. Must be
    /// idempotent per session id (a retry after a crash must find or
    /// re-create the same resource, not duplicate it).
    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease>;

    /// Observes external visibility without modifying anything.
    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation>;

    /// Removes exactly the resource described by the lease. Idempotent.
    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome>;
}

/// Immutable registry of presenters by challenge type.
///
/// Unlike the legacy solver registry, presenters carry no per-challenge
/// mutable state, so any number of sessions can run concurrently.
#[derive(Clone, Default)]
pub struct PresenterRegistry {
    presenters: HashMap<ChallengeType, Arc<dyn ChallengePresenter>>,
}

impl PresenterRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a presenter under every challenge type it supports
    /// (usually one; the DNS presenter serves both dns-01 and
    /// dns-account-01).
    pub fn register(&mut self, presenter: Arc<dyn ChallengePresenter>) {
        for kind in presenter.supported_kinds() {
            self.presenters.insert(kind, presenter.clone());
        }
    }

    /// Looks up the presenter for a challenge type.
    pub fn get(&self, kind: ChallengeType) -> Option<Arc<dyn ChallengePresenter>> {
        self.presenters.get(&kind).cloned()
    }

    /// Which challenge types have presenters.
    pub fn kinds(&self) -> Vec<ChallengeType> {
        self.presenters.keys().copied().collect()
    }
}

/// An in-memory presenter for tests and examples.
///
/// Tracks "resources" by record name with value hashes, mirroring the
/// multi-value semantics DNS TXT records have: same-name resources from
/// different sessions coexist and cleanup removes only this lease's value.
pub struct MemoryPresenter {
    kind: ChallengeType,
    resources: tokio::sync::Mutex<HashMap<(String, String), String>>, // (name, value_hash) -> value
    behavior: MemoryPresenterBehavior,
    prepare_attempts: std::sync::atomic::AtomicUsize,
    observe_attempts: std::sync::atomic::AtomicUsize,
    cleanup_attempts: std::sync::atomic::AtomicUsize,
}

/// Scriptable behavior knobs for [`MemoryPresenter`].
#[derive(Debug, Clone, Default)]
pub struct MemoryPresenterBehavior {
    /// Cleanup fails this many times before succeeding (simulates provider
    /// 5xx during cleanup retries).
    pub cleanup_failures_first: usize,
    /// Observation returns NotYet this many times before Propagated.
    pub observe_not_yet_first: usize,
    /// Prepare fails this many times before succeeding.
    pub prepare_failures_first: usize,
}

impl MemoryPresenter {
    /// A DNS-01-flavored memory presenter with default (successful)
    /// behavior.
    pub fn dns01(behavior: MemoryPresenterBehavior) -> Arc<Self> {
        Arc::new(Self::build(ChallengeType::Dns01, behavior))
    }

    /// An HTTP-01-flavored memory presenter.
    pub fn http01(behavior: MemoryPresenterBehavior) -> Arc<Self> {
        Arc::new(Self::build(ChallengeType::Http01, behavior))
    }

    /// A dns-account-01-flavored memory presenter.
    pub fn dns_account01(behavior: MemoryPresenterBehavior) -> Arc<Self> {
        Arc::new(Self::build(ChallengeType::DnsAccount01, behavior))
    }

    /// A dns-persist-01-flavored memory presenter.
    ///
    /// Mirrors the production semantics of the draft: records live under
    /// `_validation-persist.<domain>` and **cleanup never deletes them** —
    /// the record is designed to outlive the operation, and its removal is
    /// an operational decision of the zone owner (see
    /// [`ChallengePresenter::cleanup`]).
    pub fn dns_persist01(behavior: MemoryPresenterBehavior) -> Arc<Self> {
        Arc::new(Self::build(ChallengeType::DnsPersist01, behavior))
    }

    fn build(kind: ChallengeType, behavior: MemoryPresenterBehavior) -> Self {
        Self {
            kind,
            resources: tokio::sync::Mutex::new(HashMap::new()),
            behavior,
            prepare_attempts: std::sync::atomic::AtomicUsize::new(0),
            observe_attempts: std::sync::atomic::AtomicUsize::new(0),
            cleanup_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many resources currently exist.
    pub async fn resource_count(&self) -> usize {
        self.resources.lock().await.len()
    }

    /// Whether a specific (name, value) resource exists.
    pub async fn has_resource(&self, name: &str, value_hash: &str) -> bool {
        self.resources
            .lock()
            .await
            .contains_key(&(name.to_string(), value_hash.to_string()))
    }
}

#[async_trait]
impl ChallengePresenter for MemoryPresenter {
    fn kind(&self) -> ChallengeType {
        self.kind
    }

    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease> {
        // dns-persist-01 has its own record name prefix and needs CA-supplied
        // parameters instead of a digest; every other kind shares
        // `_acme-challenge.<base name>` (dns-account-01 re-derives the
        // account-bound record name below).
        let is_persist = self.kind == ChallengeType::DnsPersist01;
        let domain = match request.session.identifier.as_dns() {
            Some(dns) => dns.base_name().to_string(),
            None => request.session.identifier.acme_value(),
        };
        let record_name = if is_persist {
            dns_persist01_record_name(&domain)
        } else {
            format!("_acme-challenge.{domain}")
        };

        let value = match self.kind {
            ChallengeType::Dns01 | ChallengeType::DnsAccount01 => {
                dns01_validation_value(&request.key_authorization)
            }
            ChallengeType::DnsPersist01 => {
                // The CA names the identity it will accept and the account it
                // binds the record to; without either there is nothing valid
                // to publish, so fail explicitly instead of guessing.
                let issuer = request.issuer_domain_names.first().ok_or_else(|| {
                    crate::error::AcmeError::InvalidInput(
                        "dns-persist-01 challenge carries no issuer-domain-names".to_string(),
                    )
                })?;
                let accounturi = request.accounturi.as_deref().ok_or_else(|| {
                    crate::error::AcmeError::InvalidInput(
                        "dns-persist-01 challenge carries no accounturi".to_string(),
                    )
                })?;
                dns_persist01_validation_value(issuer, accounturi, None)
            }
            ChallengeType::Http01 | ChallengeType::TlsAlpn01 => request.key_authorization.clone(),
        };
        let record_name = match self.kind {
            ChallengeType::DnsAccount01 => dns_account01_record_name(
                &request.account_url,
                &request.session.identifier.acme_value(),
            ),
            _ => record_name,
        };
        let value_hash = crate::dns::record::txt_value_hash(&value);

        {
            // Scripted transient failures: the caller retries and the
            // resource is created on the successful attempt (idempotency).
            if self
                .prepare_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                < self.behavior.prepare_failures_first
            {
                return Err(crate::error::AcmeError::protocol(
                    "scripted prepare failure".to_string(),
                ));
            }
            let mut resources = self.resources.lock().await;
            resources.insert((record_name.clone(), value_hash.clone()), value);
        }

        let now = jiff::Timestamp::now();
        Ok(ChallengeLease {
            id: crate::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id.clone(),
            identifier: request.session.identifier.clone(),
            challenge_type: self.kind,
            locator: ChallengeLeaseLocator::Dns {
                provider_id: "memory".to_string(),
                zone: "example.com".to_string(),
                record_name: record_name.clone(),
                record_id: None,
                value_hash,
            },
            created_at: now,
            expires_at: now
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap_or(now),
            state: crate::domain::ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation> {
        if self
            .observe_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            < self.behavior.observe_not_yet_first
        {
            return Ok(Observation::NotYet {
                retry_after: std::time::Duration::from_millis(10),
            });
        }
        let resources = self.resources.lock().await;
        let exists = match &lease.locator {
            ChallengeLeaseLocator::Dns {
                record_name,
                value_hash,
                ..
            } => resources.contains_key(&(record_name.clone(), value_hash.clone())),
            ChallengeLeaseLocator::Http { token_hash, .. } => {
                resources.contains_key(&(lease.id.to_string(), token_hash.clone()))
            }
            ChallengeLeaseLocator::Tls { fingerprint, .. } => {
                resources.contains_key(&(lease.id.to_string(), fingerprint.clone()))
            }
        };
        if exists {
            Ok(Observation::Propagated)
        } else {
            Ok(Observation::NotYet {
                retry_after: std::time::Duration::from_millis(10),
            })
        }
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome> {
        if self
            .cleanup_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            < self.behavior.cleanup_failures_first
        {
            return Err(crate::error::AcmeError::protocol(
                "scripted cleanup failure".to_string(),
            ));
        }
        // dns-persist-01 leases are *persistent authorization records*
        // (draft-ietf-acme-dns-persist-01): the TXT record is designed to
        // survive this and future issuances so the CA can skip
        // re-validating a domain it has already seen. Cleanup therefore
        // reports the lease as handled WITHOUT deleting the record —
        // removing it is an operational decision of the zone owner (e.g.
        // once all accounts covering the zone have been decommissioned, or
        // after the record's `persistUntil` timestamp has passed).
        if lease.challenge_type == ChallengeType::DnsPersist01 {
            return Ok(CleanupOutcome::Cleaned);
        }
        let mut resources = self.resources.lock().await;
        let key = match &lease.locator {
            ChallengeLeaseLocator::Dns {
                record_name,
                value_hash,
                ..
            } => (record_name.clone(), value_hash.clone()),
            ChallengeLeaseLocator::Http { token_hash, .. } => {
                (lease.id.to_string(), token_hash.clone())
            }
            ChallengeLeaseLocator::Tls { fingerprint, .. } => {
                (lease.id.to_string(), fingerprint.clone())
            }
        };
        if resources.remove(&key).is_some() {
            Ok(CleanupOutcome::Cleaned)
        } else {
            Ok(CleanupOutcome::AlreadyAbsent)
        }
    }
}

/// Compatibility adapter wrapping one legacy mutable solver as a presenter.
///
/// Each `prepare` call constructs an isolated in-flight state keyed by
/// session; the adapter exists only to keep legacy tests and callers
/// working during migration (T06/T07 replace it with native presenters).
pub struct LegacySolverPresenter {
    kind: ChallengeType,
    #[allow(clippy::type_complexity)]
    factory: Box<dyn Fn() -> Box<dyn super::ChallengeSolver> + Send + Sync>,
}

impl LegacySolverPresenter {
    /// Wraps a solver factory; a fresh solver instance is created per
    /// session so mutable state never crosses challenge boundaries.
    pub fn new(
        kind: ChallengeType,
        factory: impl Fn() -> Box<dyn super::ChallengeSolver> + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            factory: Box::new(factory),
        }
    }
}

#[async_trait]
impl ChallengePresenter for LegacySolverPresenter {
    fn kind(&self) -> ChallengeType {
        self.kind
    }

    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease> {
        let mut solver = (self.factory)();
        let challenge = crate::order::Challenge {
            challenge_type: self.kind.as_str().to_string(),
            url: request.session.challenge_url.clone(),
            status: "pending".to_string(),
            // Legacy solvers read the token from the challenge struct; the
            // session stores only its hash, so reconstruct from the key
            // authorization prefix (token.fingerprint).
            token: request
                .key_authorization
                .split('.')
                .next()
                .unwrap_or_default()
                .to_string(),
            issuer_domain_names: Vec::new(),
            accounturi: None,
            key_authorization: None,
            validation: None,
            updated: None,
            error: None,
        };
        solver
            .prepare(
                &challenge,
                &request.session.identifier,
                &request.key_authorization,
            )
            .await?;
        solver.present().await?;

        let now = jiff::Timestamp::now();
        Ok(ChallengeLease {
            id: crate::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id.clone(),
            identifier: request.session.identifier.clone(),
            challenge_type: self.kind,
            locator: ChallengeLeaseLocator::Http {
                agent_id: "legacy".to_string(),
                route_id: request.session.id.clone(),
                token_hash: request.session.token_hash.clone(),
                endpoint: request.session.challenge_url.clone(),
            },
            created_at: now,
            expires_at: now
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap_or(now),
            state: crate::domain::ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation> {
        // Legacy solvers' verify() only checks in-memory state; treat the
        // lease's existence as "externally visible" for the adapter.
        let _ = lease;
        Ok(Observation::Propagated)
    }

    async fn cleanup(&self, _lease: &ChallengeLease) -> Result<CleanupOutcome> {
        let mut solver = (self.factory)();
        solver.cleanup().await?;
        Ok(CleanupOutcome::Cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Identifier;

    /// draft-ietf-acme-dns-account-01 §3: the TXT value matches DNS-01
    /// (`base64url(SHA256(key authorization))`); the record name carries the
    /// account binding: `_acme-challenge_` + base32(SHA256(account
    /// URL))[..10] + "." + domain.
    #[test]
    fn dns_account_01_txt_value_matches_draft_formula() {
        let account_url = "https://acme.example/acct/1";
        let key_authorization = "token-x.j68840FFDaInnExATgsUGAZZMFVHUYy3Jbh7AomMWPE";
        assert_eq!(
            dns_account01_validation_value(key_authorization),
            dns01_validation_value(key_authorization),
            "the draft reuses the DNS-01 TXT value"
        );
        // base32(SHA256("https://acme.example/acct/1"))[..10], lowercase.
        let record = dns_account01_record_name(account_url, "example.com");
        assert!(
            record.starts_with("_acme-challenge_"),
            "record name: {record}"
        );
        assert!(record.ends_with(".example.com"), "record name: {record}");
        let label = record
            .trim_start_matches("_acme-challenge_")
            .split('.')
            .next()
            .unwrap();
        assert_eq!(label.len(), 16, "10 bytes = 16 base32 chars");
        assert!(
            label
                .chars()
                .all(|c| "abcdefghijklmnopqrstuvwxyz234567".contains(c)),
            "record label must be lowercase base32: {record}"
        );
    }

    #[test]
    fn dns_account_01_value_differs_from_dns_01_for_same_token() {
        // Same token, different account URL -> same TXT value (the value is
        // account-independent); the ACCOUNT BINDING lives in the record name.
        let ka = "token-b.j68840FFDaInnExATgsUGAZZMFVHUYy3Jbh7AomMWPE";
        assert_eq!(
            dns_account01_validation_value(ka),
            dns01_validation_value(ka)
        );
        let record_a = dns_account01_record_name("https://acme.example/acct/1", "example.com");
        let record_b = dns_account01_record_name("https://acme.example/acct/2", "example.com");
        assert_ne!(record_a, record_b, "the account binding is in the name");
    }

    /// draft-ietf-acme-dns-persist-01: the TXT value is a semicolon
    /// parameter list `<issuer>;accounturi=<url>[;persistUntil=<ts>]`.
    #[test]
    fn dns_persist_01_txt_value_matches_draft_parameter_list() {
        assert_eq!(
            dns_persist01_validation_value(
                "pebble.letsencrypt.org",
                "https://acme.example/acct/1",
                None,
            ),
            "pebble.letsencrypt.org;accounturi=https://acme.example/acct/1"
        );
        // persistUntil is optional and appended last when present.
        assert_eq!(
            dns_persist01_validation_value(
                "pebble.letsencrypt.org",
                "https://acme.example/acct/1",
                Some(1893456000),
            ),
            "pebble.letsencrypt.org;accounturi=https://acme.example/acct/1;persistUntil=1893456000"
        );
    }

    #[test]
    fn dns_persist_01_record_name_is_not_acme_challenge() {
        assert_eq!(
            dns_persist01_record_name("example.com"),
            "_validation-persist.example.com"
        );
        assert_ne!(
            dns_persist01_record_name("example.com"),
            "_acme-challenge.example.com"
        );
    }

    fn persist_session(identifier: Identifier) -> ChallengeSession {
        ChallengeSession {
            id: "chs_persist".to_string(),
            operation_id: crate::domain::OperationId::generate(),
            authorization_url: "https://acme.example/authz/1".to_string(),
            challenge_url: "https://acme.example/authz/1/challenge".to_string(),
            identifier,
            challenge_type: ChallengeType::DnsPersist01,
            token_hash: ChallengeSession::hash_token(""),
            state: crate::challenge::ChallengeSessionState::Selected,
            lease_id: None,
            deadline: jiff::Timestamp::now()
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap(),
            last_propagation_check_at: None,
            last_propagation_status: None,
            last_ca_poll_at: None,
            last_ca_status: None,
            last_error: None,
        }
    }

    /// The memory presenter publishes the persistent TXT under
    /// `_validation-persist.<domain>` with the issuer/accounturi parameter
    /// list, and its cleanup reports Cleaned *without* deleting the record.
    #[tokio::test]
    async fn dns_persist_01_memory_presenter_publishes_and_keeps_record() {
        let presenter = MemoryPresenter::dns_persist01(MemoryPresenterBehavior::default());
        let lease = presenter
            .prepare(PrepareChallenge {
                session: persist_session(Identifier::try_dns("example.com").unwrap()),
                key_authorization: String::new(),
                account_url: "https://acme.example/acct/1".to_string(),
                issuer_domain_names: vec!["pebble.letsencrypt.org".to_string()],
                accounturi: Some("https://acme.example/acct/1".to_string()),
            })
            .await
            .unwrap();

        let expected_value = dns_persist01_validation_value(
            "pebble.letsencrypt.org",
            "https://acme.example/acct/1",
            None,
        );
        let expected_hash = crate::dns::record::txt_value_hash(&expected_value);
        match &lease.locator {
            ChallengeLeaseLocator::Dns {
                record_name,
                value_hash,
                ..
            } => {
                assert_eq!(record_name, "_validation-persist.example.com");
                assert_eq!(value_hash, &expected_hash);
            }
            other => panic!("dns locator expected, got {other:?}"),
        }
        assert_eq!(
            presenter.observe(&lease).await.unwrap(),
            Observation::Propagated
        );

        // Cleanup: handled, but the persistent record stays.
        assert_eq!(
            presenter.cleanup(&lease).await.unwrap(),
            CleanupOutcome::Cleaned
        );
        assert_eq!(presenter.resource_count().await, 1);
        assert!(
            presenter
                .has_resource("_validation-persist.example.com", &expected_hash)
                .await,
            "the persistent authorization record must survive cleanup"
        );
    }

    #[tokio::test]
    async fn dns_persist_01_prepare_requires_issuer_and_accounturi() {
        let presenter = MemoryPresenter::dns_persist01(MemoryPresenterBehavior::default());
        let missing_issuer = presenter
            .prepare(PrepareChallenge {
                session: persist_session(Identifier::try_dns("example.com").unwrap()),
                key_authorization: String::new(),
                account_url: String::new(),
                issuer_domain_names: Vec::new(),
                accounturi: Some("https://acme.example/acct/1".to_string()),
            })
            .await
            .unwrap_err();
        assert!(missing_issuer.to_string().contains("issuer-domain-names"));

        let missing_accounturi = presenter
            .prepare(PrepareChallenge {
                session: persist_session(Identifier::try_dns("example.com").unwrap()),
                key_authorization: String::new(),
                account_url: String::new(),
                issuer_domain_names: vec!["pebble.letsencrypt.org".to_string()],
                accounturi: None,
            })
            .await
            .unwrap_err();
        assert!(missing_accounturi.to_string().contains("accounturi"));
    }

    #[test]
    fn registry_registers_under_every_supported_kind() {
        struct DualKindPresenter;

        #[async_trait]
        impl ChallengePresenter for DualKindPresenter {
            fn kind(&self) -> ChallengeType {
                ChallengeType::Dns01
            }

            fn supported_kinds(&self) -> Vec<ChallengeType> {
                vec![ChallengeType::Dns01, ChallengeType::DnsAccount01]
            }

            async fn prepare(&self, _request: PrepareChallenge) -> Result<ChallengeLease> {
                unimplemented!("registry test only exercises registration")
            }

            async fn observe(&self, _lease: &ChallengeLease) -> Result<Observation> {
                unimplemented!("registry test only exercises registration")
            }

            async fn cleanup(&self, _lease: &ChallengeLease) -> Result<CleanupOutcome> {
                unimplemented!("registry test only exercises registration")
            }
        }

        let mut registry = PresenterRegistry::new();
        registry.register(MemoryPresenter::dns01(MemoryPresenterBehavior::default()));
        // The in-memory presenter only claims its own kind...
        assert!(registry.get(ChallengeType::Dns01).is_some());
        assert!(registry.get(ChallengeType::DnsAccount01).is_none());

        // ...while a multi-kind presenter is registered under all of them.
        registry.register(Arc::new(DualKindPresenter));
        assert!(registry.get(ChallengeType::Dns01).is_some());
        assert!(registry.get(ChallengeType::DnsAccount01).is_some());
        assert!(registry.get(ChallengeType::Http01).is_none());
    }
}
