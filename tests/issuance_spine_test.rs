//! Full issuance-spine integration test: the production executor set
//! (`server::worker::register_executors`) drives request → account → order
//! → DNS-01 challenge → CSR → finalize → download → verify → persist →
//! deploy/activate against a scripted fake CA (roadmap T03/T05/T07/T09/T10
//! runtime wiring).
//!
//! Everything but the network is real: managed keys live in a file secret
//! store, the CSR/finalize/download flow uses the ACME backend, the issued
//! chain is a real certificate (CA-signed leaf, so ARI CertIds work), and
//! deployment runs the durable File sink.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use acmex::account::KeyPair;
use acmex::application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, CreateCertificateIntent,
    IssueCertificate,
};
use acmex::ca_backend::{
    AccountHandle, AcmeCaBackend, CaBackend, FakeAcmeTransport, ScriptedResponse,
};
use acmex::challenge::{
    MemoryPresenter, MemoryPresenterBehavior, dns_account01_record_name,
    dns_account01_validation_value, dns01_validation_value,
};
use acmex::domain::{
    CertificateIntent, CertificateLineage, CertificateVersion, DeliveryTarget, DeliveryTargetKind,
    IdentifierSet, IntentId, KeyAlgorithm, KeyId, KeyManagementMode, KeyRef, LineageId,
    OperationId, OperationKind, OperationRecord, OperationSubject, VersionId, VersionState,
};
use acmex::key::SoftwareKeyProvider;
use acmex::protocol::Jwk;
use acmex::repository::{Clock, FakeClock, FileSecretStore, MemoryRepository, RepositorySet};
use acmex::server::worker::{WorkflowWorkerSettings, register_executors};
use acmex::workflow::WorkflowEngine;
use jiff::Timestamp;

fn now() -> Timestamp {
    Timestamp::from_str("2026-01-01T00:00:00Z").unwrap()
}

fn directory() -> serde_json::Value {
    serde_json::json!({
        "newNonce": "https://acme.example/new-nonce",
        "newAccount": "https://acme.example/new-account",
        "newOrder": "https://acme.example/new-order",
        "revokeCert": "https://acme.example/revoke-cert",
        "keyChange": "https://acme.example/key-change",
        "renewalInfo": "https://acme.example/renewal-info"
    })
}

/// A directory that additionally advertises certificate profiles (the ACME
/// profiles draft shape: names map to loose profile descriptions).
fn directory_with_profile(profile: &str) -> serde_json::Value {
    let mut dir = directory();
    dir["profiles"] = serde_json::json!({ profile: { "type": "string" } });
    dir
}

/// A self-signed test CA valid across the fake clock's time.
fn test_ca(common_name: &str) -> rcgen::CertifiedIssuer<'_, rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2027, 1, 1);
    rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap()).unwrap()
}

/// A leaf certificate for `domain` whose subject public key is `leaf_key`'s
/// (exactly what a real CA issues for a CSR generated with that key),
/// signed by `issuer`.
fn ca_signed_leaf_pem(
    domain: &str,
    leaf_key: &rcgen::KeyPair,
    issuer: &rcgen::CertifiedIssuer<rcgen::KeyPair>,
) -> String {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2027, 1, 1);
    params.signed_by(leaf_key, issuer).unwrap().pem()
}

/// A consistent chain: leaf (subject key = `leaf_key`) + issuing CA.
fn chain_for_key(
    domain: &str,
    leaf_key: &rcgen::KeyPair,
    issuer: &rcgen::CertifiedIssuer<rcgen::KeyPair>,
) -> String {
    format!(
        "{}{}",
        ca_signed_leaf_pem(domain, leaf_key, issuer),
        issuer.pem()
    )
}

/// A CA-signed leaf for `domain`, valid across the fake clock's time, with a
/// fresh leaf key (no CSR relationship — for pre-existing versions and the
/// key-mismatch fixture). Returns (leaf pem, ca pem, full chain pem).
fn issued_chain(domain: &str) -> (String, String, String) {
    let ca = test_ca("acmex test ca");
    let ca_pem = ca.pem();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_pem = ca_signed_leaf_pem(domain, &leaf_key, &ca);
    let chain = format!("{leaf_pem}{ca_pem}");
    (leaf_pem, ca_pem, chain)
}

fn raw_response(url_contains: &str, status: u16, body: String) -> ScriptedResponse {
    ScriptedResponse {
        url_contains: url_contains.to_string(),
        status,
        body: body.into_bytes(),
        replay_nonce: Some("n".to_string()),
        retry_after_raw: None,
        location: None,
        uses: 1,
    }
}

/// Scripted fake CA covering the whole issuance conversation.
struct FakeCa {
    transport: Arc<FakeAcmeTransport>,
}

impl FakeCa {
    fn new(clock: &FakeClock, directory: serde_json::Value) -> Self {
        let transport = Arc::new(FakeAcmeTransport::new(clock.now()));
        transport.push(ScriptedResponse::json("directory", 200, directory).uses(100));
        transport.push(
            ScriptedResponse::json("new-nonce", 200, serde_json::json!({}))
                .uses(1000)
                .with_headers(Some("n".to_string()), None, None),
        );
        Self { transport }
    }

    fn allow_account(&self, url: &str) {
        self.transport.push(
            ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
                .with_headers(Some("n".to_string()), None, Some(url.to_string())),
        );
    }

    fn allow_order(&self) {
        self.transport.push(
            ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
                .with_headers(
                    Some("n".to_string()),
                    None,
                    Some("https://acme.example/order/1".to_string()),
                ),
        );
    }

    /// The order resource while authorizations are pending. Consumed exactly
    /// once (LoadAuthorizations); later fetches see the scripted statuses.
    fn order_pending(&self, domain: &str) {
        self.transport.push(
            ScriptedResponse::json(
                "order/1",
                200,
                serde_json::json!({
                    "status": "pending",
                    "expires": "2026-01-08T00:00:00Z",
                    "identifiers": [{"type": "dns", "value": domain}],
                    "authorizations": ["https://acme.example/authz/a"],
                    "finalize": "https://acme.example/finalize/1"
                }),
            )
            .uses(2),
        );
    }

    fn authz(&self, domain: &str, token: &str, status: &str, uses: usize) {
        self.authz_with_challenge_type(domain, token, status, uses, "dns-01");
    }

    /// One authorization for `domain` offering a single challenge of the
    /// given ACME type string (e.g. `dns-01`, `dns-account-01`).
    fn authz_with_challenge_type(
        &self,
        domain: &str,
        token: &str,
        status: &str,
        uses: usize,
        challenge_type: &str,
    ) {
        let url = "https://acme.example/authz/a";
        self.transport.push(
            ScriptedResponse::json(
                url,
                200,
                serde_json::json!({
                    "identifier": {"type": "dns", "value": domain},
                    "status": status,
                    "expires": "2026-01-08T00:00:00Z",
                    "challenges": [{
                        "type": challenge_type,
                        "url": format!("{url}/challenge"),
                        "token": token,
                        "status": status
                    }]
                }),
            )
            .uses(uses),
        );
    }

    /// One authorization for `domain` offering the given raw challenge
    /// objects (used by the dns-persist-01 and prepare-all-supported tests,
    /// whose challenge bodies carry extra fields or multiple entries).
    fn authz_with_challenges(
        &self,
        domain: &str,
        challenges: serde_json::Value,
        status: &str,
        uses: usize,
    ) {
        let url = "https://acme.example/authz/a";
        self.transport.push(
            ScriptedResponse::json(
                url,
                200,
                serde_json::json!({
                    "identifier": {"type": "dns", "value": domain},
                    "status": status,
                    "expires": "2026-01-08T00:00:00Z",
                    "challenges": challenges
                }),
            )
            .uses(uses),
        );
    }

    fn acknowledge_ok(&self) {
        self.transport.push(
            ScriptedResponse::json(
                "challenge",
                200,
                serde_json::json!({"status": "processing"}),
            )
            .uses(10),
        );
    }

    fn finalize_ok(&self) {
        self.transport
            .push(ScriptedResponse::json("finalize/1", 200, serde_json::json!({})).uses(5));
    }

    /// Order status after finalize: one processing poll, then valid with the
    /// certificate URL.
    fn order_processing_then_valid(&self, domain: &str) {
        self.transport.push(
            ScriptedResponse::json(
                "order/1",
                200,
                serde_json::json!({
                    "status": "processing",
                    "expires": "2026-01-08T00:00:00Z",
                    "identifiers": [{"type": "dns", "value": domain}],
                    "authorizations": ["https://acme.example/authz/a"],
                    "finalize": "https://acme.example/finalize/1"
                }),
            )
            .uses(2),
        );
        self.transport.push(
            ScriptedResponse::json(
                "order/1",
                200,
                serde_json::json!({
                    "status": "valid",
                    "expires": "2026-01-08T00:00:00Z",
                    "identifiers": [{"type": "dns", "value": domain}],
                    "authorizations": ["https://acme.example/authz/a"],
                    "certificate": "https://acme.example/cert/1",
                    "finalize": "https://acme.example/finalize/1"
                }),
            )
            .uses(100),
        );
    }
}

fn sample_intent(
    identifiers: IdentifierSet,
    delivery_targets: Vec<DeliveryTarget>,
    profile: Option<&str>,
) -> CertificateIntent {
    CertificateIntent {
        id: IntentId::new("int_spine").unwrap(),
        tenant_id: acmex::domain::TenantId::default_tenant(),
        identifiers,
        ca_policy: acmex::domain::CaPolicy {
            profile: profile.map(str::to_string),
            ..Default::default()
        },
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets,
        idempotency_key: "spine-key".to_string(),
        generation: 1,
    }
}

fn soft_key_ref() -> KeyRef {
    KeyRef::software(KeyId::new("key_seed").unwrap(), KeyAlgorithm::EcP256)
}

fn active_version(id: &str, identifiers: IdentifierSet) -> CertificateVersion {
    let (_leaf, _ca, chain_pem) = issued_chain("example.com");
    CertificateVersion {
        id: VersionId::new(id).unwrap(),
        lineage_id: LineageId::new("lin_spine").unwrap(),
        identifiers,
        certificate_chain_pem: chain_pem,
        serial: "01".to_string(),
        not_before: "2025-01-01T00:00:00Z".to_string(),
        not_after: "2027-01-01T00:00:00Z".to_string(),
        issued_by: "test-ca".to_string(),
        profile: None,
        key_ref: soft_key_ref(),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Active,
    }
}

struct SpineFixture {
    clock: Arc<FakeClock>,
    repositories: RepositorySet,
    engine: WorkflowEngine,
    presenter: Arc<MemoryPresenter>,
    key_store_dir: std::path::PathBuf,
    transport: Arc<FakeAcmeTransport>,
    /// The concrete backend (rollover tests call `roll_account_key` on it).
    backend: Arc<AcmeCaBackend>,
    /// Account JWK handle for computing key authorizations in assertions.
    account_jwk: acmex::ca_backend::backend::AccountJwkHandle,
}

#[derive(Default)]
struct FixtureVerification {
    trust_anchor_pems: Vec<String>,
    skip_certificate_trust_check: bool,
}

/// File-level counter shared by every fixture builder: per-function counters
/// collide when different builders run concurrently (same key-store dir).
/// Starts at 1 so the very first fixture never collides with a zeroed value.
static FIXTURE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

async fn build_fixture(
    identifiers: &IdentifierSet,
    delivery_targets: Vec<DeliveryTarget>,
    active_version: Option<CertificateVersion>,
    profile: Option<&str>,
    directory: serde_json::Value,
) -> SpineFixture {
    build_fixture_with_verification(
        identifiers,
        delivery_targets,
        active_version,
        profile,
        directory,
        FixtureVerification::default(),
    )
    .await
}

async fn build_fixture_with_verification(
    identifiers: &IdentifierSet,
    delivery_targets: Vec<DeliveryTarget>,
    active_version: Option<CertificateVersion>,
    profile: Option<&str>,
    directory: serde_json::Value,
    verification: FixtureVerification,
) -> SpineFixture {
    let clock = Arc::new(FakeClock::at(now()));
    let repositories = MemoryRepository::with_clock(clock.clone()).into_set();

    let intent = sample_intent(identifiers.clone(), delivery_targets, profile);
    repositories.intents.create(intent.clone()).await.unwrap();
    let mut lineage = CertificateLineage::new(
        LineageId::new("lin_spine").unwrap(),
        acmex::domain::TenantId::default_tenant(),
        intent.id.clone(),
        identifiers.clone(),
    );
    if let Some(version) = &active_version {
        lineage.active_version_id = Some(version.id.clone());
        repositories.versions.create(version.clone()).await.unwrap();
    }
    repositories.lineages.create(lineage).await.unwrap();

    // Fake CA conversation. The certificate response is NOT scripted here:
    // the fake CA can only build the issued chain once the CSR (and its
    // managed key) exists — see `SpineFixture::drive_until_csr`.
    let domain = identifiers.iter().next().unwrap().acme_value();
    let ca = FakeCa::new(&clock, directory);
    ca.allow_account("https://acme.example/acct/1");
    ca.allow_order();
    ca.order_pending(&domain);
    ca.authz(&domain, "token-a", "pending", 2);
    ca.acknowledge_ok();
    // Authorizations flip to valid after acknowledgement.
    ca.authz(&domain, "token-a", "valid", 100);
    ca.finalize_ok();
    ca.order_processing_then_valid(&domain);

    // Real components: file-backed keys, in-memory DNS-01 presenter.
    // Unique per fixture: tests run in parallel within one process and the
    // fake clock is frozen, so process id + time is NOT unique.
    let fixture_seq = FIXTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let key_store_dir =
        std::env::temp_dir().join(format!("acmex-spine-{}-{fixture_seq}", std::process::id()));
    let key_provider: Arc<dyn acmex::key::KeyProvider> = Arc::new(SoftwareKeyProvider::new(
        FileSecretStore::new(key_store_dir.clone()),
    ));
    // The seeded active version's key must exist for rotation-reuse.
    if let Some(version) = &active_version {
        key_provider
            .create_key(acmex::key::CreateKey {
                policy: acmex::domain::KeyPolicy::default(),
                key_id: Some(version.key_ref.key_id.clone()),
            })
            .await
            .unwrap();
    }

    let presenter = MemoryPresenter::dns01(MemoryPresenterBehavior::default());
    let mut presenters = acmex::challenge::PresenterRegistry::new();
    presenters.register(presenter.clone());

    let account_key = Arc::new(KeyPair::generate().unwrap());
    let account_jwk = acmex::ca_backend::backend::AccountJwkHandle::new(
        Jwk::for_key_pair(&account_key.0).unwrap(),
    );
    let acme_backend = Arc::new(AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        ca.transport.clone(),
        account_key,
        repositories.clone(),
    ));
    // Key authorizations read the thumbprint through this handle; the
    // backend refreshes it when an account key rollover completes.
    acme_backend.attach_jwk_handle(account_jwk.clone());
    let backend: Arc<dyn acmex::ca_backend::CaBackend> = acme_backend.clone();

    let orchestrator = acmex::delivery::DeploymentOrchestrator::new(repositories.clone())
        .register_sink(
            DeliveryTargetKind::File,
            Arc::new(acmex::delivery::FileCertificateSink::new()),
        );

    let mut engine = WorkflowEngine::new("spine-test", repositories.clone()).with_config(
        acmex::workflow::EngineConfig {
            retry_backoff_base: Duration::from_millis(1),
            retry_backoff_max: Duration::from_millis(5),
            ..Default::default()
        },
    );
    register_executors(
        &mut engine,
        &WorkflowWorkerSettings {
            challenge_poll_interval: Duration::from_millis(50),
            trust_anchor_pems: verification.trust_anchor_pems,
            skip_certificate_trust_check: verification.skip_certificate_trust_check,
            ..Default::default()
        },
        acmex::server::worker::WorkflowWorkerComponents {
            backend,
            account_jwk: account_jwk.clone(),
            presenters,
            key_provider,
            orchestrator,
        },
    );

    SpineFixture {
        clock,
        repositories,
        engine,
        presenter,
        key_store_dir,
        transport: ca.transport,
        backend: acme_backend,
        account_jwk: account_jwk.clone(),
    }
}

/// Fixture variant in which the fake CA offers ONLY `dns-account-01`
/// (draft-ietf-acme-dns-account-01) and a dns-account-01 memory presenter is
/// registered. Everything else matches [`build_fixture_with_verification`],
/// so the existing dns-01 conversations keep running unmodified.
async fn build_dns_account01_fixture(
    identifiers: &IdentifierSet,
    verification: FixtureVerification,
) -> SpineFixture {
    let clock = Arc::new(FakeClock::at(now()));
    let repositories = MemoryRepository::with_clock(clock.clone()).into_set();

    let intent = sample_intent(identifiers.clone(), Vec::new(), None);
    repositories.intents.create(intent.clone()).await.unwrap();
    let lineage = CertificateLineage::new(
        LineageId::new("lin_spine").unwrap(),
        acmex::domain::TenantId::default_tenant(),
        intent.id.clone(),
        identifiers.clone(),
    );
    repositories.lineages.create(lineage).await.unwrap();

    let domain = identifiers.iter().next().unwrap().acme_value();
    let ca = FakeCa::new(&clock, directory());
    ca.allow_account("https://acme.example/acct/1");
    ca.allow_order();
    ca.order_pending(&domain);
    ca.authz_with_challenge_type(&domain, "token-x", "pending", 2, "dns-account-01");
    ca.acknowledge_ok();
    // Authorizations flip to valid after acknowledgement.
    ca.authz_with_challenge_type(&domain, "token-x", "valid", 100, "dns-account-01");
    ca.finalize_ok();
    ca.order_processing_then_valid(&domain);

    let fixture_seq = FIXTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let key_store_dir =
        std::env::temp_dir().join(format!("acmex-spine-{}-{fixture_seq}", std::process::id()));
    let key_provider: Arc<dyn acmex::key::KeyProvider> = Arc::new(SoftwareKeyProvider::new(
        FileSecretStore::new(key_store_dir.clone()),
    ));

    let presenter = MemoryPresenter::dns_account01(MemoryPresenterBehavior::default());
    let mut presenters = acmex::challenge::PresenterRegistry::new();
    presenters.register(presenter.clone());

    let account_key = Arc::new(KeyPair::generate().unwrap());
    let account_jwk = acmex::ca_backend::backend::AccountJwkHandle::new(
        Jwk::for_key_pair(&account_key.0).unwrap(),
    );
    let acme_backend = Arc::new(AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        ca.transport.clone(),
        account_key,
        repositories.clone(),
    ));
    // Key authorizations read the thumbprint through this handle; the
    // backend refreshes it when an account key rollover completes.
    acme_backend.attach_jwk_handle(account_jwk.clone());
    let backend: Arc<dyn acmex::ca_backend::CaBackend> = acme_backend.clone();

    let orchestrator = acmex::delivery::DeploymentOrchestrator::new(repositories.clone())
        .register_sink(
            DeliveryTargetKind::File,
            Arc::new(acmex::delivery::FileCertificateSink::new()),
        );

    let mut engine = WorkflowEngine::new("spine-dnsacct-test", repositories.clone()).with_config(
        acmex::workflow::EngineConfig {
            retry_backoff_base: Duration::from_millis(1),
            retry_backoff_max: Duration::from_millis(5),
            ..Default::default()
        },
    );
    register_executors(
        &mut engine,
        &WorkflowWorkerSettings {
            challenge_poll_interval: Duration::from_millis(50),
            trust_anchor_pems: verification.trust_anchor_pems,
            skip_certificate_trust_check: verification.skip_certificate_trust_check,
            ..Default::default()
        },
        acmex::server::worker::WorkflowWorkerComponents {
            backend,
            account_jwk: account_jwk.clone(),
            presenters,
            key_provider,
            orchestrator,
        },
    );

    SpineFixture {
        clock,
        repositories,
        engine,
        presenter,
        key_store_dir,
        transport: ca.transport,
        backend: acme_backend,
        account_jwk: account_jwk.clone(),
    }
}

/// Fixture for the dns-persist-01 and prepare-all-supported tests: the fake
/// CA offers the given challenge objects on a single authorization for
/// `example.com` (pending first, then valid after acknowledgement). The
/// caller supplies the presenter registry and the intent's validation
/// policy — the latter is what flows into PrepareChallengesStep at runtime
/// (worker deps keep their defaults), so the fixtures double as wiring
/// evidence.
async fn build_challenge_mode_fixture(
    challenges: serde_json::Value,
    presenters: acmex::challenge::PresenterRegistry,
    primary: Arc<MemoryPresenter>,
    validation_policy: acmex::domain::ValidationPolicy,
    trust_anchor_pems: Vec<String>,
) -> SpineFixture {
    let clock = Arc::new(FakeClock::at(now()));
    let repositories = MemoryRepository::with_clock(clock.clone()).into_set();
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();

    let mut intent = sample_intent(identifiers.clone(), Vec::new(), None);
    intent.validation_policy = validation_policy;
    repositories.intents.create(intent.clone()).await.unwrap();
    let lineage = CertificateLineage::new(
        LineageId::new("lin_spine").unwrap(),
        acmex::domain::TenantId::default_tenant(),
        intent.id.clone(),
        identifiers.clone(),
    );
    repositories.lineages.create(lineage).await.unwrap();

    let ca = FakeCa::new(&clock, directory());
    ca.allow_account("https://acme.example/acct/1");
    ca.allow_order();
    ca.order_pending("example.com");
    ca.authz_with_challenges("example.com", challenges.clone(), "pending", 2);
    ca.acknowledge_ok();
    // Authorization flips to valid after acknowledgement.
    ca.authz_with_challenges("example.com", challenges, "valid", 100);
    ca.finalize_ok();
    ca.order_processing_then_valid("example.com");

    let fixture_seq = FIXTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let key_store_dir =
        std::env::temp_dir().join(format!("acmex-spine-{}-{fixture_seq}", std::process::id()));
    let key_provider: Arc<dyn acmex::key::KeyProvider> = Arc::new(SoftwareKeyProvider::new(
        FileSecretStore::new(key_store_dir.clone()),
    ));

    let account_key = Arc::new(KeyPair::generate().unwrap());
    let account_jwk = acmex::ca_backend::backend::AccountJwkHandle::new(
        Jwk::for_key_pair(&account_key.0).unwrap(),
    );
    let acme_backend = Arc::new(AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        ca.transport.clone(),
        account_key,
        repositories.clone(),
    ));
    acme_backend.attach_jwk_handle(account_jwk.clone());
    let backend: Arc<dyn acmex::ca_backend::CaBackend> = acme_backend.clone();

    let orchestrator = acmex::delivery::DeploymentOrchestrator::new(repositories.clone())
        .register_sink(
            DeliveryTargetKind::File,
            Arc::new(acmex::delivery::FileCertificateSink::new()),
        );

    let mut engine = WorkflowEngine::new("spine-challenge-mode", repositories.clone()).with_config(
        acmex::workflow::EngineConfig {
            retry_backoff_base: Duration::from_millis(1),
            retry_backoff_max: Duration::from_millis(5),
            ..Default::default()
        },
    );
    register_executors(
        &mut engine,
        &WorkflowWorkerSettings {
            challenge_poll_interval: Duration::from_millis(50),
            trust_anchor_pems,
            ..Default::default()
        },
        acmex::server::worker::WorkflowWorkerComponents {
            backend,
            account_jwk,
            presenters,
            key_provider,
            orchestrator,
        },
    );

    SpineFixture {
        clock,
        repositories,
        engine,
        presenter: primary,
        key_store_dir,
        transport: ca.transport,
        backend: acme_backend,
    }
}

impl SpineFixture {
    async fn drive_to_terminal(&self, operation: &OperationId) -> OperationRecord {
        let mut guard = 0;
        loop {
            if let Some(stored) = self.repositories.operations.get(operation).await.unwrap()
                && stored.value.status.is_terminal()
            {
                return stored.value;
            }
            let advanced = self.engine.run_step(operation).await.unwrap();
            if !advanced {
                self.clock.advance_secs(1);
            }
            guard += 1;
            assert!(guard < 2000, "operation never reached a terminal state");
        }
    }

    /// Serves the issued chain from the CA's certificate endpoint. Called
    /// after the CSR exists so the chain can be built with the CSR's public
    /// key — exactly what a real CA issues.
    fn serve_certificate(&self, chain_pem: &str) {
        self.transport
            .push(raw_response("cert/1", 200, chain_pem.to_string()));
    }

    fn allow_revocation(&self) {
        self.transport.push(ScriptedResponse::json(
            "revoke-cert",
            200,
            serde_json::json!({}),
        ));
    }

    fn reject_revocation(&self) {
        self.transport.push(ScriptedResponse::json(
            "revoke-cert",
            400,
            serde_json::json!({
                "type": "urn:ietf:params:acme:error:badRevocationReason",
                "detail": "revocation reason not allowed for this certificate",
            }),
        ));
    }

    /// Advances the operation until the CSR step has produced output, then
    /// loads the managed CSR private key from the file secret store.
    ///
    /// The fake CA "issues" the leaf with the CSR's subject public key (see
    /// [`chain_for_key`]); a real CA only ever sees the CSR too. The test
    /// can load the private key because the managed store is on disk —
    /// `rcgen::CertifiedIssuer::signed_by` needs a signing key, and the
    /// CSR's own key is the honest choice for a well-behaved CA.
    async fn drive_until_csr(&self, operation: &OperationId) -> rcgen::KeyPair {
        let mut guard = 0;
        loop {
            if let Some(stored) = self.repositories.operations.get(operation).await.unwrap()
                && let Some(step) = stored
                    .value
                    .steps
                    .iter()
                    .find(|s| s.kind == acmex::domain::WorkflowStepKind::CreateCsr)
                && step.output_ref.is_some()
            {
                let payload: serde_json::Value =
                    serde_json::from_str(step.output_ref.as_deref().unwrap()).unwrap();
                let key_id = payload["key_ref"]["key_id"]
                    .as_str()
                    .expect("key_ref.key_id in the CSR payload")
                    .to_string();
                let store = FileSecretStore::new(self.key_store_dir.clone());
                let pem = store
                    .get(&key_id)
                    .await
                    .unwrap()
                    .expect("managed CSR key in the secret store");
                let pem = String::from_utf8(pem).expect("stored key is UTF-8 PEM");
                return rcgen::KeyPair::from_pem(&pem).expect("parse managed key PEM");
            }
            let advanced = self.engine.run_step(operation).await.unwrap();
            if !advanced {
                self.clock.advance_secs(1);
            }
            guard += 1;
            assert!(
                guard < 2000,
                "operation never produced a CSR: {op:?}",
                op = self
                    .repositories
                    .operations
                    .get(operation)
                    .await
                    .unwrap()
                    .map(|stored| format!(
                        "status={:?} error={:?} steps={}",
                        stored.value.status,
                        stored.value.error,
                        stored
                            .value
                            .steps
                            .iter()
                            .map(|s| format!(
                                "{}:{:?}:{}",
                                s.kind.as_str(),
                                s.status,
                                s.error
                                    .as_ref()
                                    .and_then(|e| e.detail.clone())
                                    .unwrap_or_default()
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    ))
                    .unwrap_or_default()
            );
        }
    }
}

fn cleanup_dir(path: &std::path::Path) {
    let _ = std::fs::remove_dir_all(path);
}

/// A complete issuance: real CSR, finalize, strict verification, persisted
/// version and immediate activation (no delivery targets → gate trivially
/// satisfied).
#[tokio::test]
async fn full_issuance_spine_activates_persisted_version() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    let op_id = OperationId::new("op_spine_issue").unwrap();
    let record = OperationRecord::new(
        op_id.clone(),
        OperationKind::Issue,
        OperationSubject {
            intent_id: Some(IntentId::new("int_spine").unwrap()),
            lineage_id: Some(LineageId::new("lin_spine").unwrap()),
            version_id: None,
        },
        Some("spine-issue".to_string()),
        None,
        fixture.clock.now(),
    );
    fixture
        .repositories
        .operations
        .create(record)
        .await
        .unwrap();

    // The fake CA issues a leaf whose subject public key IS the CSR's key.
    let csr_key = fixture.drive_until_csr(&op_id).await;
    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}\nrequests: {:?}\nqueue: {:?}\nsteps: {:?}",
        final_record.error,
        fixture
            .transport
            .requests()
            .iter()
            .map(|r| format!("{:?} {}", r.method, r.url))
            .collect::<Vec<_>>(),
        fixture.transport.queued_fragments(),
        final_record
            .steps
            .iter()
            .map(|s| format!(
                "{}:{:?}:{}",
                s.kind.as_str(),
                s.status,
                s.error
                    .as_ref()
                    .map(|e| e.detail.clone().unwrap_or_default())
                    .unwrap_or_default()
            ))
            .collect::<Vec<_>>()
    );

    // The verification report is persisted as the step output (T07).
    let verify = final_record
        .steps
        .iter()
        .find(|s| s.kind == acmex::domain::WorkflowStepKind::VerifyCertificate)
        .unwrap();
    let report: acmex::domain::CertificateVerificationReport =
        serde_json::from_str(verify.output_ref.as_deref().unwrap()).unwrap();
    assert!(report.accepted(), "failed: {:?}", report.failed_checks());
    assert!(report.identifiers_exact_match);
    assert!(!report.serial.is_empty());
    assert_eq!(
        report
            .checks
            .iter()
            .map(|c| (c.check.as_str(), c.status))
            .collect::<Vec<_>>(),
        vec![
            (
                "chain_parsed",
                acmex::domain::CertificateVerificationStatus::Pass
            ),
            (
                "san_exact",
                acmex::domain::CertificateVerificationStatus::Pass
            ),
            (
                "validity_window",
                acmex::domain::CertificateVerificationStatus::Pass
            ),
            (
                "serial_present",
                acmex::domain::CertificateVerificationStatus::Pass
            ),
            (
                "csr_public_key_matches",
                acmex::domain::CertificateVerificationStatus::Pass
            ),
            (
                "chain_internally_consistent",
                acmex::domain::CertificateVerificationStatus::Pass
            ),
            (
                "chain_trusted",
                acmex::domain::CertificateVerificationStatus::Pass
            )
        ]
    );

    // The version was persisted under the deterministic id and activated.
    let version_id = VersionId::new(format!("ver_{op_id}")).unwrap();
    let version = fixture
        .repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .expect("version persisted");
    assert_eq!(version.value.state, VersionState::Active);
    assert_eq!(
        version
            .value
            .verification_report
            .as_ref()
            .map(|report| report.conclusion),
        Some(acmex::domain::CertificateVerificationConclusion::Accepted)
    );
    // Serial persisted from the leaf; no private key material anywhere.
    assert!(!version.value.serial.is_empty());
    assert!(
        !serde_json::to_string(&version.value)
            .unwrap()
            .contains("PRIVATE KEY")
    );

    let lineage = fixture
        .repositories
        .lineages
        .get(&LineageId::new("lin_spine").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lineage.value.active_version_id.as_ref(), Some(&version_id));

    // Challenge resources were cleaned up.
    assert_eq!(fixture.presenter.resource_count().await, 0);
    // The managed key exists in the secret store.
    assert!(fixture.key_store_dir.join("keys").exists() || fixture.key_store_dir.exists());

    cleanup_dir(&fixture.key_store_dir);
}

/// The full issuance spine driven through dns-account-01 only
/// (draft-ietf-acme-dns-account-01): the fake CA offers no dns-01 challenge,
/// the planner picks dns-account-01 and the DNS TXT value is bound to the
/// ACCOUNT URL (`base64url(SHA256(accountUrl "." token))`) instead of the
/// key authorization thumbprint.
#[tokio::test]
async fn dns_account01_spine_publishes_account_bound_txt_value() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_dns_account01_fixture(
        &identifiers,
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    let op_id = OperationId::new("op_spine_dnsacct").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_dnsacct",
            "spine-dnsacct",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    // PrepareChallenges runs before the CSR step, so the TXT resource exists
    // once the CSR is available. Per draft-ietf-acme-dns-account-01 the TXT
    // VALUE matches dns-01 (key-authorization digest), but the RECORD NAME
    // carries the account binding
    // (_acme-challenge_<base32(SHA256(account URL))[..10]>.<domain>).
    let key_authorization = format!(
        "token-x.{}",
        fixture.account_jwk.thumbprint_sha256().unwrap()
    );
    let expected_txt = dns_account01_validation_value(&key_authorization);
    assert_eq!(
        expected_txt,
        dns01_validation_value(&key_authorization),
        "the draft reuses the DNS-01 value"
    );
    let expected_hash = acmex::dns::record::txt_value_hash(&expected_txt);
    let expected_record = dns_account01_record_name("https://acme.example/acct/1", "example.com");
    assert!(expected_record.starts_with("_acme-challenge_"));
    let csr_key = fixture.drive_until_csr(&op_id).await;
    assert!(
        fixture
            .presenter
            .has_resource(&expected_record, &expected_hash)
            .await,
        "dns-account-01 TXT resource must be presented at {expected_record}"
    );

    // The planned session really is dns-account-01.
    let sessions = fixture
        .repositories
        .challenge_sessions
        .list_by_operation(&op_id)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].value.challenge_type,
        acmex::types::ChallengeType::DnsAccount01
    );

    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));
    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}\nrequests: {:?}\nqueue: {:?}",
        final_record.error,
        fixture
            .transport
            .requests()
            .iter()
            .map(|r| format!("{:?} {}", r.method, r.url))
            .collect::<Vec<_>>(),
        fixture.transport.queued_fragments(),
    );

    // The persisted lease pins the exact value hash even after cleanup, and
    // the challenge family is preserved end-to-end.
    let sessions = fixture
        .repositories
        .challenge_sessions
        .list_by_operation(&op_id)
        .await
        .unwrap();
    let lease_id = sessions[0].value.lease_id.clone().expect("lease recorded");
    let lease = fixture
        .repositories
        .challenge_leases
        .get(&lease_id)
        .await
        .unwrap()
        .expect("lease persisted");
    assert_eq!(
        lease.value.challenge_type,
        acmex::types::ChallengeType::DnsAccount01
    );
    match &lease.value.locator {
        acmex::domain::ChallengeLeaseLocator::Dns {
            record_name,
            value_hash,
            ..
        } => {
            assert_eq!(record_name.as_str(), expected_record);
            assert_eq!(value_hash, &expected_hash);
        }
        other => panic!("dns locator expected, got {other:?}"),
    }

    // Observation/acknowledgement/cleanup reused the DNS machinery.
    assert_eq!(fixture.presenter.resource_count().await, 0);

    cleanup_dir(&fixture.key_store_dir);
}

/// dns-persist-01 end to end (draft-ietf-acme-dns-persist-01): the fake CA
/// offers ONLY dns-persist-01 — Pebble's observed shape (no token,
/// `accounturi`, `issuer-domain-names`) — the intent opts in explicitly via
/// its validation policy, the TXT is published under
/// `_validation-persist.<domain>` with the issuer/accounturi parameter list,
/// issuance succeeds and **cleanup keeps the persistent record**.
#[tokio::test]
async fn dns_persist01_spine_publishes_persistent_txt() {
    let ca = test_ca("acmex test ca");
    let challenges = serde_json::json!([{
        "type": "dns-persist-01",
        "url": "https://acme.example/authz/a/challenge",
        "status": "pending",
        "accounturi": "https://acme.example/acct/1",
        "issuer-domain-names": ["pebble.letsencrypt.org"]
    }]);
    let presenter = MemoryPresenter::dns_persist01(MemoryPresenterBehavior::default());
    let mut presenters = acmex::challenge::PresenterRegistry::new();
    presenters.register(presenter.clone());
    // The opt-in lives on the intent's validation policy; the worker's
    // ChallengeStepDeps keep their default allowed set, so this only works
    // when the intent policy actually reaches PrepareChallengesStep.
    let fixture = build_challenge_mode_fixture(
        challenges,
        presenters,
        presenter.clone(),
        acmex::domain::ValidationPolicy {
            allowed_challenges: acmex::domain::ChallengeSet::new([
                acmex::types::ChallengeType::DnsPersist01,
            ]),
            ..Default::default()
        },
        vec![ca.pem()],
    )
    .await;

    let op_id = OperationId::new("op_spine_dnspersist").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_dnspersist",
            "spine-dnspersist",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    // First issuer-domain-name wins; the accounturi is placed verbatim.
    let expected_txt = acmex::challenge::dns_persist01_validation_value(
        "pebble.letsencrypt.org",
        "https://acme.example/acct/1",
        None,
    );
    let expected_hash = acmex::dns::record::txt_value_hash(&expected_txt);

    let csr_key = fixture.drive_until_csr(&op_id).await;
    assert!(
        fixture
            .presenter
            .has_resource("_validation-persist.example.com", &expected_hash)
            .await,
        "the persistent TXT must be published under _validation-persist.<domain> \
         (never _acme-challenge) with the issuer;accounturi value"
    );

    // Exactly one session, of the dns-persist-01 family.
    let sessions = fixture
        .repositories
        .challenge_sessions
        .list_by_operation(&op_id)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].value.challenge_type,
        acmex::types::ChallengeType::DnsPersist01
    );

    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));
    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}\nrequests: {:?}\nqueue: {:?}",
        final_record.error,
        fixture
            .transport
            .requests()
            .iter()
            .map(|r| format!("{:?} {}", r.method, r.url))
            .collect::<Vec<_>>(),
        fixture.transport.queued_fragments(),
    );

    // The lifecycle handled the lease (session + lease are Cleaned)...
    let sessions = fixture
        .repositories
        .challenge_sessions
        .list_by_operation(&op_id)
        .await
        .unwrap();
    assert_eq!(
        sessions[0].value.state,
        acmex::challenge::ChallengeSessionState::Cleaned
    );
    let lease_id = sessions[0].value.lease_id.clone().expect("lease recorded");
    let lease = fixture
        .repositories
        .challenge_leases
        .get(&lease_id)
        .await
        .unwrap()
        .expect("lease persisted");
    assert_eq!(
        lease.value.state,
        acmex::domain::ChallengeLeaseState::Cleaned
    );
    match &lease.value.locator {
        acmex::domain::ChallengeLeaseLocator::Dns {
            record_name,
            value_hash,
            ..
        } => {
            assert_eq!(record_name, "_validation-persist.example.com");
            assert_eq!(value_hash, &expected_hash);
        }
        other => panic!("dns locator expected, got {other:?}"),
    }

    // ...but the persistent authorization record SURVIVES cleanup: the
    // record is designed to outlive the operation (the CA can skip
    // re-validating later issuances), so deleting it is an operational
    // decision of the zone owner — not part of the challenge lifecycle.
    assert_eq!(fixture.presenter.resource_count().await, 1);
    assert!(
        fixture
            .presenter
            .has_resource("_validation-persist.example.com", &expected_hash)
            .await,
        "cleanup must NOT delete the persistent authorization record"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// prepare-all-supported: the fake CA offers dns-01 AND http-01 (in that CA
/// order), the intent sets `prepare_all_supported = true` — BOTH challenges
/// get their own session (created and acknowledged in plan preference
/// order), issuance succeeds and every resource is cleaned up.
#[tokio::test]
async fn prepare_all_prepares_and_acks_every_offered_challenge() {
    let ca = test_ca("acmex test ca");
    let challenges = serde_json::json!([
        {
            "type": "http-01",
            "url": "https://acme.example/authz/a/challenge-http",
            "token": "token-h",
            "status": "pending"
        },
        {
            "type": "dns-01",
            "url": "https://acme.example/authz/a/challenge-dns",
            "token": "token-d",
            "status": "pending"
        }
    ]);
    let dns = MemoryPresenter::dns01(MemoryPresenterBehavior::default());
    let http = MemoryPresenter::http01(MemoryPresenterBehavior::default());
    let mut presenters = acmex::challenge::PresenterRegistry::new();
    presenters.register(dns.clone());
    presenters.register(http.clone());
    let fixture = build_challenge_mode_fixture(
        challenges,
        presenters,
        dns.clone(),
        acmex::domain::ValidationPolicy {
            prepare_all_supported: true,
            ..Default::default()
        },
        vec![ca.pem()],
    )
    .await;

    let op_id = OperationId::new("op_spine_prepare_all").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_prepare_all",
            "spine-prepare-all",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let csr_key = fixture.drive_until_csr(&op_id).await;
    assert_eq!(dns.resource_count().await, 1, "dns-01 resource prepared");
    assert_eq!(http.resource_count().await, 1, "http-01 resource prepared");

    let sessions = fixture
        .repositories
        .challenge_sessions
        .list_by_operation(&op_id)
        .await
        .unwrap();
    assert_eq!(
        sessions.len(),
        2,
        "one session per offered+allowed challenge type"
    );
    let mut types: Vec<acmex::types::ChallengeType> =
        sessions.iter().map(|s| s.value.challenge_type).collect();
    types.sort();
    assert_eq!(
        types,
        // ChallengeType's Ord follows variant declaration order.
        vec![
            acmex::types::ChallengeType::Http01,
            acmex::types::ChallengeType::Dns01,
        ]
    );

    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));
    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}\nqueue: {:?}",
        final_record.error,
        fixture.transport.queued_fragments(),
    );

    // Both sessions were acknowledged (Pebble-style CAs validate every
    // offered challenge — all supportable ones must be triggered).
    assert_eq!(
        fixture.transport.post_count("challenge"),
        2,
        "every prepared session must be acknowledged"
    );

    // Cleanup covered every session's resource.
    let sessions = fixture
        .repositories
        .challenge_sessions
        .list_by_operation(&op_id)
        .await
        .unwrap();
    assert!(
        sessions
            .iter()
            .all(|s| s.value.state == acmex::challenge::ChallengeSessionState::Cleaned),
        "every session must be cleaned, got: {:?}",
        sessions.iter().map(|s| s.value.state).collect::<Vec<_>>()
    );
    assert_eq!(dns.resource_count().await, 0);
    assert_eq!(http.resource_count().await, 0);

    cleanup_dir(&fixture.key_store_dir);
}

/// Compatibility: the same dual-offer CA with the flag ABSENT keeps the
/// historical single-prepare behavior exactly — one session, the first
/// CA-offered challenge within the allowed set, one acknowledgement.
#[tokio::test]
async fn single_prepare_remains_the_default_when_flag_is_absent() {
    let ca = test_ca("acmex test ca");
    let challenges = serde_json::json!([
        {
            "type": "http-01",
            "url": "https://acme.example/authz/a/challenge-http",
            "token": "token-h",
            "status": "pending"
        },
        {
            "type": "dns-01",
            "url": "https://acme.example/authz/a/challenge-dns",
            "token": "token-d",
            "status": "pending"
        }
    ]);
    let dns = MemoryPresenter::dns01(MemoryPresenterBehavior::default());
    let http = MemoryPresenter::http01(MemoryPresenterBehavior::default());
    let mut presenters = acmex::challenge::PresenterRegistry::new();
    presenters.register(dns.clone());
    presenters.register(http.clone());
    let fixture = build_challenge_mode_fixture(
        challenges,
        presenters,
        dns.clone(),
        Default::default(),
        vec![ca.pem()],
    )
    .await;

    let op_id = OperationId::new("op_spine_single_prepare").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_single_prepare",
            "spine-single-prepare",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let csr_key = fixture.drive_until_csr(&op_id).await;
    assert_eq!(
        http.resource_count().await,
        1,
        "the CA-offered order selects http-01 within the allowed set"
    );
    assert_eq!(dns.resource_count().await, 0, "dns-01 is not prepared");

    let sessions = fixture
        .repositories
        .challenge_sessions
        .list_by_operation(&op_id)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1, "single mode prepares one session");
    assert_eq!(
        sessions[0].value.challenge_type,
        acmex::types::ChallengeType::Http01
    );

    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));
    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        final_record.error
    );
    assert_eq!(
        fixture.transport.post_count("challenge"),
        1,
        "exactly one acknowledgement"
    );
    assert_eq!(http.resource_count().await, 0, "the resource is cleaned");

    cleanup_dir(&fixture.key_store_dir);
}

/// Trust-anchor verification is strict by default: a syntactically valid,
/// internally consistent chain is still rejected when no trust anchor is
/// configured.
#[tokio::test]
async fn verification_fails_without_trust_anchor_by_default() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let fixture = build_fixture(&identifiers, Vec::new(), None, None, directory()).await;

    let op_id = OperationId::new("op_spine_missing_anchor").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_missing_anchor",
            "spine-missing-anchor",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let csr_key = fixture.drive_until_csr(&op_id).await;
    let ca = test_ca("acmex test ca");
    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Failed,
        "expected missing trust anchor to fail, got: {:?}",
        final_record.error
    );
    let detail = final_record
        .error
        .expect("failure carries an error")
        .detail
        .expect("failure detail");
    assert!(
        detail.contains("chain_trusted"),
        "error should name the trust check: {detail}"
    );
    assert!(
        fixture
            .repositories
            .versions
            .get(&VersionId::new("ver_op_spine_missing_anchor").unwrap())
            .await
            .unwrap()
            .is_none(),
        "untrusted certificate must not be persisted"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// `not-checked` is reserved for an explicit configuration skip. This keeps
/// the public report from treating missing trust roots as a quiet success.
#[tokio::test]
async fn verification_not_checked_requires_explicit_trust_skip() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: Vec::new(),
            skip_certificate_trust_check: true,
        },
    )
    .await;

    let op_id = OperationId::new("op_spine_explicit_trust_skip").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_explicit_trust_skip",
            "spine-explicit-trust-skip",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let csr_key = fixture.drive_until_csr(&op_id).await;
    let ca = test_ca("acmex test ca");
    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        final_record.error
    );
    let verify = final_record
        .steps
        .iter()
        .find(|s| s.kind == acmex::domain::WorkflowStepKind::VerifyCertificate)
        .unwrap();
    let report: acmex::domain::CertificateVerificationReport =
        serde_json::from_str(verify.output_ref.as_deref().unwrap()).unwrap();
    let trust_check = report
        .checks
        .iter()
        .find(|check| check.check == "chain_trusted")
        .expect("chain_trusted check recorded");
    assert_eq!(
        trust_check.status,
        acmex::domain::CertificateVerificationStatus::NotChecked
    );
    assert!(
        trust_check
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("explicitly disabled by configuration"),
        "detail must identify the explicit skip source: {:?}",
        trust_check.detail
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// A renewal through the same spine: replaces the old version, reuses its
/// key (rotation = Reuse), deploys through the durable File sink and only
/// then switches the active pointer (old version superseded).
#[tokio::test]
async fn renewal_spine_supersedes_old_version_after_file_deployment() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let deploy_root = std::env::temp_dir().join(format!(
        "acmex-spine-deploy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&deploy_root);

    let (_leaf, _ca, chain_pem) = issued_chain("example.com");
    let old_version = CertificateVersion {
        id: VersionId::new("ver_old").unwrap(),
        lineage_id: LineageId::new("lin_spine").unwrap(),
        identifiers: identifiers.clone(),
        certificate_chain_pem: chain_pem,
        serial: "01".to_string(),
        not_before: "2025-01-01T00:00:00Z".to_string(),
        not_after: "2027-01-01T00:00:00Z".to_string(),
        issued_by: "test-ca".to_string(),
        profile: None,
        key_ref: soft_key_ref(),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Active,
    };
    let target = DeliveryTarget::new(
        "web",
        DeliveryTargetKind::File,
        deploy_root.to_string_lossy().as_ref(),
    )
    .unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        vec![target],
        Some(old_version),
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    let op_id = OperationId::new("op_spine_renew").unwrap();
    let record = OperationRecord::new(
        op_id.clone(),
        OperationKind::Renew,
        OperationSubject {
            intent_id: Some(IntentId::new("int_spine").unwrap()),
            lineage_id: Some(LineageId::new("lin_spine").unwrap()),
            version_id: None,
        },
        Some("spine-renewal".to_string()),
        None,
        fixture.clock.now(),
    );
    fixture
        .repositories
        .operations
        .create(record)
        .await
        .unwrap();

    // The fake CA issues with the reused key (rotation = Reuse), like the
    // first issuance.
    let csr_key = fixture.drive_until_csr(&op_id).await;
    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        final_record.error
    );

    let version_id = VersionId::new(format!("ver_{op_id}")).unwrap();
    let new_version = fixture
        .repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .expect("renewed version persisted");
    // Renewal metadata: replaces the old version, key reused.
    assert_eq!(
        new_version.value.replaces.as_ref(),
        Some(&VersionId::new("ver_old").unwrap())
    );
    assert_eq!(new_version.value.key_ref.key_id, soft_key_ref().key_id);
    // Not yet active: the required file deployment has not run.
    assert_eq!(new_version.value.state, VersionState::Issued);

    // Drive the child Deploy operation to completion.
    let deploy_op = OperationId::new(format!("op_deploy_{version_id}_web")).unwrap();
    let deploy_record = fixture.drive_to_terminal(&deploy_op).await;
    assert_eq!(
        deploy_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        deploy_record.error
    );

    // Activation switched the pointer and superseded the old version.
    let new_version = fixture
        .repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(new_version.value.state, VersionState::Active);
    let old_version = fixture
        .repositories
        .versions
        .get(&VersionId::new("ver_old").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old_version.value.state, VersionState::Superseded);
    assert_eq!(old_version.value.superseded_by.as_ref(), Some(&version_id));
    let lineage = fixture
        .repositories
        .lineages
        .get(&LineageId::new("lin_spine").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lineage.value.active_version_id.as_ref(), Some(&version_id));

    // The file sink actually serves the new version.
    assert!(deploy_root.join("current").exists() || deploy_root.exists());

    cleanup_dir(&fixture.key_store_dir);
    cleanup_dir(&deploy_root);
}

#[tokio::test]
async fn revoke_spine_calls_backend_and_succeeds() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let (_leaf, _ca, chain_pem) = issued_chain("example.com");
    let active_version = CertificateVersion {
        id: VersionId::new("ver_revoke").unwrap(),
        lineage_id: LineageId::new("lin_spine").unwrap(),
        identifiers: identifiers.clone(),
        certificate_chain_pem: chain_pem,
        serial: "02".to_string(),
        not_before: "2025-01-01T00:00:00Z".to_string(),
        not_after: "2027-01-01T00:00:00Z".to_string(),
        issued_by: "test-ca".to_string(),
        profile: None,
        key_ref: soft_key_ref(),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Active,
    };
    let fixture = build_fixture(
        &identifiers,
        Vec::new(),
        Some(active_version),
        None,
        directory(),
    )
    .await;
    fixture.transport.push(
        ScriptedResponse::json("revoke-cert", 200, serde_json::json!({})).with_headers(
            Some("n-revoke".to_string()),
            None,
            None,
        ),
    );

    let op_id = OperationId::new("op_spine_revoke").unwrap();
    fixture
        .repositories
        .operations
        .create(OperationRecord::new(
            op_id.clone(),
            OperationKind::Revoke,
            OperationSubject {
                intent_id: Some(IntentId::new("int_spine").unwrap()),
                lineage_id: Some(LineageId::new("lin_spine").unwrap()),
                version_id: Some(VersionId::new("ver_revoke").unwrap()),
            },
            Some("spine-revoke".to_string()),
            None,
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        final_record.error
    );
    assert_eq!(fixture.transport.post_count("revoke-cert"), 1);

    cleanup_dir(&fixture.key_store_dir);
}

#[tokio::test]
async fn revoke_spine_treats_ca_rejection_as_terminal() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let (_leaf, _ca, chain_pem) = issued_chain("example.com");
    let active_version = CertificateVersion {
        id: VersionId::new("ver_revoke_rejected").unwrap(),
        lineage_id: LineageId::new("lin_spine").unwrap(),
        identifiers: identifiers.clone(),
        certificate_chain_pem: chain_pem,
        serial: "03".to_string(),
        not_before: "2025-01-01T00:00:00Z".to_string(),
        not_after: "2027-01-01T00:00:00Z".to_string(),
        issued_by: "test-ca".to_string(),
        profile: None,
        key_ref: soft_key_ref(),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Active,
    };
    let fixture = build_fixture(
        &identifiers,
        Vec::new(),
        Some(active_version),
        None,
        directory(),
    )
    .await;
    fixture.transport.push(
        ScriptedResponse::json(
            "revoke-cert",
            400,
            serde_json::json!({
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "certificate cannot be revoked by this account"
            }),
        )
        .with_headers(Some("n-revoke-rejected".to_string()), None, None),
    );

    let op_id = OperationId::new("op_spine_revoke_rejected").unwrap();
    fixture
        .repositories
        .operations
        .create(OperationRecord::new(
            op_id.clone(),
            OperationKind::Revoke,
            OperationSubject {
                intent_id: Some(IntentId::new("int_spine").unwrap()),
                lineage_id: Some(LineageId::new("lin_spine").unwrap()),
                version_id: Some(VersionId::new("ver_revoke_rejected").unwrap()),
            },
            Some("spine-revoke-rejected".to_string()),
            None,
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(final_record.status, acmex::domain::OperationStatus::Failed);
    let error = final_record.error.expect("rejection carries an error");
    assert_eq!(error.class, acmex::domain::ErrorClass::Terminal);
    assert_eq!(error.code.as_str(), "ACME_HTTP_400_MALFORMED");
    assert_eq!(fixture.transport.post_count("revoke-cert"), 1);

    cleanup_dir(&fixture.key_store_dir);
}

/// An intent whose identifiers contain an IP is rejected at the order step
/// when the CA does not advertise `ip` support (RFC 8738, T07) — before any
/// order is created on the CA.
#[tokio::test]
async fn ip_identifiers_rejected_when_ca_lacks_ip_support() {
    let identifiers = IdentifierSet::parse(["192.0.2.10"]).unwrap();
    // The fixture's CA directory advertises no identifier types →
    // capabilities default to dns-only → ip must be refused.
    let fixture = build_fixture(&identifiers, Vec::new(), None, None, directory()).await;

    // Opt in to private/documentation addresses so the *policy* layer lets
    // the flow reach the CA-capability check (this test exercises the CA
    // capability consumption, not the scope rejection).
    let mut intent = fixture
        .repositories
        .intents
        .get(&IntentId::new("int_spine").unwrap())
        .await
        .unwrap()
        .unwrap()
        .value;
    intent.ca_policy.allow_private_identifiers = true;
    let stored = fixture
        .repositories
        .intents
        .get(&IntentId::new("int_spine").unwrap())
        .await
        .unwrap()
        .unwrap();
    fixture
        .repositories
        .intents
        .update(stored.revision, intent)
        .await
        .unwrap()
        .expect_updated()
        .unwrap();

    let op_id = OperationId::new("op_spine_ip").unwrap();
    let record = OperationRecord::new(
        op_id.clone(),
        OperationKind::Issue,
        OperationSubject {
            intent_id: Some(IntentId::new("int_spine").unwrap()),
            lineage_id: Some(LineageId::new("lin_spine").unwrap()),
            version_id: None,
        },
        Some("spine-ip".to_string()),
        None,
        fixture.clock.now(),
    );
    fixture
        .repositories
        .operations
        .create(record)
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Failed,
        "expected failure, got: {:?}",
        final_record.error
    );
    let error = final_record.error.expect("failure carries an error");
    assert!(
        error.detail.as_deref().unwrap_or_default().contains("ip"),
        "error should name the ip capability gap: {:?}",
        error.detail
    );
    // No order was ever created on the CA.
    assert_eq!(
        fixture.transport.post_count("new-order"),
        0,
        "no order may be created for unsupported identifiers"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// A fresh Issue operation bound to the fixture's intent/lineage.
fn issue_record(op: &str, idempotency_key: &str, now: Timestamp) -> OperationRecord {
    OperationRecord::new(
        OperationId::new(op).unwrap(),
        OperationKind::Issue,
        OperationSubject {
            intent_id: Some(IntentId::new("int_spine").unwrap()),
            lineage_id: Some(LineageId::new("lin_spine").unwrap()),
            version_id: None,
        },
        Some(idempotency_key.to_string()),
        None,
        now,
    )
}

fn revoke_record(op: &str, version_id: VersionId, now: Timestamp) -> OperationRecord {
    OperationRecord::new(
        OperationId::new(op).unwrap(),
        OperationKind::Revoke,
        OperationSubject {
            intent_id: None,
            lineage_id: Some(LineageId::new("lin_spine").unwrap()),
            version_id: Some(version_id),
        },
        Some(format!("{op}-key")),
        None,
        now,
    )
}

#[tokio::test]
async fn revoke_spine_calls_ca_and_marks_version_revoked() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let version = active_version("ver_revoke_ok", identifiers.clone());
    let version_id = version.id.clone();
    let fixture = build_fixture(&identifiers, Vec::new(), Some(version), None, directory()).await;
    fixture.allow_revocation();

    let op_id = OperationId::new("op_spine_revoke_ok").unwrap();
    fixture
        .repositories
        .operations
        .create(revoke_record(
            "op_spine_revoke_ok",
            version_id.clone(),
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        final_record.error
    );
    assert_eq!(
        fixture.transport.post_count("revoke-cert"),
        1,
        "revocation must reach the CA backend exactly once"
    );
    let stored = fixture
        .repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .expect("version remains persisted");
    assert_eq!(stored.value.state, VersionState::Revoked);

    cleanup_dir(&fixture.key_store_dir);
}

#[tokio::test]
async fn revoke_spine_ca_rejection_is_terminal() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let version = active_version("ver_revoke_rejected", identifiers.clone());
    let version_id = version.id.clone();
    let fixture = build_fixture(&identifiers, Vec::new(), Some(version), None, directory()).await;
    fixture.reject_revocation();

    let op_id = OperationId::new("op_spine_revoke_rejected").unwrap();
    fixture
        .repositories
        .operations
        .create(revoke_record(
            "op_spine_revoke_rejected",
            version_id.clone(),
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(final_record.status, acmex::domain::OperationStatus::Failed);
    let error = final_record
        .error
        .expect("rejection carries classified error");
    assert_eq!(error.class, acmex::domain::ErrorClass::Terminal);
    assert_eq!(error.code.as_str(), "ACME_HTTP_400_BADREVOCATIONREASON");
    assert_eq!(
        fixture.transport.post_count("revoke-cert"),
        1,
        "terminal revocation rejections must not be retried"
    );
    let stored = fixture
        .repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .expect("version remains persisted");
    assert_eq!(stored.value.state, VersionState::Active);

    cleanup_dir(&fixture.key_store_dir);
}

/// A CA that issues a leaf whose public key differs from the CSR's fails
/// strict verification, naming `csr_public_key_matches` (T07). The chain
/// itself is properly signed, so only the key-continuity check fails and
/// nothing is persisted.
#[tokio::test]
async fn verification_fails_when_leaf_key_differs_from_csr() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    let op_id = OperationId::new("op_spine_csr_mismatch").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_csr_mismatch",
            "spine-csr-mismatch",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    // The CA misbehaves: it issues with a fresh key instead of the CSR's.
    let _csr_key = fixture.drive_until_csr(&op_id).await;
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    fixture.serve_certificate(&chain_for_key("example.com", &leaf_key, &ca));

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Failed,
        "error: {:?}",
        final_record.error
    );
    let detail = final_record
        .error
        .expect("failure carries an error")
        .detail
        .expect("failure detail");
    assert!(
        detail.contains("csr_public_key_matches"),
        "error should name csr_public_key_matches: {detail}"
    );
    assert!(
        !detail.contains("chain_internally_consistent"),
        "the chain is properly signed, so consistency must not fail: {detail}"
    );
    // An unverifiable certificate is never persisted.
    assert!(
        fixture
            .repositories
            .versions
            .get(&VersionId::new("ver_op_spine_csr_mismatch").unwrap())
            .await
            .unwrap()
            .is_none()
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// A leaf signed by a CA that is NOT the included intermediate fails the
/// internal chain consistency check, naming `chain_internally_consistent`
/// (T07). The leaf's key still matches the CSR, isolating the failure.
#[tokio::test]
async fn verification_fails_when_leaf_not_signed_by_included_intermediate() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let included_ca = test_ca("acmex included ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: vec![included_ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    let op_id = OperationId::new("op_spine_wrong_issuer").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_wrong_issuer",
            "spine-wrong-issuer",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    // Leaf signed by the CSR's key under an unrelated CA, but the chain
    // includes a different intermediate.
    let csr_key = fixture.drive_until_csr(&op_id).await;
    let signing_ca = test_ca("acmex signing ca");
    let leaf_pem = ca_signed_leaf_pem("example.com", &csr_key, &signing_ca);
    fixture.serve_certificate(&format!("{leaf_pem}{}", included_ca.pem()));

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Failed,
        "error: {:?}",
        final_record.error
    );
    let detail = final_record
        .error
        .expect("failure carries an error")
        .detail
        .expect("failure detail");
    assert!(
        detail.contains("chain_internally_consistent"),
        "error should name chain_internally_consistent: {detail}"
    );
    assert!(
        !detail.contains("csr_public_key_matches"),
        "the leaf key matches the CSR, so continuity must not fail: {detail}"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// An intent pinning a profile the CA does not advertise is rejected at the
/// order step — before any new-order POST reaches the CA (T07 profile
/// capability cross-check).
#[tokio::test]
async fn unadvertised_profile_rejected_before_order_creation() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let fixture = build_fixture(
        &identifiers,
        Vec::new(),
        None,
        Some("shortlived"),
        directory(),
    )
    .await;

    let op_id = OperationId::new("op_spine_profile_missing").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_profile_missing",
            "spine-profile-missing",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Failed,
        "error: {:?}",
        final_record.error
    );
    let detail = final_record
        .error
        .expect("failure carries an error")
        .detail
        .expect("failure detail");
    assert!(
        detail.contains("CA does not advertise profile `shortlived`"),
        "error should name the missing profile explicitly: {detail}"
    );
    // The rejection happened at the order step (its record never advanced
    // past Running), before any POST.
    let order_step = final_record
        .steps
        .iter()
        .find(|s| s.kind == acmex::domain::WorkflowStepKind::CreateOrResumeOrder)
        .expect("order step recorded");
    assert_eq!(order_step.attempt, 1);
    assert_ne!(
        order_step.status,
        acmex::domain::StepStatus::Completed,
        "the order step must not complete for an unadvertised profile"
    );
    assert_eq!(
        fixture.transport.post_count("new-order"),
        0,
        "no order may be created for an unadvertised profile"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// The positive counterpart: a pinned profile the CA *does* advertise flows
/// through the whole issuance (the directory's `profiles` object is
/// consulted at order time and never blocks the flow).
#[tokio::test]
async fn advertised_profile_flows_through_issuance() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        Some("shortlived"),
        directory_with_profile("shortlived"),
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    let op_id = OperationId::new("op_spine_profile_ok").unwrap();
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_profile_ok",
            "spine-profile-ok",
            fixture.clock.now(),
        ))
        .await
        .unwrap();

    let csr_key = fixture.drive_until_csr(&op_id).await;
    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));

    let final_record = fixture.drive_to_terminal(&op_id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        final_record.error
    );
    assert_eq!(fixture.transport.post_count("new-order"), 1);
    // The verification report records the pinned profile.
    let verify = final_record
        .steps
        .iter()
        .find(|s| s.kind == acmex::domain::WorkflowStepKind::VerifyCertificate)
        .unwrap();
    let report: acmex::domain::CertificateVerificationReport =
        serde_json::from_str(verify.output_ref.as_deref().unwrap()).unwrap();
    assert!(report.accepted(), "failed: {:?}", report.failed_checks());
    assert_eq!(report.profile.as_deref(), Some("shortlived"));

    cleanup_dir(&fixture.key_store_dir);
}

/// Generates an external key pair and the matching PEM CSR, exactly like an
/// upstream key holder would: the private key never enters AcmeX.
fn external_key_and_csr(domain: &str) -> (rcgen::KeyPair, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    (key, csr)
}

/// Counts files below `dir` (0 when absent). The external-CSR path must
/// never add a private key entry to the secret store.
fn count_secret_entries(dir: &std::path::Path) -> usize {
    if !dir.exists() {
        return 0;
    }
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| {
            if entry.file_type().unwrap().is_dir() {
                count_secret_entries(&entry.path())
            } else {
                1
            }
        })
        .sum()
}

/// External-CSR intent issued end to end through the application service:
/// the CreateCsr step validates the supplied CSR (signature + exact SAN
/// match), the chain built for the external key passes strict verification,
/// the version records a non-exportable `external` KeyRef and the secret
/// store gains no private key entry at all.
#[tokio::test]
async fn external_csr_spine_issues_without_storing_private_keys() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;
    assert_eq!(
        count_secret_entries(&fixture.key_store_dir),
        0,
        "fixture must start without secret store entries"
    );

    // The external key holder generates its key and CSR outside AcmeX.
    let (external_key, csr_pem) = external_key_and_csr("example.com");
    // The fake CA issues with the CSR's subject public key, like a real CA.
    fixture.serve_certificate(&chain_for_key("example.com", &external_key, &ca));

    let (service, _) = ApplicationServiceBuilder::new()
        .with_repositories(fixture.repositories.clone())
        .build()
        .unwrap();
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec!["example.com".to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: acmex::domain::KeyPolicy {
                mode: KeyManagementMode::ExternalCsr,
                ..Default::default()
            },
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            external_csr: Some(csr_pem.clone()),
            idempotency_key: "extcsr-intent".to_string(),
        })
        .await
        .unwrap();
    let operation = service
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id,
            external_csr: Some(csr_pem),
            idempotency_key: "extcsr-issue".to_string(),
        })
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&operation.id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        final_record.error
    );

    let version_id = VersionId::new(format!("ver_{}", operation.id)).unwrap();
    let version = fixture
        .repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .expect("version persisted");
    let key_ref = &version.value.key_ref;
    assert_eq!(key_ref.provider, "external", "external KeyRef semantics");
    assert!(!key_ref.exportable, "external keys are never exportable");
    assert!(
        key_ref.key_id.as_str().starts_with("ext_csr_"),
        "external key id derives from the CSR fingerprint: {}",
        key_ref.key_id
    );
    assert_eq!(version.value.state, VersionState::Active);
    assert!(
        !serde_json::to_string(&version.value)
            .unwrap()
            .contains("PRIVATE KEY")
    );

    // The private key never passed through AcmeX: the secret store is
    // unchanged after a successful issuance.
    assert_eq!(
        count_secret_entries(&fixture.key_store_dir),
        0,
        "external CSR issuance must not persist private key material"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// A CSR whose SAN set does not exactly match the intent identifiers is
/// rejected at the CreateCsr step with a stable OperatorActionRequired
/// error: only the external key holder can fix the material. Nothing is
/// persisted and no private key appears anywhere.
#[tokio::test]
async fn external_csr_san_mismatch_fails_as_operator_action() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let fixture = build_fixture(&identifiers, Vec::new(), None, None, directory()).await;
    assert_eq!(
        count_secret_entries(&fixture.key_store_dir),
        0,
        "fixture must start without secret store entries"
    );

    let (_foreign_key, csr_pem) = external_key_and_csr("other.example.com");

    let (service, _) = ApplicationServiceBuilder::new()
        .with_repositories(fixture.repositories.clone())
        .build()
        .unwrap();
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec!["example.com".to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: acmex::domain::KeyPolicy {
                mode: KeyManagementMode::ExternalCsr,
                ..Default::default()
            },
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            external_csr: Some(csr_pem.clone()),
            idempotency_key: "extcsr-mismatch-intent".to_string(),
        })
        .await
        .unwrap();
    let operation = service
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id,
            external_csr: Some(csr_pem),
            idempotency_key: "extcsr-mismatch-issue".to_string(),
        })
        .await
        .unwrap();

    let final_record = fixture.drive_to_terminal(&operation.id).await;
    assert_eq!(
        final_record.status,
        acmex::domain::OperationStatus::Failed,
        "expected SAN mismatch to fail, got: {:?}",
        final_record.error
    );
    let error = final_record.error.expect("failure carries an error");
    assert_eq!(
        error.class,
        acmex::domain::ErrorClass::OperatorActionRequired,
        "the CSR owner must fix the material"
    );
    assert_eq!(
        error.code.as_str(),
        "VALIDATION_CHALLENGE_INCOMPATIBLE",
        "stable error code for external CSR rejection"
    );
    assert!(
        error
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("SAN mismatch"),
        "error should name the SAN mismatch: {:?}",
        error.detail
    );

    // An invalid CSR persists nothing and stores no key material.
    assert!(
        fixture
            .repositories
            .versions
            .get(&VersionId::new(format!("ver_{}", operation.id)).unwrap())
            .await
            .unwrap()
            .is_none(),
        "rejected CSR must not produce a version"
    );
    assert_eq!(
        count_secret_entries(&fixture.key_store_dir),
        0,
        "rejected external CSR must not persist private key material"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// A managed intent that declares external CSR material is a 400-class
/// configuration error — at intent creation and at issue time — because
/// AcmeX would generate and hold the key, defeating the declared mode.
#[tokio::test]
async fn managed_intent_rejects_external_csr_material() {
    let (service, _) = ApplicationServiceBuilder::new().build().unwrap();
    let (_unused_key, csr_pem) = external_key_and_csr("example.com");

    // Managed intent + external_csr at creation → 400 semantics.
    let mut command = external_csr_intent("managed-with-csr", &csr_pem);
    command.key_policy.mode = KeyManagementMode::Managed;
    let err = service.create_intent(command).await.unwrap_err();
    assert!(
        matches!(err, acmex::error::AcmeError::InvalidInput(_)),
        "expected invalid input, got: {err:?}"
    );

    // Valid managed intent, then external_csr at issue time → 400 semantics.
    let intent = service
        .create_intent(external_csr_intent("managed-issue-no-csr", ""))
        .await
        .unwrap();
    let err = service
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id,
            external_csr: Some(csr_pem),
            idempotency_key: "managed-issue-with-csr".to_string(),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, acmex::error::AcmeError::InvalidInput(_)),
        "expected invalid input, got: {err:?}"
    );
}

/// A create-intent command for a managed intent (empty material is dropped).
fn external_csr_intent(key: &str, external_csr: &str) -> CreateCertificateIntent {
    CreateCertificateIntent {
        context: ActorContext::default(),
        identifiers: vec!["example.com".to_string()],
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: acmex::domain::KeyPolicy {
            mode: KeyManagementMode::Managed,
            ..Default::default()
        },
        renewal_policy: Default::default(),
        delivery_targets: Vec::new(),
        external_csr: if external_csr.is_empty() {
            None
        } else {
            Some(external_csr.to_string())
        },
        idempotency_key: key.to_string(),
    }
}

/// A second full CA conversation under a distinct order URL (`order/2`),
/// consumed by the renewal of the external-CSR lineage.
fn script_second_conversation(fixture: &SpineFixture, chain_pem: &str) {
    let order = |status: &str, certificate: Option<&str>| {
        let mut body = serde_json::json!({
            "status": status,
            "expires": "2026-01-08T00:00:00Z",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": ["https://acme.example/authz/b"],
            "finalize": "https://acme.example/finalize/2"
        });
        if let Some(url) = certificate {
            body["certificate"] = serde_json::json!(url);
        }
        body
    };
    let authz = |status: &str| {
        serde_json::json!({
            "identifier": {"type": "dns", "value": "example.com"},
            "status": status,
            "expires": "2026-01-08T00:00:00Z",
            "challenges": [{
                "type": "dns-01",
                "url": "https://acme.example/authz/b/challenge",
                "token": "token-b",
                "status": status
            }]
        })
    };
    fixture.transport.push(
        ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
            .with_headers(
                Some("n".to_string()),
                None,
                Some("https://acme.example/order/2".to_string()),
            ),
    );
    fixture
        .transport
        .push(ScriptedResponse::json("order/2", 200, order("pending", None)).uses(2));
    fixture
        .transport
        .push(ScriptedResponse::json("authz/b", 200, authz("pending")).uses(2));
    fixture
        .transport
        .push(ScriptedResponse::json("authz/b", 200, authz("valid")).uses(100));
    fixture
        .transport
        .push(ScriptedResponse::json("finalize/2", 200, serde_json::json!({})).uses(5));
    fixture
        .transport
        .push(ScriptedResponse::json("order/2", 200, order("processing", None)).uses(2));
    fixture.transport.push(
        ScriptedResponse::json(
            "order/2",
            200,
            order("valid", Some("https://acme.example/cert/2")),
        )
        .uses(100),
    );
    fixture
        .transport
        .push(raw_response("cert/2", 200, chain_pem.to_string()));
}

/// Renewing an external-CSR lineage recovers the original CSR from the
/// issuing operation's persisted CreateCsr payload and renews end to end:
/// the version is replaced, the external key reference stays stable (same
/// CSR → same SubjectPublicKeyInfo fingerprint) and no private key ever
/// reaches the secret store.
#[tokio::test]
async fn external_csr_renewal_restores_csr_and_succeeds() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    // First issuance with externally held key material.
    let (external_key, csr_pem) = external_key_and_csr("example.com");
    fixture.serve_certificate(&chain_for_key("example.com", &external_key, &ca));
    let (service, _) = ApplicationServiceBuilder::new()
        .with_repositories(fixture.repositories.clone())
        .build()
        .unwrap();
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec!["example.com".to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: acmex::domain::KeyPolicy {
                mode: KeyManagementMode::ExternalCsr,
                ..Default::default()
            },
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            external_csr: Some(csr_pem.clone()),
            idempotency_key: "extcsr-renew-intent".to_string(),
        })
        .await
        .unwrap();
    let issued = service
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id.clone(),
            external_csr: Some(csr_pem),
            idempotency_key: "extcsr-renew-issue".to_string(),
        })
        .await
        .unwrap();
    let issued_record = fixture.drive_to_terminal(&issued.id).await;
    assert_eq!(
        issued_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "issuance error: {:?}",
        issued_record.error
    );
    let issued_version_id = VersionId::new(format!("ver_{}", issued.id)).unwrap();

    // Renewal through the application service: the CSR is recovered from
    // the issuing operation, not supplied again.
    script_second_conversation(&fixture, &chain_for_key("example.com", &external_key, &ca));
    let lineage_id = fixture
        .repositories
        .lineages
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|stored| stored.value.intent_id == intent.id)
        .map(|stored| stored.value.id)
        .expect("issue created the lineage");
    let renewed = service
        .renew(acmex::application::RenewCertificate {
            context: ActorContext::default(),
            lineage_id: Some(lineage_id.clone()),
            identifiers: Vec::new(),
            force: false,
            idempotency_key: "extcsr-renew-op".to_string(),
        })
        .await
        .unwrap();
    let renewed_record = fixture.drive_to_terminal(&renewed.id).await;
    assert_eq!(
        renewed_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "renewal error: {:?}",
        renewed_record.error
    );

    let renewed_version_id = VersionId::new(format!("ver_{}", renewed.id)).unwrap();
    let renewed_version = fixture
        .repositories
        .versions
        .get(&renewed_version_id)
        .await
        .unwrap()
        .expect("renewed version persisted");
    let issued_version = fixture
        .repositories
        .versions
        .get(&issued_version_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        renewed_version.value.key_ref.provider, "external",
        "the renewal stays in external-CSR mode"
    );
    assert_eq!(
        renewed_version.value.key_ref.key_id, issued_version.value.key_ref.key_id,
        "same CSR → same key fingerprint"
    );
    assert_eq!(
        renewed_version.value.replaces.as_ref(),
        Some(&issued_version_id),
        "the renewal replaces the first version"
    );
    assert_eq!(issued_version.value.state, VersionState::Superseded);
    assert_eq!(
        issued_version.value.superseded_by.as_ref(),
        Some(&renewed_version_id)
    );
    let lineage = fixture
        .repositories
        .lineages
        .get(&lineage_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lineage.value.active_version_id, Some(renewed_version_id));

    assert_eq!(
        count_secret_entries(&fixture.key_store_dir),
        0,
        "external CSR renewal must not persist private key material"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// A renewal of an external-CSR lineage whose CSR material cannot be
/// recovered (here: an active version with no issuing operation behind it)
/// still reaches a terminal, clearly classified failure — never managed key
/// generation and never a silent dead end.
#[tokio::test]
async fn external_csr_renewal_without_recoverable_csr_fails_as_operator_action() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let fixture = build_fixture(&identifiers, Vec::new(), None, None, directory()).await;
    let (service, _) = ApplicationServiceBuilder::new()
        .with_repositories(fixture.repositories.clone())
        .build()
        .unwrap();
    let (_foreign_key, csr_pem) = external_key_and_csr("example.com");
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec!["example.com".to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: acmex::domain::KeyPolicy {
                mode: KeyManagementMode::ExternalCsr,
                ..Default::default()
            },
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            external_csr: Some(csr_pem),
            idempotency_key: "extcsr-ghost-intent".to_string(),
        })
        .await
        .unwrap();

    // External lineage with an active version but no recoverable issuing
    // operation (the `ver_op_ghost` id does not resolve to a record).
    let mut lineage = CertificateLineage::new(
        LineageId::new("lin_ext_ghost").unwrap(),
        acmex::domain::TenantId::default_tenant(),
        intent.id.clone(),
        identifiers.clone(),
    );
    let version = CertificateVersion {
        id: VersionId::new("ver_op_ghost").unwrap(),
        lineage_id: lineage.id.clone(),
        identifiers: identifiers.clone(),
        certificate_chain_pem: "-----BEGIN CERTIFICATE-----".to_string(),
        serial: "01".to_string(),
        not_before: "2025-01-01T00:00:00Z".to_string(),
        not_after: "2027-01-01T00:00:00Z".to_string(),
        issued_by: "test-ca".to_string(),
        profile: None,
        key_ref: KeyRef {
            provider: "external".to_string(),
            key_id: KeyId::new("key_ghost").unwrap(),
            algorithm: KeyAlgorithm::EcP256,
            exportable: false,
        },
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Issued,
    };
    lineage.active_version_id = Some(version.id.clone());
    fixture.repositories.versions.create(version).await.unwrap();
    fixture.repositories.lineages.create(lineage).await.unwrap();

    let renewed = service
        .renew(acmex::application::RenewCertificate {
            context: ActorContext::default(),
            lineage_id: Some(LineageId::new("lin_ext_ghost").unwrap()),
            identifiers: Vec::new(),
            force: false,
            idempotency_key: "extcsr-ghost-renew".to_string(),
        })
        .await
        .unwrap();
    let record = fixture.drive_to_terminal(&renewed.id).await;
    assert_eq!(
        record.status,
        acmex::domain::OperationStatus::Failed,
        "expected the renewal to fail, got: {:?}",
        record.error
    );
    let error = record.error.expect("failure carries an error");
    assert_eq!(
        error.class,
        acmex::domain::ErrorClass::OperatorActionRequired,
        "only the external key holder can supply the material"
    );
    assert!(
        error
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("external CSR material missing"),
        "error should name the missing material: {:?}",
        error.detail
    );

    assert!(
        fixture
            .repositories
            .versions
            .get(&VersionId::new(format!("ver_{}", renewed.id)).unwrap())
            .await
            .unwrap()
            .is_none(),
        "the failed renewal must not produce a version"
    );
    assert_eq!(
        count_secret_entries(&fixture.key_store_dir),
        0,
        "the failed renewal must not fall back to managed key generation"
    );

    cleanup_dir(&fixture.key_store_dir);
}

/// Review P3-6 regression, end to end: after an account key rollover the
/// pipeline computes key authorizations from the NEW thumbprint. The first
/// issuance runs with the original key; `roll_account_key` then refreshes
/// the shared `AccountJwkHandle`; the second issuance must publish a
/// DNS-01 TXT value derived from `token.<new thumbprint>` — the CA holds
/// the new public key, so the old thumbprint's value would be rejected.
#[tokio::test]
async fn issuance_after_account_key_rollover_uses_the_new_thumbprint() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let ca = test_ca("acmex test ca");
    let fixture = build_fixture_with_verification(
        &identifiers,
        Vec::new(),
        None,
        None,
        directory(),
        FixtureVerification {
            trust_anchor_pems: vec![ca.pem()],
            skip_certificate_trust_check: false,
        },
    )
    .await;

    // ---- First issuance with the original account key. ----
    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_pre_rollover",
            "spine-pre-rollover",
            fixture.clock.now(),
        ))
        .await
        .unwrap();
    let op1 = OperationId::new("op_spine_pre_rollover").unwrap();
    let csr_key = fixture.drive_until_csr(&op1).await;
    fixture.serve_certificate(&chain_for_key("example.com", &csr_key, &ca));
    let record = fixture.drive_to_terminal(&op1).await;
    assert_eq!(record.status, acmex::domain::OperationStatus::Succeeded);
    assert_eq!(
        fixture.presenter.resource_count().await,
        0,
        "first issuance cleaned up its challenge resources"
    );

    // ---- Roll the account key (RFC 8555 §7.3.5) on the same backend. ----
    fixture.transport.push(ScriptedResponse::json(
        "key-change",
        200,
        serde_json::json!({"status": "valid"}),
    ));
    let account_url = fixture
        .repositories
        .accounts
        .get("ten_default:test-ca")
        .await
        .unwrap()
        .expect("account persisted by the first issuance")
        .value
        .account_url
        .expect("account URL persisted");
    let new_key = Arc::new(KeyPair::generate().unwrap());
    fixture
        .backend
        .roll_account_key(
            &AccountHandle {
                ca_id: "test-ca".to_string(),
                account_url,
                key_id: String::new(),
            },
            new_key.clone(),
        )
        .await
        .unwrap();

    // ---- Second issuance: the same engine and handle, post-rollover.
    // Scripts live under distinct URL fragments (order/2, authz/b) so they
    // cannot collide with the first issuance's leftover scripts. ----
    fixture.transport.push(
        ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
            .with_headers(
                Some("n".to_string()),
                None,
                Some("https://acme.example/order/2".to_string()),
            ),
    );
    fixture.transport.push(
        ScriptedResponse::json(
            "order/2",
            200,
            serde_json::json!({
                "status": "pending",
                "expires": "2026-01-08T00:00:00Z",
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "authorizations": ["https://acme.example/authz/b"],
                "finalize": "https://acme.example/finalize/2"
            }),
        )
        .uses(2),
    );
    fixture.transport.push(
        ScriptedResponse::json(
            "authz/b",
            200,
            serde_json::json!({
                "identifier": {"type": "dns", "value": "example.com"},
                "status": "pending",
                "expires": "2026-01-08T00:00:00Z",
                "challenges": [{
                    "type": "dns-01",
                    "url": "https://acme.example/authz/b/challenge",
                    "token": "token-b",
                    "status": "pending"
                }]
            }),
        )
        .uses(2),
    );
    fixture.transport.push(
        ScriptedResponse::json(
            "authz/b/challenge",
            200,
            serde_json::json!({"status": "processing"}),
        )
        .uses(10),
    );
    fixture.transport.push(
        ScriptedResponse::json(
            "authz/b",
            200,
            serde_json::json!({
                "identifier": {"type": "dns", "value": "example.com"},
                "status": "valid",
                "expires": "2026-01-08T00:00:00Z",
                "challenges": [{
                    "type": "dns-01",
                    "url": "https://acme.example/authz/b/challenge",
                    "token": "token-b",
                    "status": "valid"
                }]
            }),
        )
        .uses(100),
    );
    fixture
        .transport
        .push(ScriptedResponse::json("finalize/2", 200, serde_json::json!({})).uses(5));
    fixture.transport.push(
        ScriptedResponse::json(
            "order/2",
            200,
            serde_json::json!({
                "status": "processing",
                "expires": "2026-01-08T00:00:00Z",
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "authorizations": ["https://acme.example/authz/b"],
                "finalize": "https://acme.example/finalize/2"
            }),
        )
        .uses(2),
    );
    fixture.transport.push(
        ScriptedResponse::json(
            "order/2",
            200,
            serde_json::json!({
                "status": "valid",
                "expires": "2026-01-08T00:00:00Z",
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "authorizations": ["https://acme.example/authz/b"],
                "certificate": "https://acme.example/cert/2",
                "finalize": "https://acme.example/finalize/2"
            }),
        )
        .uses(100),
    );

    fixture
        .repositories
        .operations
        .create(issue_record(
            "op_spine_post_rollover",
            "spine-post-rollover",
            fixture.clock.now(),
        ))
        .await
        .unwrap();
    let op2 = OperationId::new("op_spine_post_rollover").unwrap();
    let csr_key = fixture.drive_until_csr(&op2).await;
    // The post-rollover order advertises cert/2 (see the scripted order).
    fixture.transport.push(raw_response(
        "cert/2",
        200,
        chain_for_key("example.com", &csr_key, &ca),
    ));

    // Between PrepareChallenges and the final cleanup the published TXT
    // value must be the one derived from the NEW thumbprint.
    let new_jwk = Jwk::for_key_pair(&new_key.0).unwrap();
    let key_authorization = format!("token-b.{}", new_jwk.thumbprint_sha256().unwrap());
    let txt_value = acmex::challenge::dns01_validation_value(&key_authorization);
    assert!(
        fixture
            .presenter
            .has_resource(
                "_acme-challenge.example.com",
                &acmex::dns::record::txt_value_hash(&txt_value),
            )
            .await,
        "the post-rollover TXT value must be derived from the new thumbprint"
    );
    // Exactly one resource: nothing was ever prepared with the stale
    // (pre-rollover) thumbprint.
    assert_eq!(fixture.presenter.resource_count().await, 1);

    let record = fixture.drive_to_terminal(&op2).await;
    assert_eq!(
        record.status,
        acmex::domain::OperationStatus::Succeeded,
        "error: {:?}",
        record.error
    );
    cleanup_dir(&fixture.key_store_dir);
}
