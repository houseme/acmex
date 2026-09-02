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
use acmex::ca_backend::{AcmeCaBackend, FakeAcmeTransport, ScriptedResponse};
use acmex::challenge::{MemoryPresenter, MemoryPresenterBehavior};
use acmex::domain::{
    CertificateIntent, CertificateLineage, CertificateVersion, DeliveryTarget, DeliveryTargetKind,
    IdentifierSet, IntentId, KeyAlgorithm, KeyId, KeyRef, LineageId, OperationId, OperationKind,
    OperationRecord, OperationSubject, VersionId, VersionState,
};
use acmex::key::SoftwareKeyProvider;
use acmex::protocol::Jwk;
use acmex::repository::{Clock, FakeClock, FileSecretStore, MemoryRepository, RepositorySet};
use acmex::server::worker::{WorkflowWorkerSettings, register_executors};
use acmex::workflow::WorkflowEngine;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
                        "type": "dns-01",
                        "url": format!("{url}/challenge"),
                        "token": token,
                        "status": status
                    }]
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
}

#[derive(Default)]
struct FixtureVerification {
    trust_anchor_pems: Vec<String>,
    skip_certificate_trust_check: bool,
}

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
    static FIXTURE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
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
    let account_jwk = Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(account_key.public_key_bytes()));
    let backend: Arc<dyn acmex::ca_backend::CaBackend> =
        Arc::new(AcmeCaBackend::with_fake_transport(
            "test-ca",
            "https://acme.example/directory",
            ca.transport.clone(),
            account_key,
            repositories.clone(),
        ));

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
        presenter,
        key_store_dir,
        transport: ca.transport,
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
            assert!(guard < 2000, "operation never produced a CSR");
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
