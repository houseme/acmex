//! Intent-based certificate issuance on the durable workflow API (v0.9+).
//!
//! This is the modern counterpart to `basic_issuance.rs`: instead of the
//! legacy in-process `AcmeClient` session, it walks the exact path the
//! HTTP API and CLI take today:
//!
//! 1. submit a `CertificateIntent` through the application service
//!    (`ApplicationServiceBuilder`, in-memory repository);
//! 2. create an issue operation — the service derives the certificate
//!    lineage and persists a durable, restartable operation;
//! 3. assemble the production executor set in-process
//!    (`server::worker::register_executors`, the same assembly
//!    `acmex obtain --wait` and `acmex serve` use);
//! 4. drive the workflow engine step by step until the certificate is
//!    issued, verified, persisted and deployed to a file sink.
//!
//! Everything except the network is real: managed keys live in a file
//! secret store, the CSR/finalize/download flow uses the ACME backend,
//! the issued chain is a real CA-signed certificate and verification is
//! strict. Only the CA conversations are scripted with
//! [`acmex::ca_backend::FakeAcmeTransport`] (the same fixture the
//! integration tests use), so the example runs offline. A test CA issues
//! the leaf for the CSR's public key — exactly what a real CA does.
//!
//! Run it:
//!
//! ```text
//! cargo run --example intent_issuance
//! ```

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use acmex::account::KeyPair;
use acmex::application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, CreateCertificateIntent,
    IssueCertificate,
};
use acmex::ca_backend::{AcmeCaBackend, FakeAcmeTransport, ScriptedResponse};
use acmex::challenge::{MemoryPresenter, MemoryPresenterBehavior, PresenterRegistry};
use acmex::delivery::{DeploymentOrchestrator, FileCertificateSink};
use acmex::domain::{
    DeliveryTarget, DeliveryTargetKind, OperationId, OperationStatus, VersionId, WorkflowStepKind,
};
use acmex::key::SoftwareKeyProvider;
use acmex::protocol::Jwk;
use acmex::repository::{Clock, FakeClock, FileSecretStore, MemoryRepository};
use acmex::server::worker::{WorkflowWorkerComponents, WorkflowWorkerSettings, register_executors};
use acmex::workflow::{EngineConfig, WorkflowEngine};
use jiff::Timestamp;

const DOMAIN: &str = "example.com";
const DIRECTORY_URL: &str = "https://acme.example/directory";
/// Fixed wall clock: the scripted CA data is consistent with it.
const NOW: &str = "2026-01-01T00:00:00Z";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Output locations: managed keys and the delivered certificate land in
    // throwaway temp directories so the example is side-effect free.
    let run = format!(
        "acmex-intent-issuance-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let secret_store_dir = std::env::temp_dir().join(format!("{run}-secrets"));
    let deploy_dir = std::env::temp_dir().join(format!("{run}-deploy"));

    // ---------------------------------------------------------------------------
    // 1. The scripted fake CA: every ACME round trip is answered offline.
    // ---------------------------------------------------------------------------
    let clock = Arc::new(FakeClock::at(Timestamp::from_str(NOW)?));
    let transport = Arc::new(FakeAcmeTransport::new(clock.now()));
    script_ca_conversation(&transport);

    // ---------------------------------------------------------------------------
    // 2. Durable repositories + the application service boundary.
    // ---------------------------------------------------------------------------
    let repositories = MemoryRepository::with_clock(clock.clone()).into_set();
    let (service, repositories) = ApplicationServiceBuilder::new()
        .with_repositories(repositories)
        .build()?;

    // ---------------------------------------------------------------------------
    // 3. Submit the intent, then the issue operation (both idempotent).
    // ---------------------------------------------------------------------------
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec![DOMAIN.to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: Default::default(),
            renewal_policy: Default::default(),
            // Deliver the issued material through the durable file sink.
            delivery_targets: vec![DeliveryTarget::new(
                "web",
                DeliveryTargetKind::File,
                deploy_dir.to_string_lossy().as_ref(),
            )?],
            external_csr: None,
            idempotency_key: "intent-issuance-demo".to_string(),
        })
        .await?;
    let operation = service
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id.clone(),
            external_csr: None,
            idempotency_key: "intent-issuance-demo-issue".to_string(),
        })
        .await?;
    println!("intent            = {}", intent.id);
    println!("issue operation   = {}", operation.id);
    println!("lineage           = {:?}", operation.subject.lineage_id);

    // ---------------------------------------------------------------------------
    // 4. Assemble the production executor set (what `obtain --wait` runs).
    // ---------------------------------------------------------------------------
    // The demo CA that "issues" the leaf; its certificate is also the trust
    // anchor configured for strict verification below.
    let issuer = test_ca("acmex demo ca");
    // Managed certificate keys in a file secret store.
    let key_provider: Arc<dyn acmex::key::KeyProvider> = Arc::new(SoftwareKeyProvider::new(
        FileSecretStore::new(secret_store_dir.clone()),
    ));
    // An in-memory DNS-01 presenter stands in for a real DNS provider.
    let presenter = MemoryPresenter::dns01(MemoryPresenterBehavior::default());
    let mut presenters = PresenterRegistry::new();
    presenters.register(presenter.clone());
    // The ACME account key and the CA backend over the fake transport.
    let account_key = Arc::new(KeyPair::generate()?);
    let account_jwk =
        acmex::ca_backend::backend::AccountJwkHandle::new(Jwk::for_key_pair(&account_key.0)?);
    let acme_backend = AcmeCaBackend::with_fake_transport(
        "demo-ca",
        DIRECTORY_URL,
        transport.clone(),
        account_key,
        repositories.clone(),
    );
    // Key authorizations read the thumbprint through this handle; the
    // backend refreshes it when an account key rollover completes.
    acme_backend.attach_jwk_handle(account_jwk.clone());
    let backend: Arc<dyn acmex::ca_backend::CaBackend> = Arc::new(acme_backend);
    // The durable file sink for the intent's delivery target.
    let orchestrator = DeploymentOrchestrator::new(repositories.clone()).register_sink(
        DeliveryTargetKind::File,
        Arc::new(FileCertificateSink::new()),
    );

    let mut engine = WorkflowEngine::new("intent-issuance-example", repositories.clone())
        .with_config(EngineConfig {
            retry_backoff_base: Duration::from_millis(1),
            retry_backoff_max: Duration::from_millis(5),
            ..Default::default()
        });
    register_executors(
        &mut engine,
        &WorkflowWorkerSettings {
            challenge_poll_interval: Duration::from_millis(50),
            // Strict trust verification against our demo CA's anchor.
            trust_anchor_pems: vec![issuer.pem()],
            ..Default::default()
        },
        WorkflowWorkerComponents {
            backend,
            account_jwk,
            presenters,
            key_provider,
            orchestrator,
        },
    );

    // ---------------------------------------------------------------------------
    // 5. Drive the workflow: CSR → (CA issues) → finalize → verify → persist.
    // ---------------------------------------------------------------------------
    //
    // The chain can only be built once the CSR (and its managed key)
    // exists, so the run pauses at the CSR step — a real CA sees the CSR
    // at exactly the same point in the conversation.
    let csr_key = drive_until_csr(
        &engine,
        &repositories,
        &operation.id,
        &secret_store_dir,
        &clock,
    )
    .await?;
    println!("\nCA: issuing a leaf for the CSR's public key (chain: leaf + demo CA)");
    transport.push(raw_response(
        "cert/1",
        200,
        chain_for_key(DOMAIN, &csr_key, &issuer),
    ));

    let record = drive_to_terminal(&engine, &repositories, &operation.id, &clock).await?;
    if record.status != OperationStatus::Succeeded {
        return Err(format!(
            "issue operation ended in {}: {}",
            record.status.as_str(),
            record
                .error
                .as_ref()
                .and_then(|e| e.detail.clone())
                .unwrap_or_else(|| "no detail".to_string())
        )
        .into());
    }
    println!("issue operation   = {} (succeeded)", operation.id);

    // The issued version was persisted under a deterministic id.
    let version_id = VersionId::new(format!("ver_{}", operation.id))?;
    let version = repositories
        .versions
        .get(&version_id)
        .await?
        .ok_or("issued version was not persisted")?
        .value;
    println!(
        "version           = {} serial {} ({})",
        version.id,
        version.serial,
        version
            .verification_report
            .as_ref()
            .map(|r| format!("{:?}", r.conclusion))
            .unwrap_or_default()
    );

    // ---------------------------------------------------------------------------
    // 6. Drive the derived deploy operation: file sink + activation gate.
    // ---------------------------------------------------------------------------
    let deploy_op = OperationId::new(format!("op_deploy_{version_id}_web"))?;
    let deploy_record = drive_to_terminal(&engine, &repositories, &deploy_op, &clock).await?;
    if deploy_record.status != OperationStatus::Succeeded {
        return Err(format!(
            "deploy operation ended in {}: {}",
            deploy_record.status.as_str(),
            deploy_record
                .error
                .as_ref()
                .and_then(|e| e.detail.clone())
                .unwrap_or_else(|| "no detail".to_string())
        )
        .into());
    }

    let version = repositories.versions.get(&version_id).await?.unwrap().value;
    println!(
        "deployment        = file sink active, version state `{}`",
        version.state.as_str()
    );
    println!(
        "dns-01 resources left behind = {} (cleaned up)",
        presenter.resource_count().await
    );

    // ---------------------------------------------------------------------------
    // 7. Show what landed on disk.
    // ---------------------------------------------------------------------------
    println!("\nDelivered files under {}:", deploy_dir.display());
    print_tree(&deploy_dir, 1)?;
    println!(
        "\nManaged keys under {} (not printed):",
        secret_store_dir.display()
    );
    println!(
        "\nDone. The repositories were in-memory; a real deployment just\nswaps in `ApplicationServiceBuilder::from_config` + `spawn_from_config`."
    );

    let _ = repositories; // kept alive so the printed state stays readable
    Ok(())
}

/// Scripts the whole ACME conversation the workflow will hold with the CA:
/// directory discovery, nonces, account registration, order creation,
/// a pending dns-01 authorization that flips to valid, finalize and the
/// order polling that ends in a certificate URL. The certificate download
/// itself is scripted later, once the CSR key exists.
fn script_ca_conversation(transport: &FakeAcmeTransport) {
    let order_body = |status: &str, certificate: Option<&str>| {
        serde_json::json!({
            "status": status,
            "expires": "2026-01-08T00:00:00Z",
            "identifiers": [{"type": "dns", "value": DOMAIN}],
            "authorizations": ["https://acme.example/authz/a"],
            "finalize": "https://acme.example/finalize/1",
            "certificate": certificate,
        })
    };
    let authz_body = |status: &str| {
        serde_json::json!({
            "identifier": {"type": "dns", "value": DOMAIN},
            "status": status,
            "expires": "2026-01-08T00:00:00Z",
            "challenges": [{
                "type": "dns-01",
                "url": "https://acme.example/authz/a/challenge",
                "token": "demo-token",
                "status": status
            }]
        })
    };

    transport.push(
        ScriptedResponse::json(
            "directory",
            200,
            serde_json::json!({
                "newNonce": "https://acme.example/new-nonce",
                "newAccount": "https://acme.example/new-account",
                "newOrder": "https://acme.example/new-order",
                "revokeCert": "https://acme.example/revoke-cert",
                "keyChange": "https://acme.example/key-change",
                "renewalInfo": "https://acme.example/renewal-info"
            }),
        )
        .uses(100),
    );
    transport.push(
        ScriptedResponse::json("new-nonce", 200, serde_json::json!({}))
            .uses(1000)
            .with_headers(Some("n".to_string()), None, None),
    );
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("n".to_string()),
                None,
                Some("https://acme.example/acct/1".to_string()),
            ),
    );
    transport.push(
        ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
            .with_headers(
                Some("n".to_string()),
                None,
                Some("https://acme.example/order/1".to_string()),
            ),
    );
    // Order resource while authorizations are pending (fetched a couple of
    // times), then processing after finalize, then valid with the cert URL.
    transport.push(ScriptedResponse::json("order/1", 200, order_body("pending", None)).uses(2));
    transport.push(ScriptedResponse::json("authz/a", 200, authz_body("pending")).uses(2));
    transport.push(
        ScriptedResponse::json(
            "challenge",
            200,
            serde_json::json!({"status": "processing"}),
        )
        .uses(10),
    );
    // Authorizations flip to valid after acknowledgement.
    transport.push(ScriptedResponse::json("authz/a", 200, authz_body("valid")).uses(100));
    transport.push(ScriptedResponse::json("finalize/1", 200, serde_json::json!({})).uses(5));
    transport.push(ScriptedResponse::json("order/1", 200, order_body("processing", None)).uses(2));
    transport.push(
        ScriptedResponse::json(
            "order/1",
            200,
            order_body("valid", Some("https://acme.example/cert/1")),
        )
        .uses(100),
    );
}

/// Advances the engine until the CSR step has produced output, then loads
/// the managed CSR private key from the file secret store.
async fn drive_until_csr(
    engine: &WorkflowEngine,
    repositories: &acmex::repository::RepositorySet,
    operation: &OperationId,
    secret_store_dir: &std::path::Path,
    clock: &FakeClock,
) -> Result<rcgen::KeyPair, Box<dyn std::error::Error>> {
    let store = FileSecretStore::new(secret_store_dir.to_path_buf());
    for _ in 0..5000 {
        if let Some(stored) = repositories.operations.get(operation).await?
            && let Some(step) = stored
                .value
                .steps
                .iter()
                .find(|step| step.kind == WorkflowStepKind::CreateCsr)
            && let Some(output) = &step.output_ref
        {
            let payload: serde_json::Value = serde_json::from_str(output)?;
            let key_id = payload["key_ref"]["key_id"]
                .as_str()
                .ok_or("CSR payload is missing key_ref.key_id")?;
            let pem = store
                .get(key_id)
                .await?
                .ok_or_else(|| format!("managed CSR key `{key_id}` missing from the store"))?;
            return Ok(rcgen::KeyPair::from_pem(&String::from_utf8(pem)?)?);
        }
        if !engine.run_step(operation).await? {
            clock.advance_secs(1);
        }
    }
    Err("the workflow never produced a CSR".into())
}

/// Advances the engine until the operation reaches a terminal state.
async fn drive_to_terminal(
    engine: &WorkflowEngine,
    repositories: &acmex::repository::RepositorySet,
    operation: &OperationId,
    clock: &FakeClock,
) -> Result<acmex::domain::OperationRecord, Box<dyn std::error::Error>> {
    for _ in 0..5000 {
        if let Some(stored) = repositories.operations.get(operation).await?
            && stored.value.status.is_terminal()
        {
            return Ok(stored.value);
        }
        if !engine.run_step(operation).await? {
            clock.advance_secs(1);
        }
    }
    Err(format!("operation {operation} never reached a terminal state").into())
}

/// A raw (non-JSON) scripted response, used for the PEM certificate body.
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

/// A self-signed demo CA valid across the fixed clock's time.
fn test_ca(common_name: &str) -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2027, 1, 1);
    rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap()).unwrap()
}

/// A CA-signed leaf for `domain` whose subject public key is `leaf_key`'s
/// (exactly what a real CA issues for a CSR generated with that key),
/// plus the issuing CA — a consistent chain PEM.
fn chain_for_key(
    domain: &str,
    leaf_key: &rcgen::KeyPair,
    issuer: &rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
) -> String {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2027, 1, 1);
    format!(
        "{}{}",
        params.signed_by(leaf_key, issuer).unwrap().pem(),
        issuer.pem()
    )
}

/// Small recursive listing of the delivered files (depth-capped).
fn print_tree(root: &std::path::Path, depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries: Vec<_> = std::fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = std::fs::read_link(&path)
            .map(|link| format!("{name} -> {}", link.display()))
            .unwrap_or_else(|_| {
                if path.is_dir() {
                    format!("{name}/")
                } else {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    format!("{name} ({size} bytes)")
                }
            });
        println!("{}{target}", "  ".repeat(depth));
        if path.is_dir() {
            print_tree(&path, depth + 1)?;
        }
    }
    Ok(())
}
