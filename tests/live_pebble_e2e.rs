//! REAL Pebble E2E (roadmap T12) — the gate `scripts/run_pebble_e2e.sh` runs.
//!
//! Everything is real except the transport's TLS verification (Pebble's
//! cert is deliberately invalid) and the DNS presenter, which programs
//! Pebble's bundled `challtestsrv` (the same way the reference boulder/
//! pebble integrations do):
//!
//! ```text
//! intent → issue operation → WorkflowEngine (register_executors)
//!   → AcmeCaBackend over real HTTPS (insecure verify, Pebble)
//!   → DNS-01 TXT via challtestsrv admin API (set-txt / clear-txt)
//!   → CSR by SoftwareKeyProvider (file secret store)
//!   → finalize/download on Pebble
//!   → strict verification (SAN/validity/chain/CSR-key)
//!   → persisted version + activation
//! ```
//!
//! Gated behind `#[ignore]`: requires `RUN_PEBBLE_E2E=1` plus a running
//! pebble + challtestsrv pair (see `scripts/docker-compose.pebble.yml`).
//! Without the environment the test prints the skip reason and returns —
//! a skipped run is not a release pass.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;

use acmex::account::KeyPair;
use acmex::ca_backend::{
    AcmeCaBackend, AcmeMethod, AcmeRequest, AcmeResponse, AcmeTransport, CaBackend,
};
use acmex::challenge::{
    ChallengePresenter, CleanupOutcome, Observation, PrepareChallenge, PresenterRegistry,
    dns01_validation_value,
};
use acmex::domain::{
    CertificateIntent, ChallengeLease, ChallengeLeaseLocator, ChallengeLeaseState, IdentifierSet,
    IntentId, LineageId, OperationId, OperationKind, OperationRecord, OperationSubject, TenantId,
};
use acmex::key::SoftwareKeyProvider;
use acmex::protocol::Jwk;
use acmex::repository::{FileSecretStore, MemoryRepository};
use acmex::server::worker::{WorkflowWorkerComponents, WorkflowWorkerSettings, register_executors};
use acmex::workflow::WorkflowEngine;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

struct PebbleEnv {
    directory_url: String,
    challtestsrv_admin: String,
    challtestsrv_dns: String,
    domain: String,
}

impl PebbleEnv {
    fn load() -> Self {
        Self {
            directory_url: env_or("PEBBLE_DIRECTORY_URL", "https://127.0.0.1:14000/dir"),
            challtestsrv_admin: env_or("PEBBLE_CHALLTESTSRV_ADMIN", "http://127.0.0.1:8055"),
            challtestsrv_dns: env_or("PEBBLE_CHALLTESTSRV_DNS", "127.0.0.1:8053"),
            domain: env_or("PEBBLE_E2E_DOMAIN", "acmex-test.example.com"),
        }
    }
}

// ---------------------------------------------------------------------------
// transport: real HTTPS, TLS verification disabled (Pebble's cert is invalid
// by design — every client testing against Pebble opts out of verification)
// ---------------------------------------------------------------------------

struct InsecurePebbleTransport {
    client: reqwest::Client,
}

impl InsecurePebbleTransport {
    fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .timeout(Duration::from_secs(30))
                .build()
                .expect("insecure test client"),
        }
    }
}

#[async_trait]
impl AcmeTransport for InsecurePebbleTransport {
    async fn request(&self, request: AcmeRequest) -> acmex::error::Result<AcmeResponse> {
        let url = reqwest::Url::parse(&request.url)
            .map_err(|e| acmex::error::AcmeError::invalid_input(format!("bad URL: {e}")))?;
        let builder = match request.method {
            AcmeMethod::Get => self.client.get(url),
            AcmeMethod::Head => self.client.head(url),
            AcmeMethod::Post => self
                .client
                .post(url)
                .header("Content-Type", "application/jose+json"),
        };
        let builder = match &request.body {
            Some(body) => builder.body(body.clone()),
            None => builder,
        };
        let response = builder
            .send()
            .await
            .map_err(|e| acmex::error::AcmeError::transport(format!("pebble request: {e}")))?;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let replay_nonce = header("Replay-Nonce");
        let location = header("Location");
        let retry_after = header("Retry-After")
            .and_then(|v| acmex::ca_backend::parse_retry_after(&v, Timestamp::now()));
        let body = response
            .bytes()
            .await
            .map_err(|e| acmex::error::AcmeError::transport(format!("pebble body: {e}")))?
            .to_vec();
        Ok(AcmeResponse {
            status,
            body,
            replay_nonce,
            retry_after,
            location,
        })
    }
}

// ---------------------------------------------------------------------------
// presenter: DNS-01 via the challtestsrv admin API — set-txt publishes both
// the admin record and the DNS TXT the Pebble VA resolves.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ChalltestsrvPresenter {
    admin: String,
    /// record name + value hash → TXT value. This is an optimization for the
    /// single-process E2E path; observe still falls back to the challtestsrv
    /// dump so rebuilt presenters can verify by the persisted hash alone.
    txt_values: Arc<tokio::sync::Mutex<HashMap<(String, String), String>>>,
}

impl ChalltestsrvPresenter {
    fn new(admin: String) -> Self {
        Self {
            admin,
            txt_values: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    async fn admin_post(&self, path: &str, body: serde_json::Value) -> acmex::error::Result<()> {
        let response = reqwest::Client::new()
            .post(format!("{}{path}", self.admin))
            .json(&body)
            .send()
            .await
            .map_err(|e| acmex::error::AcmeError::transport(format!("challtestsrv: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(acmex::error::AcmeError::transport(format!(
                "challtestsrv {path} failed: {status} {text}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl ChallengePresenter for ChalltestsrvPresenter {
    fn kind(&self) -> acmex::types::ChallengeType {
        acmex::types::ChallengeType::Dns01
    }

    async fn prepare(&self, request: PrepareChallenge) -> acmex::error::Result<ChallengeLease> {
        use sha2::{Digest, Sha256};
        let record_name = format!("_acme-challenge.{}", request.session.identifier);
        let txt_value = dns01_validation_value(&request.key_authorization);
        self.admin_post(
            "/set-txt",
            serde_json::json!({
                "host": record_name,
                "value": txt_value,
            }),
        )
        .await?;

        let mut hasher = Sha256::new();
        hasher.update(txt_value.as_bytes());
        let value_hash = hex::encode(hasher.finalize());
        self.txt_values
            .lock()
            .await
            .insert((record_name.clone(), value_hash.clone()), txt_value);

        let now = Timestamp::now();
        Ok(ChallengeLease {
            id: acmex::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id.clone(),
            identifier: request.session.identifier.clone(),
            challenge_type: acmex::types::ChallengeType::Dns01,
            locator: ChallengeLeaseLocator::Dns {
                provider_id: "challtestsrv".to_string(),
                zone: request
                    .session
                    .identifier
                    .acme_value()
                    .split_once('.')
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or_else(|| request.session.identifier.acme_value()),
                record_name,
                record_id: None,
                value_hash,
            },
            created_at: now,
            expires_at: now
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap_or(now),
            state: ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, lease: &ChallengeLease) -> acmex::error::Result<Observation> {
        let (record_name, value_hash, cached_value) = match &lease.locator {
            ChallengeLeaseLocator::Dns {
                record_name,
                value_hash,
                ..
            } => {
                let cached = self
                    .txt_values
                    .lock()
                    .await
                    .get(&(record_name.clone(), value_hash.clone()))
                    .cloned();
                (record_name.clone(), value_hash.clone(), cached)
            }
            _ => {
                return Ok(Observation::NotYet {
                    retry_after: Duration::from_secs(1),
                });
            }
        };
        let dump = reqwest::Client::new()
            .get(format!("{}/dump-dns", self.admin))
            .send()
            .await
            .map_err(|e| acmex::error::AcmeError::transport(format!("dump-dns: {e}")))?;
        let body = dump.text().await.unwrap_or_default();
        let expected_visible = cached_value
            .as_deref()
            .is_some_and(|value| body.contains(record_name.as_str()) && body.contains(value));
        let expected_hash_visible = body
            .split(|ch: char| {
                ch == '"' || ch == '[' || ch == ']' || ch == ',' || ch.is_whitespace()
            })
            .any(|value| {
                !value.is_empty() && acmex::dns::record::txt_value_hash(value) == value_hash
            });
        if expected_visible || expected_hash_visible {
            Ok(Observation::Propagated)
        } else {
            Ok(Observation::NotYet {
                retry_after: Duration::from_secs(1),
            })
        }
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> acmex::error::Result<CleanupOutcome> {
        match &lease.locator {
            ChallengeLeaseLocator::Dns {
                record_name,
                value_hash,
                ..
            } => {
                self.admin_post("/clear-txt", serde_json::json!({ "host": record_name }))
                    .await?;
                self.txt_values
                    .lock()
                    .await
                    .remove(&(record_name.clone(), value_hash.clone()));
                Ok(CleanupOutcome::Cleaned)
            }
            _ => Ok(CleanupOutcome::AlreadyAbsent),
        }
    }
}

// ---------------------------------------------------------------------------
// the test
// ---------------------------------------------------------------------------

/// Full issuance against a real Pebble: intent → durable operation → DNS-01
/// via challtestsrv → CSR → finalize → download → strict verification →
/// persisted active version. `#[ignore]` + `RUN_PEBBLE_E2E=1` gating keeps
/// CI green without the environment while `scripts/run_pebble_e2e.sh` runs
/// it as the L4 release gate.
#[tokio::test]
#[ignore = "requires a running pebble + challtestsrv pair (scripts/run_pebble_e2e.sh)"]
async fn pebble_full_issuance_dns01() {
    if std::env::var("RUN_PEBBLE_E2E").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: RUN_PEBBLE_E2E=1 not set — see scripts/run_pebble_e2e.sh; \
             a skipped run is not a release pass"
        );
        return;
    }
    let env = PebbleEnv::load();
    println!(
        "🎯 Pebble E2E against {} ({})",
        env.directory_url, env.domain
    );

    // Readiness probe with an actionable message.
    match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(&env.directory_url)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => panic!(
            "Pebble answered HTTP {} — check the pebble config",
            response.status()
        ),
        Err(err) => panic!(
            "Pebble unreachable at {}: {err} — start it with \
             `docker compose -f scripts/docker-compose.pebble.yml up -d`",
            env.directory_url
        ),
    }
    let _ = env.challtestsrv_dns; // DNS is consumed by Pebble, not this test.

    // Durable state + intent/lineage fixtures.
    let repositories = MemoryRepository::new().into_set();
    let identifiers = IdentifierSet::parse([env.domain.as_str()]).unwrap();
    let intent = CertificateIntent {
        id: IntentId::new("int_pebble").unwrap(),
        tenant_id: TenantId::default_tenant(),
        identifiers: identifiers.clone(),
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets: Vec::new(),
        idempotency_key: "pebble-e2e-intent".to_string(),
        generation: 1,
    };
    repositories.intents.create(intent.clone()).await.unwrap();
    repositories
        .lineages
        .create(acmex::domain::CertificateLineage::new(
            LineageId::new("lin_pebble").unwrap(),
            TenantId::default_tenant(),
            intent.id.clone(),
            identifiers,
        ))
        .await
        .unwrap();

    // Production assembly over the insecure Pebble transport.
    let key_dir = std::env::temp_dir().join(format!(
        "acmex-pebble-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let account_key = Arc::new(KeyPair::generate().unwrap());
    let backend: Arc<dyn CaBackend> = Arc::new(AcmeCaBackend::new(
        "pebble",
        env.directory_url.clone(),
        Arc::new(InsecurePebbleTransport::new()),
        account_key.clone(),
        repositories.clone(),
    ));
    let account_jwk = Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(account_key.public_key_bytes()));

    let mut presenters = PresenterRegistry::new();
    presenters.register(Arc::new(ChalltestsrvPresenter::new(
        env.challtestsrv_admin.clone(),
    )));

    let key_provider: Arc<dyn acmex::key::KeyProvider> = Arc::new(SoftwareKeyProvider::new(
        FileSecretStore::new(key_dir.clone()),
    ));
    let orchestrator = acmex::delivery::DeploymentOrchestrator::new(repositories.clone())
        .register_sink(
            acmex::domain::DeliveryTargetKind::File,
            Arc::new(acmex::delivery::FileCertificateSink::new()),
        );

    let mut engine = WorkflowEngine::new("pebble-e2e", repositories.clone());
    register_executors(
        &mut engine,
        &WorkflowWorkerSettings {
            propagation_timeout: Duration::from_secs(120),
            challenge_poll_interval: Duration::from_secs(2),
            terms_agreed: true,
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

    // Submit + drive to terminal (real wall-clock: Pebble polls + Retry-After).
    let op_id = OperationId::new("op_pebble_e2e").unwrap();
    repositories
        .operations
        .create(OperationRecord::new(
            op_id.clone(),
            OperationKind::Issue,
            OperationSubject {
                intent_id: Some(intent.id.clone()),
                lineage_id: Some(LineageId::new("lin_pebble").unwrap()),
                version_id: None,
            },
            Some("pebble-e2e".to_string()),
            None,
            Timestamp::now(),
        ))
        .await
        .unwrap();

    let finished = engine
        .run_until_terminal(&op_id, Duration::from_secs(300))
        .await;
    if let Err(err) = &finished {
        let state = repositories
            .operations
            .get(&op_id)
            .await
            .ok()
            .flatten()
            .map(|s| {
                format!(
                    "status={:?} error={:?} steps={:?}",
                    s.value.status,
                    s.value.error,
                    s.value
                        .steps
                        .iter()
                        .map(|step| (
                            step.kind.as_str(),
                            step.status,
                            step.error.as_ref().and_then(|e| e.detail.clone())
                        ))
                        .collect::<Vec<_>>()
                )
            })
            .unwrap_or_else(|| "no record".to_string());
        panic!("operation did not finish: {err}; {state}");
    }
    let record = finished.unwrap();
    assert_eq!(
        record.status,
        acmex::domain::OperationStatus::Succeeded,
        "steps: {:#?}",
        record.steps
    );

    // The certificate was persisted and activated.
    let version_id = acmex::domain::VersionId::new(format!("ver_{op_id}")).unwrap();
    let version = repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("version {version_id} not persisted"))
        .value;
    assert_eq!(version.state, acmex::domain::VersionState::Active);
    assert!(version.certificate_chain_pem.contains("BEGIN CERTIFICATE"));
    assert!(!version.serial.is_empty());
    let lineage = repositories
        .lineages
        .get(&LineageId::new("lin_pebble").unwrap())
        .await
        .unwrap()
        .unwrap()
        .value;
    assert_eq!(lineage.active_version_id.as_ref(), Some(&version_id));

    let _ = std::fs::remove_dir_all(&key_dir);
    println!("✅ Pebble E2E succeeded: version {} active", version.id);
}
