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
//!   → DNS-01 / HTTP-01 / TLS-ALPN-01 via challtestsrv admin API
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
    CertificateIntent, ChallengeLease, ChallengeLeaseLocator, ChallengeLeaseState, ChallengeSet,
    DeliveryTarget, DeliveryTargetKind, DeploymentId, DeploymentState, IdentifierSet, IntentId,
    LineageId, OperationId, OperationKind, OperationRecord, OperationStatus, OperationSubject,
    TenantId, ValidationPolicy, VersionId, WorkflowStepKind,
};
use acmex::key::SoftwareKeyProvider;
use acmex::protocol::Jwk;
use acmex::repository::{FileSecretStore, MemoryRepository};
use acmex::server::worker::{WorkflowWorkerComponents, WorkflowWorkerSettings, register_executors};
use acmex::types::ChallengeType;
use acmex::workflow::WorkflowEngine;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

struct PebbleEnv {
    directory_url: String,
    challtestsrv_admin: String,
    challtestsrv_dns: String,
    domain: String,
    trust_anchor_pem_file: Option<String>,
}

impl PebbleEnv {
    fn load() -> Self {
        Self {
            directory_url: env_or("PEBBLE_DIRECTORY_URL", "https://127.0.0.1:14000/dir"),
            challtestsrv_admin: env_or("PEBBLE_CHALLTESTSRV_ADMIN", "http://127.0.0.1:8055"),
            challtestsrv_dns: env_or("PEBBLE_CHALLTESTSRV_DNS", "127.0.0.1:8053"),
            domain: env_or("PEBBLE_E2E_DOMAIN", "acmex-test.example.com"),
            trust_anchor_pem_file: std::env::var("PEBBLE_TRUST_ANCHOR_PEM_FILE").ok(),
        }
    }
}

fn chall_host(name: impl AsRef<str>) -> String {
    let name = name.as_ref();
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

fn read_trust_anchor_pem(path: &str) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(pem) => Some(pem),
        Err(err) => {
            eprintln!(
                "SKIP: PEBBLE_TRUST_ANCHOR_PEM_FILE `{path}` could not be read ({err}). \
                 A skipped Pebble run is not a release pass."
            );
            None
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
struct ChalltestsrvAdmin {
    admin: String,
}

impl ChalltestsrvAdmin {
    fn new(admin: String) -> Self {
        Self { admin }
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> acmex::error::Result<()> {
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

    async fn get_text(&self, path: &str) -> acmex::error::Result<String> {
        let response = reqwest::Client::new()
            .get(format!("{}{path}", self.admin))
            .send()
            .await
            .map_err(|e| acmex::error::AcmeError::transport(format!("challtestsrv: {e}")))?;
        Ok(response.text().await.unwrap_or_default())
    }
}

#[derive(Clone)]
struct ChalltestsrvDnsPresenter {
    admin: ChalltestsrvAdmin,
    /// record name + value hash → TXT value. This is an optimization for the
    /// single-process E2E path; observe still falls back to the challtestsrv
    /// dump so rebuilt presenters can verify by the persisted hash alone.
    txt_values: Arc<tokio::sync::Mutex<HashMap<(String, String), String>>>,
}

impl ChalltestsrvDnsPresenter {
    fn new(admin: String) -> Self {
        Self {
            admin: ChalltestsrvAdmin::new(admin),
            txt_values: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ChallengePresenter for ChalltestsrvDnsPresenter {
    fn kind(&self) -> ChallengeType {
        ChallengeType::Dns01
    }

    async fn prepare(&self, request: PrepareChallenge) -> acmex::error::Result<ChallengeLease> {
        use sha2::{Digest, Sha256};
        let record_name = chall_host(format!("_acme-challenge.{}", request.session.identifier));
        let txt_value = dns01_validation_value(&request.key_authorization);
        self.admin
            .post(
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
            challenge_type: ChallengeType::Dns01,
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
        let body = self.admin.get_text("/dump-dns").await?;
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
                self.admin
                    .post("/clear-txt", serde_json::json!({ "host": record_name }))
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

#[derive(Clone)]
struct ChalltestsrvHttpPresenter {
    admin: ChalltestsrvAdmin,
}

impl ChalltestsrvHttpPresenter {
    fn new(admin: String) -> Self {
        Self {
            admin: ChalltestsrvAdmin::new(admin),
        }
    }
}

#[async_trait]
impl ChallengePresenter for ChalltestsrvHttpPresenter {
    fn kind(&self) -> ChallengeType {
        ChallengeType::Http01
    }

    async fn prepare(&self, request: PrepareChallenge) -> acmex::error::Result<ChallengeLease> {
        if request.session.identifier.is_wildcard() {
            return Err(acmex::error::AcmeError::invalid_input(
                "HTTP-01 cannot validate wildcard DNS identifiers",
            ));
        }
        let token = request
            .key_authorization
            .split('.')
            .next()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                acmex::error::AcmeError::invalid_input("key authorization is missing token")
            })?
            .to_string();
        self.admin
            .post(
                "/add-http01",
                serde_json::json!({
                    "token": token,
                    "content": request.key_authorization,
                }),
            )
            .await?;

        let now = Timestamp::now();
        Ok(ChallengeLease {
            id: acmex::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id.clone(),
            identifier: request.session.identifier.clone(),
            challenge_type: ChallengeType::Http01,
            locator: ChallengeLeaseLocator::Http {
                agent_id: "challtestsrv".to_string(),
                route_id: request.session.id,
                token_hash: acmex::challenge::ChallengeSession::hash_token(&token),
                endpoint: format!(
                    "http://{}/.well-known/acme-challenge/{token}",
                    request.session.identifier
                ),
            },
            created_at: now,
            expires_at: now.checked_add(jiff::Span::new().hours(1)).unwrap_or(now),
            state: ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, _lease: &ChallengeLease) -> acmex::error::Result<Observation> {
        Ok(Observation::Propagated)
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> acmex::error::Result<CleanupOutcome> {
        let ChallengeLeaseLocator::Http { endpoint, .. } = &lease.locator else {
            return Ok(CleanupOutcome::AlreadyAbsent);
        };
        let token = endpoint.rsplit('/').next().unwrap_or_default();
        self.admin
            .post("/del-http01", serde_json::json!({ "token": token }))
            .await?;
        Ok(CleanupOutcome::Cleaned)
    }
}

#[derive(Clone)]
struct ChalltestsrvTlsAlpnPresenter {
    admin: ChalltestsrvAdmin,
}

impl ChalltestsrvTlsAlpnPresenter {
    fn new(admin: String) -> Self {
        Self {
            admin: ChalltestsrvAdmin::new(admin),
        }
    }
}

#[async_trait]
impl ChallengePresenter for ChalltestsrvTlsAlpnPresenter {
    fn kind(&self) -> ChallengeType {
        ChallengeType::TlsAlpn01
    }

    async fn prepare(&self, request: PrepareChallenge) -> acmex::error::Result<ChallengeLease> {
        if request.session.identifier.is_wildcard() {
            return Err(acmex::error::AcmeError::invalid_input(
                "TLS-ALPN-01 cannot validate wildcard DNS identifiers",
            ));
        }
        let host = chall_host(request.session.identifier.acme_value());
        self.admin
            .post(
                "/add-tlsalpn01",
                serde_json::json!({
                    "host": host,
                    "content": request.key_authorization,
                }),
            )
            .await?;

        let now = Timestamp::now();
        Ok(ChallengeLease {
            id: acmex::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id.clone(),
            identifier: request.session.identifier.clone(),
            challenge_type: ChallengeType::TlsAlpn01,
            locator: ChallengeLeaseLocator::Tls {
                agent_id: "challtestsrv".to_string(),
                route_id: request.session.id,
                sni: host,
                fingerprint: acmex::dns::record::txt_value_hash(&request.key_authorization),
            },
            created_at: now,
            expires_at: now.checked_add(jiff::Span::new().hours(1)).unwrap_or(now),
            state: ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, _lease: &ChallengeLease) -> acmex::error::Result<Observation> {
        Ok(Observation::Propagated)
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> acmex::error::Result<CleanupOutcome> {
        let ChallengeLeaseLocator::Tls { sni, .. } = &lease.locator else {
            return Ok(CleanupOutcome::AlreadyAbsent);
        };
        self.admin
            .post("/del-tlsalpn01", serde_json::json!({ "host": sni }))
            .await?;
        Ok(CleanupOutcome::Cleaned)
    }
}

// ---------------------------------------------------------------------------
// the test
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PebbleRunMode {
    Basic,
    Lifecycle,
    Restart,
    Rollback,
}

fn pebble_presenters(admin: &str) -> PresenterRegistry {
    let mut presenters = PresenterRegistry::new();
    presenters.register(Arc::new(ChalltestsrvDnsPresenter::new(admin.to_string())));
    presenters.register(Arc::new(ChalltestsrvHttpPresenter::new(admin.to_string())));
    presenters.register(Arc::new(ChalltestsrvTlsAlpnPresenter::new(
        admin.to_string(),
    )));
    presenters
}

async fn run_pebble_issue(
    challenge_type: ChallengeType,
    suffix: &str,
    mode: PebbleRunMode,
) -> VersionId {
    if std::env::var("RUN_PEBBLE_E2E").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: RUN_PEBBLE_E2E=1 not set — see scripts/run_pebble_e2e.sh; \
             a skipped run is not a release pass"
        );
        return VersionId::new("ver_skipped").unwrap();
    }
    let env = PebbleEnv::load();
    let trust_anchor_pem = match env.trust_anchor_pem_file.as_deref() {
        Some(path) => match read_trust_anchor_pem(path) {
            Some(pem) => pem,
            None => return VersionId::new("ver_skipped").unwrap(),
        },
        None => {
            eprintln!(
                "SKIP: PEBBLE_TRUST_ANCHOR_PEM_FILE is required for strict certificate \
                 trust verification. A skipped Pebble run is not a release pass."
            );
            return VersionId::new("ver_skipped").unwrap();
        }
    };
    println!(
        "🎯 Pebble E2E {challenge_type} against {} ({})",
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
    let lineage_id = LineageId::new(format!("lin_pebble_{suffix}")).unwrap();
    let deploy_root = std::env::temp_dir().join(format!(
        "acmex-pebble-deploy-{}-{suffix}",
        std::process::id()
    ));
    let intent = CertificateIntent {
        id: IntentId::new(format!("int_pebble_{suffix}")).unwrap(),
        tenant_id: TenantId::default_tenant(),
        identifiers: identifiers.clone(),
        ca_policy: Default::default(),
        validation_policy: ValidationPolicy {
            allowed_challenges: ChallengeSet::new([challenge_type]),
            ..Default::default()
        },
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets: vec![
            DeliveryTarget::new(
                "file",
                DeliveryTargetKind::File,
                deploy_root.to_string_lossy().as_ref(),
            )
            .unwrap(),
        ],
        idempotency_key: format!("pebble-e2e-intent-{suffix}"),
        generation: 1,
    };
    repositories.intents.create(intent.clone()).await.unwrap();
    repositories
        .lineages
        .create(acmex::domain::CertificateLineage::new(
            lineage_id.clone(),
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

    let key_provider: Arc<dyn acmex::key::KeyProvider> = Arc::new(SoftwareKeyProvider::new(
        FileSecretStore::new(key_dir.clone()),
    ));
    let orchestrator = acmex::delivery::DeploymentOrchestrator::new(repositories.clone())
        .register_sink(
            acmex::domain::DeliveryTargetKind::File,
            Arc::new(acmex::delivery::FileCertificateSink::new()),
        );

    let build_engine = || {
        let mut engine = WorkflowEngine::new("pebble-e2e", repositories.clone());
        register_executors(
            &mut engine,
            &WorkflowWorkerSettings {
                propagation_timeout: Duration::from_secs(120),
                challenge_poll_interval: Duration::from_secs(2),
                trust_anchor_pems: vec![trust_anchor_pem.clone()],
                terms_agreed: true,
                ..Default::default()
            },
            WorkflowWorkerComponents {
                backend: backend.clone(),
                account_jwk: account_jwk.clone(),
                presenters: pebble_presenters(&env.challtestsrv_admin),
                key_provider: key_provider.clone(),
                orchestrator: orchestrator.clone(),
            },
        );
        engine
    };
    let mut engine = build_engine();

    // Submit + drive to terminal (real wall-clock: Pebble polls + Retry-After).
    let op_id = OperationId::new(format!("op_pebble_e2e_{suffix}")).unwrap();
    repositories
        .operations
        .create(OperationRecord::new(
            op_id.clone(),
            OperationKind::Issue,
            OperationSubject {
                intent_id: Some(intent.id.clone()),
                lineage_id: Some(lineage_id.clone()),
                version_id: None,
            },
            Some(format!("pebble-e2e-{suffix}")),
            None,
            Timestamp::now(),
        ))
        .await
        .unwrap();

    if mode == PebbleRunMode::Restart {
        for expected_step in [
            WorkflowStepKind::Plan,
            WorkflowStepKind::EnsureAccount,
            WorkflowStepKind::CreateOrResumeOrder,
        ] {
            assert!(engine.run_step(&op_id).await.unwrap());
            let stored = repositories
                .operations
                .get(&op_id)
                .await
                .unwrap()
                .unwrap()
                .value;
            assert!(
                stored.steps.iter().any(|step| step.kind == expected_step
                    && step.status == acmex::domain::StepStatus::Completed),
                "restart window did not complete {}: {:#?}",
                expected_step.as_str(),
                stored.steps
            );
            drop(engine);
            engine = build_engine();
        }
    }

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

    // The certificate was persisted, then the required File sink deploy
    // operation must pass before activation.
    let version_id = VersionId::new(format!("ver_{op_id}")).unwrap();
    let version = repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("version {version_id} not persisted"))
        .value;
    assert_eq!(version.state, acmex::domain::VersionState::Issued);
    assert!(version.certificate_chain_pem.contains("BEGIN CERTIFICATE"));
    assert!(!version.serial.is_empty());

    let deploy_op = OperationId::new(format!("op_deploy_{version_id}_file")).unwrap();
    if mode == PebbleRunMode::Rollback {
        assert!(engine.run_step(&deploy_op).await.unwrap());
        assert!(engine.run_step(&deploy_op).await.unwrap());
        let deployment_id = DeploymentId::new(format!("dep_{version_id}_file")).unwrap();
        let deployment = repositories
            .deployments
            .get(&deployment_id)
            .await
            .unwrap()
            .unwrap()
            .value;
        assert_eq!(deployment.state, DeploymentState::Active);
        let staged_ref = deployment.staged_ref.expect("deployment staged ref");
        let metadata = std::path::Path::new(&staged_ref).join("metadata.json");
        let mut payload: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&metadata).await.unwrap()).unwrap();
        payload["leaf_sha256"] = serde_json::json!("corrupted-by-pebble-rollback-test");
        tokio::fs::write(&metadata, serde_json::to_vec_pretty(&payload).unwrap())
            .await
            .unwrap();

        let failed_deploy = engine
            .run_until_terminal(&deploy_op, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(
            failed_deploy.status,
            OperationStatus::Failed,
            "rollback deploy steps: {:#?}",
            failed_deploy.steps
        );
        let rolled_back = repositories
            .deployments
            .get(&deployment_id)
            .await
            .unwrap()
            .unwrap()
            .value;
        assert_eq!(rolled_back.state, DeploymentState::RolledBack);
        assert!(
            !deploy_root.join("current").exists(),
            "rollback without a previous active ref must remove current pointer"
        );
        let _ = std::fs::remove_dir_all(&key_dir);
        let _ = std::fs::remove_dir_all(&deploy_root);
        return version_id;
    }

    let deploy_record = engine
        .run_until_terminal(&deploy_op, Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(
        deploy_record.status,
        acmex::domain::OperationStatus::Succeeded,
        "deploy steps: {:#?}",
        deploy_record.steps
    );

    let version = repositories
        .versions
        .get(&version_id)
        .await
        .unwrap()
        .unwrap()
        .value;
    assert_eq!(version.state, acmex::domain::VersionState::Active);
    let lineage = repositories
        .lineages
        .get(&lineage_id)
        .await
        .unwrap()
        .unwrap()
        .value;
    assert_eq!(lineage.active_version_id.as_ref(), Some(&version_id));

    if mode == PebbleRunMode::Lifecycle {
        let renew_op = OperationId::new(format!("op_pebble_renew_{suffix}")).unwrap();
        repositories
            .operations
            .create(OperationRecord::new(
                renew_op.clone(),
                OperationKind::Renew,
                OperationSubject {
                    intent_id: Some(intent.id.clone()),
                    lineage_id: Some(lineage_id.clone()),
                    version_id: None,
                },
                Some(format!("pebble-renew-{suffix}")),
                None,
                Timestamp::now(),
            ))
            .await
            .unwrap();

        let renewed_record = engine
            .run_until_terminal(&renew_op, Duration::from_secs(300))
            .await
            .unwrap();
        assert_eq!(
            renewed_record.status,
            acmex::domain::OperationStatus::Succeeded,
            "renew steps: {:#?}",
            renewed_record.steps
        );
        let renewed_version_id = VersionId::new(format!("ver_{renew_op}")).unwrap();
        let renewed = repositories
            .versions
            .get(&renewed_version_id)
            .await
            .unwrap()
            .unwrap()
            .value;
        assert_eq!(renewed.replaces.as_ref(), Some(&version_id));
        assert_eq!(renewed.state, acmex::domain::VersionState::Issued);

        let renew_deploy_op =
            OperationId::new(format!("op_deploy_{renewed_version_id}_file")).unwrap();
        let renew_deploy_record = engine
            .run_until_terminal(&renew_deploy_op, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(
            renew_deploy_record.status,
            acmex::domain::OperationStatus::Succeeded,
            "renew deploy steps: {:#?}",
            renew_deploy_record.steps
        );

        let old = repositories
            .versions
            .get(&version_id)
            .await
            .unwrap()
            .unwrap()
            .value;
        assert_eq!(old.state, acmex::domain::VersionState::Superseded);
        assert_eq!(old.superseded_by.as_ref(), Some(&renewed_version_id));
        let active_lineage = repositories
            .lineages
            .get(&lineage_id)
            .await
            .unwrap()
            .unwrap()
            .value;
        assert_eq!(
            active_lineage.active_version_id.as_ref(),
            Some(&renewed_version_id)
        );

        let revoke_op = OperationId::new(format!("op_pebble_revoke_{suffix}")).unwrap();
        repositories
            .operations
            .create(OperationRecord::new(
                revoke_op.clone(),
                OperationKind::Revoke,
                OperationSubject {
                    intent_id: Some(intent.id.clone()),
                    lineage_id: Some(lineage_id.clone()),
                    version_id: Some(renewed_version_id.clone()),
                },
                Some(format!("pebble-revoke-{suffix}")),
                None,
                Timestamp::now(),
            ))
            .await
            .unwrap();

        let revoke_record = engine
            .run_until_terminal(&revoke_op, Duration::from_secs(180))
            .await
            .unwrap();
        assert_eq!(
            revoke_record.status,
            acmex::domain::OperationStatus::Succeeded,
            "revoke steps: {:#?}",
            revoke_record.steps
        );
        let revoked = repositories
            .versions
            .get(&renewed_version_id)
            .await
            .unwrap()
            .unwrap()
            .value;
        assert_eq!(revoked.state, acmex::domain::VersionState::Revoked);
    }

    let _ = std::fs::remove_dir_all(&key_dir);
    let _ = std::fs::remove_dir_all(&deploy_root);
    println!(
        "✅ Pebble E2E {challenge_type} succeeded: version {} active",
        version.id
    );
    version_id
}

/// Full issuance against a real Pebble with DNS-01 via challtestsrv.
#[tokio::test]
#[ignore = "requires a running pebble + challtestsrv pair (scripts/run_pebble_e2e.sh)"]
async fn pebble_full_issuance_dns01() {
    let _ = run_pebble_issue(ChallengeType::Dns01, "dns01", PebbleRunMode::Basic).await;
}

/// Full issuance against a real Pebble with HTTP-01 via challtestsrv.
#[tokio::test]
#[ignore = "requires a running pebble + challtestsrv pair (scripts/run_pebble_e2e.sh)"]
async fn pebble_full_issuance_http01() {
    let _ = run_pebble_issue(ChallengeType::Http01, "http01", PebbleRunMode::Basic).await;
}

/// Full issuance against a real Pebble with TLS-ALPN-01 via challtestsrv.
#[tokio::test]
#[ignore = "requires a running pebble + challtestsrv pair (scripts/run_pebble_e2e.sh)"]
async fn pebble_full_issuance_tls_alpn01() {
    let _ = run_pebble_issue(ChallengeType::TlsAlpn01, "tlsalpn01", PebbleRunMode::Basic).await;
}

/// Full DNS-01 lifecycle against Pebble: initial issue, File sink activation,
/// renewal replacement, File sink activation, and real CA revocation.
#[tokio::test]
#[ignore = "requires a running pebble + challtestsrv pair (scripts/run_pebble_e2e.sh)"]
async fn pebble_dns01_renewal_and_revocation() {
    let _ = run_pebble_issue(
        ChallengeType::Dns01,
        "dns01_lifecycle",
        PebbleRunMode::Lifecycle,
    )
    .await;
}

/// Real executor restart evidence: rebuild the engine after three early
/// step boundaries, then finish the same durable operation against Pebble.
#[tokio::test]
#[ignore = "requires a running pebble + challtestsrv pair (scripts/run_pebble_e2e.sh)"]
async fn pebble_dns01_restart_windows_resume_real_executors() {
    let _ = run_pebble_issue(
        ChallengeType::Dns01,
        "dns01_restart",
        PebbleRunMode::Restart,
    )
    .await;
}

/// Real File sink failure evidence: corrupt staged metadata after activation,
/// require health failure, and assert rollback removes the active pointer.
#[tokio::test]
#[ignore = "requires a running pebble + challtestsrv pair (scripts/run_pebble_e2e.sh)"]
async fn pebble_dns01_file_sink_health_failure_rolls_back() {
    let _ = run_pebble_issue(
        ChallengeType::Dns01,
        "dns01_rollback",
        PebbleRunMode::Rollback,
    )
    .await;
}
