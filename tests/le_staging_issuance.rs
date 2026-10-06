//! Real Let's Encrypt staging issuance evidence (roadmap T19).
//!
//! This is deliberately a separate ignored integration-test binary.  It
//! never issues a certificate unless `RUN_LE_STAGING=1` *and* the selected
//! scenario has every caller-owned asset it needs.  Output artifacts are
//! public metadata only; account and certificate private keys live in a
//! process-private temporary directory and are never copied into the evidence
//! directory.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use acmex::account::KeyPair;
use acmex::ca_backend::backend::AccountJwkHandle;
use acmex::ca_backend::{AcmeCaBackend, CaBackend, ReqwestAcmeTransport};
use acmex::challenge::PresenterRegistry;
use acmex::challenge::http01_presenter::Http01Presenter;
use acmex::dns::factory::DefaultDnsProviderFactory;
use acmex::dns::presenter::Dns01Presenter;
use acmex::dns::propagation::{HickoryPropagationObserver, PropagationPolicyV2};
use acmex::dns::router::ProviderRouterBuilder;
use acmex::dns::spec::{DnsProviderSpec, EnvFileSecretResolver, SecretRef};
use acmex::dns::zone::HickoryZoneResolver;
use acmex::domain::{
    CaPolicy, CertificateIntent, CertificateLineage, CertificateVerificationReport, ChallengeSet,
    DeliveryTarget, DeliveryTargetKind, Identifier, IdentifierSet, IntentId, LineageId,
    OperationId, OperationKind, OperationRecord, OperationStatus, OperationSubject, TenantId,
    ValidationPolicy, VersionId, VersionState,
};
use acmex::key::SoftwareKeyProvider;
use acmex::protocol::Jwk;
use acmex::renewal::RenewalInfoProvider;
use acmex::repository::{FileSecretStore, MemoryRepository, RepositorySet};
use acmex::server::worker::{WorkflowWorkerComponents, WorkflowWorkerSettings, register_executors};
use acmex::types::ChallengeType;
use acmex::workflow::WorkflowEngine;
use jiff::Timestamp;
use sha2::{Digest, Sha256};

const DEFAULT_DIRECTORY_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ISSUANCE_SCENARIOS: &[&str] = &["http-01", "dns-01", "renewal", "profile"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Http01,
    Dns01,
    Renewal,
    Profile,
}

impl Scenario {
    const fn name(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
            Self::Renewal => "renewal",
            Self::Profile => "profile",
        }
    }
}

#[derive(Debug)]
struct LiveConfig {
    directory_url: String,
    email: String,
    domain: String,
    trust_anchor_pem: String,
    artifact_dir: PathBuf,
    http_listen: Option<SocketAddr>,
    dns: Option<DnsConfig>,
    profile: Option<String>,
}

#[derive(Debug, Clone)]
struct DnsConfig {
    provider_type: String,
    zone: String,
    extra: HashMap<String, String>,
}

fn parse_scenarios(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|scenario| !scenario.is_empty())
        .flat_map(|scenario| {
            if scenario == "all" {
                ISSUANCE_SCENARIOS.iter().copied().collect::<Vec<_>>()
            } else {
                vec![scenario]
            }
        })
        .map(str::to_string)
        .collect()
}

fn selected(scenario: Scenario) -> bool {
    let raw = std::env::var("ACMEX_LE_STAGING_SCENARIOS").unwrap_or_else(|_| "all".to_string());
    parse_scenarios(&raw).contains(scenario.name())
}

fn required_env(name: &'static str, missing: &mut Vec<&'static str>) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => {
            missing.push(name);
            None
        }
    }
}

fn configured_dns(missing: &mut Vec<&'static str>) -> Option<DnsConfig> {
    let provider_type = required_env("ACMEX_LIVE_DNS_TYPE", missing)?;
    let zone = required_env("ACMEX_LIVE_DNS_ZONE", missing)?;
    // The value stays in the process environment; provider assembly receives
    // only this SecretRef, never a literal token copied into a config record.
    required_env("ACMEX_LIVE_DNS_TOKEN", missing)?;
    let extra = std::env::var("ACMEX_LIVE_DNS_PROVIDER_EXTRA_JSON")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|raw| {
            serde_json::from_str(&raw).unwrap_or_else(|_| {
                panic!(
                    "ACMEX_LIVE_DNS_PROVIDER_EXTRA_JSON must be a JSON object of non-secret provider settings"
                )
            })
        })
        .unwrap_or_default();
    Some(DnsConfig {
        provider_type,
        zone,
        extra,
    })
}

fn load_config(scenario: Scenario, challenge: ChallengeType) -> Option<LiveConfig> {
    if std::env::var("RUN_LE_STAGING").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: RUN_LE_STAGING=1 is required for real LE staging issuance; a skipped run is not a release pass"
        );
        return None;
    }
    if !selected(scenario) {
        eprintln!(
            "SKIP: LE staging scenario `{}` was not selected",
            scenario.name()
        );
        return None;
    }

    let mut missing = Vec::new();
    let email = required_env("ACMEX_LE_STAGING_ACCOUNT_EMAIL", &mut missing);
    let domain = required_env("ACMEX_LE_STAGING_DOMAIN", &mut missing);
    let trust_anchor = required_env("ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE", &mut missing);
    let artifact_dir = required_env("ACMEX_LE_STAGING_ARTIFACT_DIR", &mut missing);
    let http_listen = if challenge == ChallengeType::Http01 {
        required_env("ACMEX_LE_STAGING_HTTP01_LISTEN", &mut missing).map(|listen| {
            listen.parse::<SocketAddr>().unwrap_or_else(|_| {
                panic!("ACMEX_LE_STAGING_HTTP01_LISTEN must be a socket address such as 0.0.0.0:80")
            })
        })
    } else {
        None
    };
    let dns = if challenge == ChallengeType::Dns01 {
        configured_dns(&mut missing)
    } else {
        None
    };
    let profile = if scenario == Scenario::Profile {
        required_env("ACMEX_LE_STAGING_PROFILE", &mut missing)
    } else {
        None
    };

    assert!(
        missing.is_empty(),
        "RUN_LE_STAGING=1 scenario `{}` needs caller-owned assets: missing {missing:?}; refusing to simulate issuance",
        scenario.name()
    );

    let trust_anchor_path = PathBuf::from(trust_anchor.expect("checked above"));
    let trust_anchor_pem = std::fs::read_to_string(&trust_anchor_path).unwrap_or_else(|_| {
        panic!(
            "ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE must name a readable public PEM trust anchor"
        )
    });
    assert!(
        trust_anchor_pem.contains("BEGIN CERTIFICATE"),
        "ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE must contain a PEM certificate"
    );

    Some(LiveConfig {
        directory_url: std::env::var("ACMEX_LE_STAGING_DIRECTORY_URL")
            .unwrap_or_else(|_| DEFAULT_DIRECTORY_URL.to_string()),
        email: email.expect("checked above"),
        domain: domain.expect("checked above"),
        trust_anchor_pem,
        artifact_dir: PathBuf::from(artifact_dir.expect("checked above")),
        http_listen,
        dns,
        profile,
    })
}

async fn live_presenters(config: &LiveConfig, challenge: ChallengeType) -> PresenterRegistry {
    let mut presenters = PresenterRegistry::new();
    match challenge {
        ChallengeType::Http01 => {
            let listen = config.http_listen.expect("HTTP listener is preflighted");
            let presenter = Http01Presenter::with_local_listener(listen)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "could not bind ACMEX_LE_STAGING_HTTP01_LISTEN; configure the caller-owned public port/ingress before retrying"
                    )
                });
            presenters.register(Arc::new(presenter));
        }
        ChallengeType::Dns01 => {
            let dns = config.dns.as_ref().expect("DNS assets are preflighted");
            assert!(
                DefaultDnsProviderFactory::supported_types().contains(&dns.provider_type.as_str()),
                "DNS provider type `{}` is not enabled in this AcmeX build; rebuild with the corresponding dns-* feature",
                dns.provider_type
            );
            let spec = DnsProviderSpec {
                id: "le-staging-live".to_string(),
                provider_type: dns.provider_type.clone(),
                credential: Some(SecretRef::Env {
                    name: "ACMEX_LIVE_DNS_TOKEN".to_string(),
                }),
                zones: vec![dns.zone.clone()],
                zone_suffixes: vec![dns.zone.clone()],
                endpoint: None,
                timeout_secs: 30,
                extra: dns.extra.clone(),
            };
            let router = ProviderRouterBuilder::new(Box::new(EnvFileSecretResolver))
                .provider(spec)
                .build()
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "DNS provider assembly failed; verify non-secret provider settings and caller-owned credential access"
                    )
                });
            let zone_resolver = Arc::new(
                HickoryZoneResolver::from_system()
                    .unwrap_or_else(|_| panic!("system DNS resolver is unavailable for DNS-01")),
            );
            let observer = HickoryPropagationObserver::new(
                zone_resolver.clone(),
                PropagationPolicyV2::default(),
            )
            .unwrap_or_else(|_| panic!("could not create DNS propagation observer"));
            presenters.register(Arc::new(Dns01Presenter::new(
                Arc::new(router),
                zone_resolver,
                Arc::new(observer),
            )));
        }
        _ => panic!("T19 issuance runner only supports HTTP-01 and DNS-01"),
    }
    presenters
}

struct LiveHarness {
    repositories: RepositorySet,
    engine: WorkflowEngine,
    intent_id: IntentId,
    lineage_id: LineageId,
    deploy_root: PathBuf,
    secret_root: PathBuf,
}

impl LiveHarness {
    async fn new(config: &LiveConfig, challenge: ChallengeType, profile: Option<String>) -> Self {
        let run_id = format!("{:x}", rand::random::<u128>());
        let repositories = MemoryRepository::new().into_set();
        let intent_id = IntentId::new(format!("int_le_staging_{run_id}")).expect("generated id");
        let lineage_id = LineageId::new(format!("lin_le_staging_{run_id}")).expect("generated id");
        let deploy_root = std::env::temp_dir().join(format!("acmex-le-staging-deploy-{run_id}"));
        let secret_root = std::env::temp_dir().join(format!("acmex-le-staging-secrets-{run_id}"));
        let identifiers = IdentifierSet::new(vec![
            Identifier::try_dns(&config.domain).expect("preflighted DNS identifier"),
        ])
        .expect("one valid identifier");
        let intent = CertificateIntent {
            id: intent_id.clone(),
            tenant_id: TenantId::default_tenant(),
            identifiers: identifiers.clone(),
            ca_policy: CaPolicy {
                ca_id: Some("le-staging".to_string()),
                profile,
                ..Default::default()
            },
            validation_policy: ValidationPolicy {
                allowed_challenges: ChallengeSet::new([challenge]),
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
                .expect("temporary file delivery target"),
            ],
            idempotency_key: format!("le-staging-{run_id}"),
            generation: 1,
        };
        repositories
            .intents
            .create(intent)
            .await
            .expect("persist intent");
        repositories
            .lineages
            .create(CertificateLineage::new(
                lineage_id.clone(),
                TenantId::default_tenant(),
                intent_id.clone(),
                identifiers,
            ))
            .await
            .expect("persist lineage");

        let account_key = Arc::new(KeyPair::generate().expect("generate staging account key"));
        let account_jwk = AccountJwkHandle::new(
            Jwk::for_key_pair(&account_key.0).expect("describe staging account key"),
        );
        let acme_backend = AcmeCaBackend::new(
            "le-staging",
            config.directory_url.clone(),
            Arc::new(ReqwestAcmeTransport::new()),
            account_key,
            repositories.clone(),
        );
        acme_backend.attach_jwk_handle(account_jwk.clone());
        let backend: Arc<dyn CaBackend> = Arc::new(acme_backend);
        let key_provider = Arc::new(SoftwareKeyProvider::new(FileSecretStore::new(
            secret_root.clone(),
        )));
        let orchestrator = acmex::delivery::DeploymentOrchestrator::new(repositories.clone())
            .register_sink(
                DeliveryTargetKind::File,
                Arc::new(acmex::delivery::FileCertificateSink::new()),
            );
        let mut engine = WorkflowEngine::new("le-staging-issuance", repositories.clone());
        register_executors(
            &mut engine,
            &WorkflowWorkerSettings {
                propagation_timeout: Duration::from_secs(600),
                challenge_poll_interval: Duration::from_secs(5),
                account_contacts: vec![format!("mailto:{}", config.email)],
                trust_anchor_pems: vec![config.trust_anchor_pem.clone()],
                allowed_challenges: ChallengeSet::new([challenge]),
                ..Default::default()
            },
            WorkflowWorkerComponents {
                backend,
                account_jwk,
                presenters: live_presenters(config, challenge).await,
                key_provider,
                orchestrator,
            },
        );
        Self {
            repositories,
            engine,
            intent_id,
            lineage_id,
            deploy_root,
            secret_root,
        }
    }

    async fn issue_and_activate(&mut self, kind: OperationKind) -> VersionId {
        let operation_id = OperationId::generate();
        self.repositories
            .operations
            .create(OperationRecord::new(
                operation_id.clone(),
                kind,
                OperationSubject {
                    intent_id: Some(self.intent_id.clone()),
                    lineage_id: Some(self.lineage_id.clone()),
                    version_id: None,
                },
                Some(format!("le-staging-{}", operation_id.as_str())),
                None,
                Timestamp::now(),
            ))
            .await
            .expect("persist issuance operation");
        let record = self
            .engine
            .run_until_terminal(&operation_id, Duration::from_secs(600))
            .await
            .expect("run real LE staging issuance operation");
        assert_eq!(
            record.status,
            OperationStatus::Succeeded,
            "LE staging issuance did not succeed (operation state only): {}",
            record.status.as_str()
        );
        let version_id = VersionId::new(format!("ver_{operation_id}")).expect("derived version id");
        let deploy_operation_id = OperationId::new(format!("op_deploy_{version_id}_file"))
            .expect("derived deployment operation id");
        let deployment = self
            .engine
            .run_until_terminal(&deploy_operation_id, Duration::from_secs(180))
            .await
            .expect("run file sink deployment operation");
        assert_eq!(
            deployment.status,
            OperationStatus::Succeeded,
            "File sink activation did not succeed (operation state only): {}",
            deployment.status.as_str()
        );
        version_id
    }

    async fn version(&self, id: &VersionId) -> acmex::domain::CertificateVersion {
        self.repositories
            .versions
            .get(id)
            .await
            .expect("read version")
            .expect("version exists")
            .value
    }
}

impl Drop for LiveHarness {
    fn drop(&mut self) {
        // These paths are process-private temporary child directories.  Drop
        // also covers assertion/panic paths, so a failed external run does
        // not leave a private key beside the caller-owned evidence archive.
        let _ = std::fs::remove_dir_all(&self.deploy_root);
        let _ = std::fs::remove_dir_all(&self.secret_root);
    }
}

fn summary_path(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

fn public_version_summary(version: &acmex::domain::CertificateVersion) -> serde_json::Value {
    let report: Option<&CertificateVerificationReport> = version.verification_report.as_ref();
    let mut leaf_hash = Sha256::new();
    leaf_hash.update(version.certificate_chain_pem.as_bytes());
    serde_json::json!({
        "version_state": version.state.as_str(),
        "serial": version.serial,
        "not_before": version.not_before,
        "not_after": version.not_after,
        "certificate_chain_sha256": hex::encode(leaf_hash.finalize()),
        "verification_report": report.map(|report| serde_json::json!({
            "accepted": report.accepted(),
            "identifiers_exact_match": report.identifiers_exact_match,
            "checks": report.checks.iter().map(|check| serde_json::json!({
                "check": check.check,
                "status": check.status,
            })).collect::<Vec<_>>(),
        })),
    })
}

fn write_public_summary(path: PathBuf, summary: serde_json::Value) {
    std::fs::create_dir_all(path.parent().expect("summary has parent"))
        .expect("create caller-owned artifact directory");
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&summary).expect("serialize public evidence summary"),
    )
    .expect("write public evidence summary");
}

async fn run_issuance(scenario: Scenario, challenge: ChallengeType) {
    let Some(config) = load_config(scenario, challenge) else {
        return;
    };
    let mut harness = LiveHarness::new(&config, challenge, None).await;
    let version_id = harness.issue_and_activate(OperationKind::Issue).await;
    let version = harness.version(&version_id).await;
    assert_eq!(version.state, VersionState::Active);
    let report = version
        .verification_report
        .as_ref()
        .expect("real issuance must persist a verification report");
    assert!(
        report.accepted(),
        "real certificate verification must be accepted"
    );
    assert!(
        report.all_passed(),
        "all strict verification checks must pass"
    );
    assert!(
        harness.deploy_root.join("current").exists(),
        "File sink must activate a current pointer before the scenario passes"
    );
    let filename = match challenge {
        ChallengeType::Http01 => "issuance-http-01-summary.json",
        ChallengeType::Dns01 => "issuance-dns-01-summary.json",
        _ => unreachable!("only HTTP-01 and DNS-01 are dispatched"),
    };
    write_public_summary(
        summary_path(&config.artifact_dir, filename),
        serde_json::json!({
            "scenario": scenario.name(),
            "challenge": challenge.as_str(),
            "file_sink_activated": true,
            "secret_values_recorded": false,
            "version": public_version_summary(&version),
        }),
    );
}

#[test]
fn le_staging_issuance_scenario_parser_expands_all_without_secret_values() {
    let scenarios = parse_scenarios("http-01, all, dns-01");
    assert_eq!(
        scenarios,
        BTreeSet::from([
            "dns-01".to_string(),
            "http-01".to_string(),
            "profile".to_string(),
            "renewal".to_string(),
        ])
    );
    assert!(
        !scenarios
            .iter()
            .any(|entry| entry.contains("TOKEN") || entry.contains("SECRET")),
        "scenario selection is a name-only control plane"
    );
}

#[tokio::test]
#[ignore = "real LE staging HTTP-01 issuance; requires caller-owned public HTTP endpoint"]
async fn le_staging_http01_issues_verifies_and_activates_file_sink() {
    run_issuance(Scenario::Http01, ChallengeType::Http01).await;
}

#[tokio::test]
#[ignore = "real LE staging DNS-01 issuance; requires caller-owned DNS provider credentials"]
async fn le_staging_dns01_issues_verifies_and_activates_file_sink() {
    run_issuance(Scenario::Dns01, ChallengeType::Dns01).await;
}

#[tokio::test]
#[ignore = "real LE staging renewal; requires the same caller-owned HTTP-01 assets twice"]
async fn le_staging_renewal_records_replaces_and_supersedes_after_file_activation() {
    let Some(config) = load_config(Scenario::Renewal, ChallengeType::Http01) else {
        return;
    };
    let mut harness = LiveHarness::new(&config, ChallengeType::Http01, None).await;
    let first_id = harness.issue_and_activate(OperationKind::Issue).await;
    let first = harness.version(&first_id).await;
    assert_eq!(first.state, VersionState::Active);
    let ari = acmex::ca_backend::DirectoryAriProvider::new(
        config.directory_url.clone(),
        Arc::new(ReqwestAcmeTransport::new()),
    )
    .renewal_window(&first.certificate_chain_pem)
    .await
    .expect("query ARI renewal information or its explicit no-suggestion response");
    let renewed_id = harness.issue_and_activate(OperationKind::Renew).await;
    let renewed = harness.version(&renewed_id).await;
    assert_eq!(renewed.state, VersionState::Active);
    assert_eq!(renewed.replaces.as_ref(), Some(&first_id));
    let superseded = harness.version(&first_id).await;
    assert_eq!(superseded.state, VersionState::Superseded);
    assert_eq!(superseded.superseded_by.as_ref(), Some(&renewed_id));
    let lineage = harness
        .repositories
        .lineages
        .get(&harness.lineage_id)
        .await
        .expect("read lineage")
        .expect("lineage exists")
        .value;
    assert_eq!(lineage.active_version_id.as_ref(), Some(&renewed_id));
    write_public_summary(
        summary_path(&config.artifact_dir, "renewal-ari-replaces-summary.json"),
        serde_json::json!({
            "scenario": "renewal",
            "renewal_operation_completed": true,
            "replaces_recorded": true,
            "old_version_superseded_after_file_activation": true,
            "ari": match ari {
                Some(window) => serde_json::json!({
                    "outcome": "suggested_window",
                    "start": window.start.to_string(),
                    "end": window.end.to_string(),
                }),
                None => serde_json::json!({ "outcome": "not_advertised_or_no_suggestion" }),
            },
            "secret_values_recorded": false,
            "initial_version": public_version_summary(&first),
            "renewed_version": public_version_summary(&renewed),
        }),
    );
}

#[tokio::test]
#[ignore = "real LE staging profile behavior; requires a caller-selected advertised profile and HTTP-01 assets"]
async fn le_staging_profile_selection_is_observed_or_explicitly_recorded_as_unavailable() {
    let Some(config) = load_config(Scenario::Profile, ChallengeType::Http01) else {
        return;
    };
    let profile = config.profile.clone().expect("profile is preflighted");
    let account_key = Arc::new(KeyPair::generate().expect("generate staging account key"));
    let repositories = MemoryRepository::new().into_set();
    let backend = AcmeCaBackend::new(
        "le-staging",
        config.directory_url.clone(),
        Arc::new(ReqwestAcmeTransport::new()),
        account_key,
        repositories,
    );
    let capabilities = backend
        .capabilities()
        .await
        .expect("fetch LE staging capabilities");
    if !capabilities.supports_profile(&profile) {
        write_public_summary(
            summary_path(&config.artifact_dir, "profile-summary.json"),
            serde_json::json!({
                "scenario": "profile",
                "requested_profile": profile,
                "outcome": "not_advertised_by_ca",
                "advertised_profiles": capabilities.profiles.iter().map(|item| &item.name).collect::<Vec<_>>(),
                "secret_values_recorded": false,
            }),
        );
        return;
    }

    let mut harness = LiveHarness::new(&config, ChallengeType::Http01, Some(profile.clone())).await;
    let version_id = harness.issue_and_activate(OperationKind::Issue).await;
    let version = harness.version(&version_id).await;
    assert_eq!(version.profile.as_deref(), Some(profile.as_str()));
    let report = version
        .verification_report
        .as_ref()
        .expect("profile issuance must persist a verification report");
    assert_eq!(report.profile.as_deref(), Some(profile.as_str()));
    write_public_summary(
        summary_path(&config.artifact_dir, "profile-summary.json"),
        serde_json::json!({
            "scenario": "profile",
            "requested_profile": profile,
            "outcome": "issued_and_recorded",
            "secret_values_recorded": false,
            "version": public_version_summary(&version),
        }),
    );
}
