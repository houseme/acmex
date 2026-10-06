//! Controlled Let's Encrypt Staging IP-identifier evidence runner (T19).
//!
//! This is deliberately an ignored integration test. It only contacts the
//! public staging CA after the caller has opted in with `RUN_LE_STAGING=1` and
//! supplied a controlled public IP plus the exact privileged listener address
//! for every requested scenario. Missing or malformed assets are test
//! failures, never a skipped success.
//!
//! The test uses the normal production worker assembly: `AcmeCaBackend`, the
//! local HTTP-01 / TLS-ALPN-01 presenters, managed keys, durable workflow
//! steps, and strict certificate verification. It writes only a sanitized
//! evidence manifest; it never records email addresses, listener addresses,
//! trust-anchor paths, private keys, or certificate PEM.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jiff::Timestamp;
use sha2::{Digest, Sha256};

use acmex::config::Config;
use acmex::domain::{
    CaPolicy, CertificateIntent, CertificateLineage, ChallengeSet, Identifier, IdentifierSet,
    IntentId, LineageId, OperationId, OperationKind, OperationRecord, OperationStatus,
    OperationSubject, TenantId, ValidationPolicy, VersionId, VersionState,
};
use acmex::metrics::MetricsRegistry;
use acmex::repository::MemoryRepository;
use acmex::server::worker::{WorkflowWorkerSettings, build_engine_from_config};
use acmex::types::ChallengeType;

const LE_STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const SCENARIOS_ENV: &str = "ACMEX_LE_STAGING_IP_SCENARIOS";
const ACCOUNT_EMAIL_ENV: &str = "ACMEX_LE_STAGING_IP_ACCOUNT_EMAIL";
const TRUST_ANCHOR_ENV: &str = "ACMEX_LE_STAGING_IP_TRUST_ANCHOR_PEM_FILE";
const ARTIFACT_DIR_ENV: &str = "ACMEX_LE_STAGING_IP_ARTIFACT_DIR";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Scenario {
    Ipv4Http01,
    Ipv4TlsAlpn01,
    Ipv6Http01,
    Ipv6TlsAlpn01,
}

impl Scenario {
    const ALL: [Self; 4] = [
        Self::Ipv4Http01,
        Self::Ipv4TlsAlpn01,
        Self::Ipv6Http01,
        Self::Ipv6TlsAlpn01,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Ipv4Http01 => "ipv4-http-01",
            Self::Ipv4TlsAlpn01 => "ipv4-tls-alpn-01",
            Self::Ipv6Http01 => "ipv6-http-01",
            Self::Ipv6TlsAlpn01 => "ipv6-tls-alpn-01",
        }
    }

    fn identifier_env(self) -> &'static str {
        match self {
            Self::Ipv4Http01 | Self::Ipv4TlsAlpn01 => "ACMEX_LE_STAGING_IP_V4",
            Self::Ipv6Http01 | Self::Ipv6TlsAlpn01 => "ACMEX_LE_STAGING_IP_V6",
        }
    }

    fn listener_env(self) -> &'static str {
        match self {
            Self::Ipv4Http01 => "ACMEX_LE_STAGING_IP_V4_HTTP01_LISTEN",
            Self::Ipv4TlsAlpn01 => "ACMEX_LE_STAGING_IP_V4_TLS_ALPN01_LISTEN",
            Self::Ipv6Http01 => "ACMEX_LE_STAGING_IP_V6_HTTP01_LISTEN",
            Self::Ipv6TlsAlpn01 => "ACMEX_LE_STAGING_IP_V6_TLS_ALPN01_LISTEN",
        }
    }

    fn challenge_type(self) -> ChallengeType {
        match self {
            Self::Ipv4Http01 | Self::Ipv6Http01 => ChallengeType::Http01,
            Self::Ipv4TlsAlpn01 | Self::Ipv6TlsAlpn01 => ChallengeType::TlsAlpn01,
        }
    }

    fn expected_port(self) -> u16 {
        match self.challenge_type() {
            ChallengeType::Http01 => 80,
            ChallengeType::TlsAlpn01 => 443,
            _ => unreachable!("T19 IP scenarios only use HTTP-01 or TLS-ALPN-01"),
        }
    }

    fn accepts_ip(self, ip: IpAddr) -> bool {
        matches!(
            (self, ip),
            (Self::Ipv4Http01 | Self::Ipv4TlsAlpn01, IpAddr::V4(_))
                | (Self::Ipv6Http01 | Self::Ipv6TlsAlpn01, IpAddr::V6(_))
        )
    }
}

fn parse_scenarios(raw: &str) -> Result<Vec<Scenario>, String> {
    let requested = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Err(format!(
            "{SCENARIOS_ENV} must name at least one IP scenario"
        ));
    }

    let mut scenarios = BTreeSet::new();
    for item in requested {
        if item == "all" {
            for scenario in Scenario::ALL {
                if !scenarios.insert(scenario) {
                    return Err(format!(
                        "{SCENARIOS_ENV} repeats scenario `{}` via `all`",
                        scenario.name()
                    ));
                }
            }
            continue;
        }
        let scenario = Scenario::ALL
            .into_iter()
            .find(|scenario| scenario.name() == item)
            .ok_or_else(|| {
                format!(
                    "{SCENARIOS_ENV} contains unknown scenario `{item}`; expected one of: \
                     ipv4-http-01, ipv4-tls-alpn-01, ipv6-http-01, ipv6-tls-alpn-01, all"
                )
            })?;
        if !scenarios.insert(scenario) {
            return Err(format!("{SCENARIOS_ENV} repeats scenario `{item}`"));
        }
    }
    Ok(scenarios.into_iter().collect())
}

fn required_env(name: &'static str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("missing required controlled asset `{name}`"))
}

fn reject_non_public_ip(ip: IpAddr) -> Result<(), String> {
    let disallowed = match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || ip.is_unspecified()
                || ip.is_multicast()
        }
    };
    (!disallowed).then_some(()).ok_or_else(|| {
        "controlled T19 IP assets must be publicly routable; private, local, documentation, \
         multicast, and unspecified addresses are rejected before any CA request"
            .to_string()
    })
}

#[derive(Debug, Clone)]
struct ScenarioAssets {
    scenario: Scenario,
    identifier: Identifier,
    listen: SocketAddr,
}

#[derive(Debug)]
struct RunAssets {
    email: String,
    trust_anchor: PathBuf,
    artifact_dir: PathBuf,
    scenarios: Vec<ScenarioAssets>,
}

impl RunAssets {
    fn load() -> Result<Self, String> {
        if std::env::var("RUN_LE_STAGING").as_deref() != Ok("1") {
            return Err(
                "RUN_LE_STAGING=1 is required before this test may contact Let's Encrypt Staging; \
                 an unconfigured external run is not a pass"
                    .to_string(),
            );
        }
        let scenarios = parse_scenarios(&required_env(SCENARIOS_ENV)?)?;
        let email = required_env(ACCOUNT_EMAIL_ENV)?;
        let trust_anchor = PathBuf::from(required_env(TRUST_ANCHOR_ENV)?);
        if !trust_anchor.is_file() {
            return Err(format!("{TRUST_ANCHOR_ENV} must name a readable PEM file"));
        }
        let artifact_dir = PathBuf::from(required_env(ARTIFACT_DIR_ENV)?);

        let scenarios = scenarios
            .into_iter()
            .map(|scenario| {
                let identifier = Identifier::try_ip(required_env(scenario.identifier_env())?)
                    .map_err(|_| {
                        format!("{} must be a literal IP address", scenario.identifier_env())
                    })?;
                let ip = identifier.as_ip().ok_or_else(|| {
                    "T19 runner accepted a non-IP identifier unexpectedly".to_string()
                })?;
                if !scenario.accepts_ip(ip) {
                    return Err(format!(
                        "{} must provide a {} address for scenario `{}`",
                        scenario.identifier_env(),
                        if matches!(scenario, Scenario::Ipv4Http01 | Scenario::Ipv4TlsAlpn01) {
                            "IPv4"
                        } else {
                            "IPv6"
                        },
                        scenario.name()
                    ));
                }
                reject_non_public_ip(ip)?;
                let listen = required_env(scenario.listener_env())?
                    .parse::<SocketAddr>()
                    .map_err(|_| {
                        format!(
                            "{} must be a literal socket address",
                            scenario.listener_env()
                        )
                    })?;
                if listen.ip() != ip {
                    return Err(format!(
                        "{} must bind exactly the controlled identifier address",
                        scenario.listener_env()
                    ));
                }
                if listen.port() != scenario.expected_port() {
                    return Err(format!(
                        "{} must use the ACME-required port {}",
                        scenario.listener_env(),
                        scenario.expected_port()
                    ));
                }
                Ok(ScenarioAssets {
                    scenario,
                    identifier,
                    listen,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self {
            email,
            trust_anchor,
            artifact_dir,
            scenarios,
        })
    }
}

fn unique_test_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "acmex-le-staging-ip-{label}-{}-{nanos}",
        std::process::id()
    ))
}

/// The worker persists a real account key and a managed certificate key while
/// issuing. Keep that sensitive test state outside the caller's evidence
/// directory and remove it on both success and unwinding.
struct SecretStoreGuard(PathBuf);

impl Drop for SecretStoreGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn configured_worker(assets: &RunAssets) -> Config {
    let mut config = Config::default();
    config.acme.ca = "letsencrypt".to_string();
    config.acme.ca_environment = "staging".to_string();
    config.acme.directory = LE_STAGING_DIRECTORY.to_string();
    config.acme.identifier_types = vec!["ip".to_string()];
    config.acme.trust_anchor_pem_files = vec![assets.trust_anchor.to_string_lossy().into_owned()];
    config.ca.account_key_type = "ecdsa_p256".to_string();
    config.repository.backend = "memory".to_string();
    config
}

async fn run_scenario(assets: &RunAssets, scenario: &ScenarioAssets) -> serde_json::Value {
    let repositories = MemoryRepository::new().into_set();
    let secret_store_dir = unique_test_dir(scenario.scenario.name());
    let _secret_store_guard = SecretStoreGuard(secret_store_dir.clone());
    let config = configured_worker(assets);
    let settings = WorkflowWorkerSettings {
        account_contacts: vec![format!("mailto:{}", assets.email)],
        terms_agreed: true,
        allowed_challenges: ChallengeSet::new([scenario.scenario.challenge_type()]),
        secret_store_dir: secret_store_dir.clone(),
        http01_listen: (scenario.scenario.challenge_type() == ChallengeType::Http01)
            .then(|| scenario.listen.to_string()),
        tls_alpn_listen: (scenario.scenario.challenge_type() == ChallengeType::TlsAlpn01)
            .then(|| scenario.listen.to_string()),
        propagation_timeout: Duration::from_secs(120),
        challenge_poll_interval: Duration::from_secs(2),
        ..Default::default()
    };
    let engine = build_engine_from_config(
        &config,
        repositories.clone(),
        Arc::new(MetricsRegistry::new()),
        settings,
    )
    .await
    .unwrap_or_else(|err| panic!("production worker assembly failed: {err}"));

    let intent_id = IntentId::generate();
    let lineage_id = LineageId::generate();
    let identifiers = IdentifierSet::new(vec![scenario.identifier.clone()])
        .expect("single validated IP identifier");
    let intent = CertificateIntent {
        id: intent_id.clone(),
        tenant_id: TenantId::default_tenant(),
        identifiers: identifiers.clone(),
        ca_policy: CaPolicy::default(),
        validation_policy: ValidationPolicy {
            allowed_challenges: ChallengeSet::new([scenario.scenario.challenge_type()]),
            ..Default::default()
        },
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets: Vec::new(),
        idempotency_key: format!("t19-{}", scenario.scenario.name()),
        generation: 1,
    };
    repositories
        .intents
        .create(intent)
        .await
        .expect("persist T19 intent");
    repositories
        .lineages
        .create(CertificateLineage::new(
            lineage_id.clone(),
            TenantId::default_tenant(),
            intent_id.clone(),
            identifiers,
        ))
        .await
        .expect("persist T19 lineage");

    let operation_id = OperationId::generate();
    repositories
        .operations
        .create(OperationRecord::new(
            operation_id.clone(),
            OperationKind::Issue,
            OperationSubject {
                intent_id: Some(intent_id),
                lineage_id: Some(lineage_id),
                version_id: None,
            },
            Some(format!("t19-{}", scenario.scenario.name())),
            None,
            Timestamp::now(),
        ))
        .await
        .expect("persist T19 issue operation");

    let record = engine
        .run_until_terminal(&operation_id, Duration::from_secs(600))
        .await
        .unwrap_or_else(|err| panic!("T19 {} did not finish: {err}", scenario.scenario.name()));
    assert_eq!(
        record.status,
        OperationStatus::Succeeded,
        "T19 {} failed: {:?}",
        scenario.scenario.name(),
        record.error
    );

    let version_id = VersionId::new(format!("ver_{operation_id}")).expect("derived version id");
    let version = repositories
        .versions
        .get(&version_id)
        .await
        .expect("load issued version")
        .unwrap_or_else(|| {
            panic!(
                "T19 {} persisted no certificate version",
                scenario.scenario.name()
            )
        })
        .value;
    assert_eq!(version.state, VersionState::Issued);
    assert!(version.certificate_chain_pem.contains("BEGIN CERTIFICATE"));
    let report = version.verification_report.as_ref().unwrap_or_else(|| {
        panic!(
            "T19 {} did not persist verification evidence",
            scenario.scenario.name()
        )
    });
    assert!(
        report.accepted() && report.all_passed(),
        "verification report: {report:?}"
    );

    let certificate_sha256 = hex::encode(Sha256::digest(version.certificate_chain_pem.as_bytes()));
    let identifier_sha256 =
        hex::encode(Sha256::digest(scenario.identifier.acme_value().as_bytes()));
    serde_json::json!({
        "scenario": scenario.scenario.name(),
        "directory": LE_STAGING_DIRECTORY,
        "identifier_type": "ip",
        "identifier_sha256": identifier_sha256,
        "challenge_type": match scenario.scenario.challenge_type() {
            ChallengeType::Http01 => "http-01",
            ChallengeType::TlsAlpn01 => "tls-alpn-01",
            _ => unreachable!("scenario challenge is constrained above"),
        },
        "certificate_chain_sha256": certificate_sha256,
        "not_before": version.not_before,
        "not_after": version.not_after,
        "verification_conclusion": format!("{:?}", report.conclusion),
        "verification_checks": report.checks.iter().map(|check| check.check.as_str()).collect::<Vec<_>>(),
        "recorded_at": Timestamp::now().to_string(),
        "secret_values_recorded": false,
    })
}

fn write_evidence(dir: &Path, evidence: &[serde_json::Value]) {
    std::fs::create_dir_all(dir).expect("create caller-provided evidence directory");
    let manifest = serde_json::json!({
        "gate": "le-staging-ip-identifiers",
        "directory": LE_STAGING_DIRECTORY,
        "results": evidence,
        "secret_values_recorded": false,
    });
    std::fs::write(
        dir.join("ip-identifier-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize sanitized evidence"),
    )
    .expect("write sanitized T19 evidence");
}

#[test]
fn t19_ip_scenario_parser_requires_explicit_known_selection() {
    assert_eq!(
        parse_scenarios("ipv4-http-01, ipv6-tls-alpn-01").expect("known scenarios"),
        vec![Scenario::Ipv4Http01, Scenario::Ipv6TlsAlpn01]
    );
    assert_eq!(parse_scenarios("all").expect("all scenarios").len(), 4);
    assert!(parse_scenarios("").is_err());
    assert!(parse_scenarios("ipv4-http-01,unknown").is_err());
    assert!(parse_scenarios("ipv4-http-01,ipv4-http-01").is_err());
}

#[test]
fn t19_ip_preflight_rejects_non_public_identifier_ranges() {
    for ip in [
        "127.0.0.1".parse().unwrap(),
        "192.0.2.1".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        "fc00::1".parse().unwrap(),
    ] {
        assert!(reject_non_public_ip(ip).is_err(), "{ip} must be rejected");
    }
}

#[test]
fn t19_ip_scenarios_bind_only_the_standard_acme_ports() {
    assert_eq!(Scenario::Ipv4Http01.expected_port(), 80);
    assert_eq!(Scenario::Ipv6Http01.expected_port(), 80);
    assert_eq!(Scenario::Ipv4TlsAlpn01.expected_port(), 443);
    assert_eq!(Scenario::Ipv6TlsAlpn01.expected_port(), 443);
}

#[test]
fn t19_ip_scenarios_reject_the_other_address_family() {
    let ipv4: IpAddr = "198.51.100.1".parse().unwrap();
    let ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    assert!(Scenario::Ipv4Http01.accepts_ip(ipv4));
    assert!(!Scenario::Ipv4Http01.accepts_ip(ipv6));
    assert!(Scenario::Ipv6TlsAlpn01.accepts_ip(ipv6));
    assert!(!Scenario::Ipv6TlsAlpn01.accepts_ip(ipv4));
}

#[tokio::test]
#[ignore = "contacts Let's Encrypt Staging and binds caller-controlled public IP addresses"]
async fn le_staging_ip_identifier_issuance() {
    let assets = RunAssets::load().unwrap_or_else(|err| panic!("T19 IP preflight failed: {err}"));
    let mut evidence = Vec::with_capacity(assets.scenarios.len());
    for scenario in &assets.scenarios {
        evidence.push(run_scenario(&assets, scenario).await);
    }
    write_evidence(&assets.artifact_dir, &evidence);
    println!(
        "T19 IP evidence written: {}",
        assets
            .artifact_dir
            .join("ip-identifier-manifest.json")
            .display()
    );
}
