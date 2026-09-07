//! External HTTP agent sink evidence (roadmap T20).
//!
//! This is the environment-backed counterpart of `tests/agent_live.rs`: it does
//! not start the reference child process, but drives an already deployed agent
//! URL through the real `HttpAgentSink` contract. It is ignored by default
//! because it mutates an external agent route table.

use std::time::Duration;

use acmex::delivery::http_sink::HttpAgentSink;
use acmex::dns::spec::{EnvFileSecretResolver, SecretRef, SecretResolver};
use acmex::{
    CertificateMaterialBuilder, CertificateMaterialRef, CertificateSink, CertificateVersion,
    CleanupOutcome, DeliveryRequirement, DeliveryTargetKind, DeploymentHealth, DeploymentSpec,
    IdentifierSet, KeyAlgorithm, KeyId, KeyRef, LineageId, SecretBytes, TargetId, VersionId,
    VersionState,
};

struct LiveAgentConfig {
    base_url: String,
    token_ref: String,
    agent_id: String,
    target_id: TargetId,
}

fn config() -> Option<LiveAgentConfig> {
    let base_url = std::env::var("ACMEX_LIVE_HTTP_AGENT_URL").ok()?;
    let token_ref = std::env::var("ACMEX_LIVE_HTTP_AGENT_TOKEN_REF").ok()?;
    let agent_id =
        std::env::var("ACMEX_LIVE_HTTP_AGENT_ID").unwrap_or_else(|_| "external-agent".to_string());
    let target_id = std::env::var("ACMEX_LIVE_HTTP_AGENT_TARGET_ID")
        .ok()
        .and_then(|value| TargetId::new(value).ok())
        .unwrap_or_else(|| TargetId::new("edge-live-external").unwrap());
    Some(LiveAgentConfig {
        base_url,
        token_ref,
        agent_id,
        target_id,
    })
}

fn skip_reason() -> &'static str {
    "SKIP: set ACMEX_LIVE_HTTP_AGENT_URL and ACMEX_LIVE_HTTP_AGENT_TOKEN_REF \
     (env:/file: SecretRef) to run the external HTTP agent sink contract"
}

async fn resolve_token(token_ref: &str) -> String {
    let reference = SecretRef::parse(token_ref)
        .expect("ACMEX_LIVE_HTTP_AGENT_TOKEN_REF must be env:/file:/vault:/provider: SecretRef");
    let secret = EnvFileSecretResolver
        .resolve(&reference)
        .await
        .expect("resolve ACMEX_LIVE_HTTP_AGENT_TOKEN_REF");
    assert!(
        !secret.expose().is_empty(),
        "ACMEX_LIVE_HTTP_AGENT_TOKEN_REF resolved to an empty token"
    );
    String::from_utf8(secret.expose().to_vec()).expect("agent token must be UTF-8")
}

fn sample_version(domain: &str) -> (CertificateVersion, String) {
    let certified = rcgen::generate_simple_self_signed([domain.to_string()]).unwrap();
    let version = CertificateVersion {
        id: VersionId::generate(),
        lineage_id: LineageId::generate(),
        identifiers: IdentifierSet::parse([domain]).unwrap(),
        certificate_chain_pem: certified.cert.pem(),
        serial: "01".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2026-04-01T00:00:00Z".into(),
        issued_by: "external-contract-ca".into(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Issued,
    };
    (version, certified.signing_key.serialize_pem())
}

fn keyed_material(version: &CertificateVersion, key_pem: &str) -> acmex::CertificateMaterial {
    CertificateMaterialBuilder::new()
        .require_private_key()
        .build(version, Some(SecretBytes::new(key_pem.as_bytes().to_vec())))
        .expect("build certificate material")
}

fn deployment_spec(target_id: TargetId) -> DeploymentSpec {
    DeploymentSpec {
        target_id,
        kind: DeliveryTargetKind::Webhook,
        reference: "external-http-agent-live".to_string(),
        requirement: DeliveryRequirement::Required,
    }
}

async fn assert_health(
    sink: &HttpAgentSink,
    staged: &acmex::StagedDeployment,
    expected: DeploymentHealth,
    context: &str,
) {
    let health = sink.health_check(staged).await.expect(context);
    assert_eq!(health, expected, "{context}: got {health:?}");
}

#[tokio::test]
#[ignore = "requires a deployed external HTTP agent and token SecretRef"]
async fn external_http_agent_full_lifecycle_contract() {
    let Some(config) = config() else {
        eprintln!("{}", skip_reason());
        return;
    };

    let token = resolve_token(&config.token_ref).await;
    let sink = HttpAgentSink::new(config.agent_id, config.base_url, token);
    let spec = deployment_spec(config.target_id);

    let unique = format!("{}", jiff::Timestamp::now().as_millisecond());
    let (version1, key1) = sample_version(&format!("agent-ext-{unique}.example.com"));
    let material1 = keyed_material(&version1, &key1);
    let staged1 = sink
        .stage(
            &spec,
            &version1,
            CertificateMaterialRef {
                material: &material1,
            },
        )
        .await
        .expect("stage v1 on external HTTP agent");
    assert!(staged1.resource_version >= 1);
    assert!(
        matches!(
            sink.health_check(&staged1).await.unwrap(),
            DeploymentHealth::Unhealthy(_)
        ),
        "staged route must be reachable but inactive before activate"
    );

    sink.activate(&staged1).await.expect("activate v1");
    assert_health(&sink, &staged1, DeploymentHealth::Healthy, "v1 active").await;

    let (version2, key2) = sample_version(&format!("agent-ext-next-{unique}.example.com"));
    let material2 = keyed_material(&version2, &key2);
    let staged2 = sink
        .stage(
            &spec,
            &version2,
            CertificateMaterialRef {
                material: &material2,
            },
        )
        .await
        .expect("stage v2 on external HTTP agent");
    assert_health(
        &sink,
        &staged1,
        DeploymentHealth::Healthy,
        "v1 remains active",
    )
    .await;
    assert!(
        matches!(
            sink.health_check(&staged2).await.unwrap(),
            DeploymentHealth::Unhealthy(_)
        ),
        "staged v2 must not become active until activate"
    );

    sink.activate(&staged2).await.expect("activate v2");
    assert_health(&sink, &staged2, DeploymentHealth::Healthy, "v2 active").await;
    sink.rollback(&staged2).await.expect("rollback v2");
    assert_health(
        &sink,
        &staged1,
        DeploymentHealth::Healthy,
        "rollback restores v1",
    )
    .await;

    assert_eq!(
        sink.cleanup(&staged2).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert_eq!(
        sink.cleanup(&staged1).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert_eq!(
        sink.cleanup(&staged1).await.unwrap(),
        CleanupOutcome::AlreadyClean
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    println!(
        "external HTTP agent contract passed for target {}",
        spec.target_id
    );
}
