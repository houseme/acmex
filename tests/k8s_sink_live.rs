//! Live Kubernetes Secret sink contract (roadmap T20) — `#[ignore]`d because
//! it talks to a real API server and mutates real Secrets.
//!
//! This is the live counterpart of the mock coverage in
//! `tests/certificate_sink_contract.rs` for `KubernetesSecretSink`: the full
//! five-phase lifecycle (stage → activate → health → tamper → rollback →
//! cleanup) runs against an actual cluster, and every phase is cross-checked
//! with `kubectl` (shelled out via `std::process::Command`; the current
//! context must point at the same cluster, admin access is only used for the
//! independent verification and the tamper step — the sink itself operates
//! through the least-privileged bearer token).
//!
//! Configuration (all via environment):
//!
//! ```text
//! ACMEX_LIVE_K8S_ENDPOINT=https://127.0.0.1:26443   # API server URL
//! ACMEX_LIVE_K8S_TOKEN=...                          # bearer token, or a
//!                                                   # `env:`/`file:` SecretRef
//! ACMEX_LIVE_K8S_CA=/path/to/ca.pem                 # cluster CA (PEM)
//! ACMEX_LIVE_K8S_NAMESPACE=acmex-live               # optional, default below
//! ```
//!
//! Setup used for the recorded evidence run:
//!
//! ```text
//! kubectl create namespace acmex-live
//! kubectl -n acmex-live create serviceaccount acmex-live
//! # Role: get/create/update/delete/patch secrets; RoleBinding to the SA
//! kubectl create token acmex-live -n acmex-live --duration=2h
//! ```
//!
//! Run: `cargo test --test k8s_sink_live -- --ignored --nocapture`
//!
//! The test creates Secrets named `acmex-live-<unix_ts>` (plus the
//! `staging-` twin) and deletes them again at the end; the token is never
//! printed. A missing environment variable prints an explicit SKIP line —
//! that counts as *no evidence collected*, never as a pass.

use std::process::Command;

use acmex::dns::spec::{EnvFileSecretResolver, SecretRef};
use acmex::domain::{
    DeliveryTargetKind, IdentifierSet, KeyAlgorithm, KeyId, KeyRef, LineageId, TargetId, VersionId,
    VersionState,
};
use acmex::{
    CertificateMaterialBuilder, CertificateMaterialRef, CertificateSink, CertificateVersion,
    CleanupOutcome, DeploymentHealth, DeploymentSpec, KubernetesAuth, KubernetesSecretConfig,
    KubernetesSecretSink, SecretBytes,
};

const SKIP_MESSAGE: &str = "SKIP: set ACMEX_LIVE_K8S_ENDPOINT, ACMEX_LIVE_K8S_TOKEN (value or \
env:/file: SecretRef) and ACMEX_LIVE_K8S_CA (PEM path) against a throwaway namespace \
(ACMEX_LIVE_K8S_NAMESPACE, default acmex-live) to collect live Kubernetes sink evidence";

struct LiveK8sConfig {
    endpoint: String,
    namespace: String,
    token: String,
    ca_path: std::path::PathBuf,
}

fn config() -> Option<LiveK8sConfig> {
    let endpoint = std::env::var("ACMEX_LIVE_K8S_ENDPOINT").ok()?;
    let token = std::env::var("ACMEX_LIVE_K8S_TOKEN").ok()?;
    let ca_path = std::env::var("ACMEX_LIVE_K8S_CA").ok()?;
    let namespace =
        std::env::var("ACMEX_LIVE_K8S_NAMESPACE").unwrap_or_else(|_| "acmex-live".to_string());
    Some(LiveK8sConfig {
        endpoint,
        namespace,
        token,
        ca_path: std::path::PathBuf::from(ca_path),
    })
}

/// A `kubectl` cross-check failure is a harness error, not a sink error.
fn kubectl_json(namespace: &str, name: &str) -> Option<serde_json::Value> {
    let output = Command::new("kubectl")
        .args([
            "--namespace",
            namespace,
            "get",
            "secret",
            name,
            "--output",
            "json",
        ])
        .output()
        .expect("spawn kubectl (harness dependency)");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("kubectl get secret {name}: not found ({})", stderr.trim());
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

/// Independent read path: the SHA-256 of the Secret's decoded `tls.crt` DER
/// leaf as observed by `kubectl`, outside the sink's HTTP client.
fn kubectl_leaf_sha(namespace: &str, name: &str) -> Option<String> {
    let value = kubectl_json(namespace, name)?;
    let encoded = value["data"]["tls.crt"].as_str()?;
    let decoded = base64_decode(encoded)?;
    let blocks = pem::parse_many(decoded).ok()?;
    let leaf = blocks
        .iter()
        .find(|block| block.tag() == "CERTIFICATE")?
        .contents()
        .to_vec();
    use sha2::Digest;
    Some(hex::encode(sha2::Sha256::digest(leaf)))
}

fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
}

/// The `type` of the live Secret as observed by `kubectl`.
fn kubectl_secret_type(namespace: &str, name: &str) -> Option<String> {
    kubectl_json(namespace, name)?["type"]
        .as_str()
        .map(str::to_owned)
}

/// Overwrites `tls.crt` in the live Secret through kubectl (admin path),
/// simulating an out-of-band change the sink must detect as `Unhealthy`.
fn kubectl_tamper_tls_crt(namespace: &str, name: &str, replacement_pem: &str) {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(replacement_pem);
    let payload = serde_json::json!({ "data": { "tls.crt": encoded } });
    let output = Command::new("kubectl")
        .args([
            "--namespace",
            namespace,
            "patch",
            "secret",
            name,
            "--type=merge",
            "--patch",
            &payload.to_string(),
        ])
        .output()
        .expect("spawn kubectl (harness dependency)");
    assert!(
        output.status.success(),
        "kubectl patch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn kubectl_delete_secret(namespace: &str, name: &str) {
    let _ = Command::new("kubectl")
        .args([
            "--namespace",
            namespace,
            "delete",
            "secret",
            name,
            "--ignore-not-found",
        ])
        .output();
}

fn sample_version(lineage_id: &LineageId, domain: &str) -> (CertificateVersion, String) {
    let certified = rcgen::generate_simple_self_signed([domain.to_string()]).unwrap();
    let version = CertificateVersion {
        id: VersionId::generate(),
        lineage_id: lineage_id.clone(),
        identifiers: IdentifierSet::parse([domain]).unwrap(),
        certificate_chain_pem: certified.cert.pem(),
        serial: "01".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2026-04-01T00:00:00Z".into(),
        issued_by: "live-contract-ca".into(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Issued,
    };
    (version, certified.signing_key.serialize_pem())
}

#[tokio::test]
#[ignore = "talks to a real Kubernetes API server and mutates live Secrets"]
async fn live_kubernetes_secret_sink_full_lifecycle() {
    let Some(config) = config() else {
        eprintln!("{SKIP_MESSAGE}");
        return;
    };
    let name = format!("acmex-live-{}", jiff::Timestamp::now().as_second());
    let staging_name = format!("staging-{name}");
    println!("live secret name: {name} (namespace {})", config.namespace);

    // The token is either an already-resolved value or a `env:`/`file:`
    // SecretRef, matching the sink's no-literal-token convention.
    let auth = if config.token.starts_with("env:") || config.token.starts_with("file:") {
        KubernetesAuth::Resolved {
            reference: SecretRef::parse(&config.token).expect("valid SecretRef"),
            resolver: std::sync::Arc::new(EnvFileSecretResolver),
        }
    } else {
        KubernetesAuth::Token(config.token.clone())
    };
    let sink = KubernetesSecretSink::new(
        KubernetesSecretConfig {
            endpoint: Some(config.endpoint.clone()),
            namespace: config.namespace.clone(),
            ca_path: Some(config.ca_path.clone()),
            ..KubernetesSecretConfig::default()
        },
        auth,
    )
    .expect("sink construction with explicit endpoint and CA");
    assert_eq!(sink.namespace(), config.namespace);

    let lineage_id = LineageId::generate();
    let (old_version, old_key) = sample_version(&lineage_id, "old.live.example.com");
    let (new_version, new_key) = sample_version(&lineage_id, "new.live.example.com");
    let old_material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&old_version, Some(SecretBytes::new(old_key)))
        .unwrap();
    let new_material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&new_version, Some(SecretBytes::new(new_key)))
        .unwrap();
    let spec = DeploymentSpec {
        target_id: TargetId::new("live-k8s").unwrap(),
        kind: DeliveryTargetKind::KubernetesSecret,
        reference: name.clone(),
        requirement: acmex::domain::DeliveryRequirement::Required,
    };
    let old_sha = old_material.leaf_sha256.clone();
    let new_sha = new_material.leaf_sha256.clone();

    // ---- Phase 1: stage + activate the previous (rollback baseline).
    let old_staged = sink
        .stage(
            &spec,
            &old_version,
            CertificateMaterialRef {
                material: &old_material,
            },
        )
        .await
        .expect("stage previous version");
    assert_eq!(old_staged.resource_version, 0, "no target existed yet");
    assert!(
        kubectl_json(&config.namespace, &staging_name).is_some(),
        "kubectl sees the staging secret"
    );
    assert!(
        kubectl_json(&config.namespace, &name).is_none(),
        "target untouched by stage"
    );
    sink.activate(&old_staged)
        .await
        .expect("activate previous version");
    assert_eq!(
        kubectl_secret_type(&config.namespace, &name).as_deref(),
        Some("kubernetes.io/tls"),
        "kubectl cross-check: target Secret has the native TLS type"
    );
    assert_eq!(
        kubectl_leaf_sha(&config.namespace, &name).as_deref(),
        Some(old_sha.as_str()),
        "kubectl cross-check: target serves the previous certificate"
    );
    println!("kubectl cross-check after activate: type=kubernetes.io/tls leaf_sha256={old_sha}");
    assert_eq!(
        sink.health_check(&old_staged).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // ---- Phase 2: stage + activate the new version (target switch).
    let new_staged = sink
        .stage(
            &spec,
            &new_version,
            CertificateMaterialRef {
                material: &new_material,
            },
        )
        .await
        .expect("stage new version");
    assert!(
        new_staged.previous_active_ref.is_some(),
        "snapshot recorded for rollback"
    );
    sink.activate(&new_staged)
        .await
        .expect("activate new version");
    assert_eq!(
        kubectl_leaf_sha(&config.namespace, &name).as_deref(),
        Some(new_sha.as_str()),
        "kubectl cross-check: target switched to the new certificate"
    );
    println!(
        "kubectl cross-check after switch: leaf_sha256={new_sha} (staged fingerprint matched)"
    );
    assert_eq!(
        sink.health_check(&new_staged).await.unwrap(),
        DeploymentHealth::Healthy,
        "health check Healthy right after activate"
    );

    // ---- Phase 3: external tamper → Unhealthy.
    kubectl_tamper_tls_crt(&config.namespace, &name, &old_material.cert_pem);
    assert_eq!(
        kubectl_leaf_sha(&config.namespace, &name).as_deref(),
        Some(old_sha.as_str()),
        "kubectl cross-check: tamper really replaced tls.crt out of band"
    );
    match sink.health_check(&new_staged).await.unwrap() {
        DeploymentHealth::Unhealthy(reason) => {
            println!("tampered target correctly reported Unhealthy: {reason}");
        }
        other => panic!("expected Unhealthy after tamper, got {other:?}"),
    }

    // ---- Phase 4: rollback restores the stage-time snapshot.
    sink.rollback(&new_staged)
        .await
        .expect("rollback to the pre-activation snapshot");
    assert_eq!(
        kubectl_leaf_sha(&config.namespace, &name).as_deref(),
        Some(old_sha.as_str()),
        "kubectl cross-check: rollback restored the previous certificate"
    );
    println!("kubectl cross-check after rollback: leaf_sha256={old_sha} (snapshot restored)");
    assert_eq!(
        sink.health_check(&old_staged).await.unwrap(),
        DeploymentHealth::Healthy,
        "health check recovers after rollback"
    );

    // ---- Phase 5: cleanup removes the staging slot (idempotent).
    assert_eq!(
        sink.cleanup(&new_staged).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert!(kubectl_json(&config.namespace, &staging_name).is_none());
    assert_eq!(
        sink.cleanup(&old_staged).await.unwrap(),
        CleanupOutcome::AlreadyClean,
        "cleanup is idempotent across staged handles of the same slot"
    );

    // ---- Leave no residue behind.
    kubectl_delete_secret(&config.namespace, &name);
    assert!(
        kubectl_json(&config.namespace, &name).is_none(),
        "test secret removed from the namespace"
    );
    println!(
        "✅ live Kubernetes Secret sink contract passed against {} (namespace {})",
        config.endpoint, config.namespace
    );
}
