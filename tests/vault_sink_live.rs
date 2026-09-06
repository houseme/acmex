//! Live Vault KV v2 sink contract (roadmap T20) — `#[ignore]`d because it
//! talks to a real Vault server and mutates real KV entries.
//!
//! Live counterpart of the mock coverage in
//! `tests/certificate_sink_contract.rs` for `VaultKvSink`: the full five-phase
//! lifecycle (stage → activate → health → tamper → rollback → cleanup) runs
//! against an actual server, and every phase is cross-checked over the raw
//! Vault HTTP API (`GET/PUT /v1/<mount>/data/<path>` via `reqwest` with the
//! token header), independent of the sink's own code paths.
//!
//! Configuration (all via environment):
//!
//! ```text
//! ACMEX_LIVE_VAULT_ENDPOINT=http://127.0.0.1:8210  # Vault base URL
//! ACMEX_LIVE_VAULT_TOKEN=...                       # token, or `env:`/`file:` SecretRef
//! ACMEX_LIVE_VAULT_MOUNT=acmex-live                # KV v2 mount (default below)
//! ```
//!
//! Setup used for the recorded evidence run (throwaway dev server, in-memory):
//!
//! ```text
//! curl -fsSL -o /tmp/vault.zip https://releases.hashicorp.com/vault/1.20.0/vault_1.20.0_darwin_arm64.zip
//! # SHA256SUMS verified before unpacking
//! vault server -dev -dev-root-token-id=<throwaway> -dev-listen-address=127.0.0.1:8210
//! vault secrets enable -path=acmex-live kv-v2
//! ```
//!
//! Run: `cargo test --test vault_sink_live -- --ignored --nocapture`
//!
//! The test writes under the unique path `acmex-live-<unix_ts>` (plus the
//! `-staging` twin) and hard-deletes both metadata entries at the end; the
//! token is never printed. A missing environment variable prints an explicit
//! SKIP line — that counts as *no evidence collected*, never as a pass.

use acmex::dns::spec::{EnvFileSecretResolver, SecretRef};
use acmex::domain::{
    DeliveryTargetKind, IdentifierSet, KeyAlgorithm, KeyId, KeyRef, LineageId, TargetId, VersionId,
    VersionState,
};
use acmex::{
    CertificateMaterialBuilder, CertificateMaterialRef, CertificateSink, CertificateVersion,
    CleanupOutcome, DeploymentHealth, DeploymentSpec, SecretBytes, VaultAuth, VaultKvConfig,
    VaultKvSink,
};
use serde_json::{Value, json};

const SKIP_MESSAGE: &str = "SKIP: set ACMEX_LIVE_VAULT_ENDPOINT and ACMEX_LIVE_VAULT_TOKEN \
(value or env:/file: SecretRef) against a throwaway Vault server with a KV v2 mount \
(ACMEX_LIVE_VAULT_MOUNT, default acmex-live) to collect live Vault sink evidence";

struct LiveVaultConfig {
    endpoint: String,
    mount: String,
    token: String,
}

fn config() -> Option<LiveVaultConfig> {
    let endpoint = std::env::var("ACMEX_LIVE_VAULT_ENDPOINT").ok()?;
    let token = std::env::var("ACMEX_LIVE_VAULT_TOKEN").ok()?;
    let mount =
        std::env::var("ACMEX_LIVE_VAULT_MOUNT").unwrap_or_else(|_| "acmex-live".to_string());
    Some(LiveVaultConfig {
        endpoint,
        mount,
        token,
    })
}

/// The raw cross-check helpers speak the Vault HTTP API directly, so a
/// `env:`/`file:` SecretRef token must be resolved the same way the sink's
/// `EnvFileSecretResolver` would resolve it.
fn resolve_token_reference(token: &str) -> String {
    if let Some(path) = token.strip_prefix("file:") {
        std::fs::read_to_string(path)
            .expect("read file: secret reference")
            .trim()
            .to_owned()
    } else if let Some(name) = token.strip_prefix("env:") {
        std::env::var(name).expect("read env: secret reference")
    } else {
        token.to_owned()
    }
}

fn data_url(endpoint: &str, mount: &str, path: &str) -> String {
    format!("{endpoint}/v1/{mount}/data/{path}")
}

fn metadata_url(endpoint: &str, mount: &str, path: &str) -> String {
    format!("{endpoint}/v1/{mount}/metadata/{path}")
}

/// Independent read path: raw `GET /v1/<mount>/data/<path>` with the token
/// header, outside the sink. Returns `(version, leaf_sha256_of_certificate)`.
async fn raw_read(
    client: &reqwest::Client,
    endpoint: &str,
    mount: &str,
    token: &str,
    path: &str,
) -> Option<(u64, String)> {
    let response = client
        .get(data_url(endpoint, mount, path))
        .header("X-Vault-Token", token)
        .send()
        .await
        .expect("vault raw GET");
    if !response.status().is_success() {
        println!("raw GET {path}: HTTP {}", response.status());
        return None;
    }
    let body: Value = response.json().await.expect("vault JSON body");
    let data = &body["data"];
    let version = data["metadata"]["version"].as_u64()?;
    let certificate = data["data"]["certificate"].as_str()?;
    Some((version, pem_leaf_sha(certificate)))
}

/// Out-of-band write path: replaces the `certificate` field through the raw
/// API, simulating an operator/attacker change the sink must detect.
async fn raw_write_certificate(
    client: &reqwest::Client,
    endpoint: &str,
    mount: &str,
    token: &str,
    path: &str,
    replacement_pem: &str,
) {
    let response = client
        .put(data_url(endpoint, mount, path))
        .header("X-Vault-Token", token)
        .json(&json!({ "data": { "certificate": replacement_pem } }))
        .send()
        .await
        .expect("vault raw PUT");
    assert!(
        response.status().is_success(),
        "raw tamper write failed: HTTP {}",
        response.status()
    );
}

/// Hard-deletes both the metadata (full version history) of a path.
async fn raw_delete_metadata(
    client: &reqwest::Client,
    endpoint: &str,
    mount: &str,
    token: &str,
    path: &str,
) {
    let response = client
        .delete(metadata_url(endpoint, mount, path))
        .header("X-Vault-Token", token)
        .send()
        .await
        .expect("vault raw DELETE");
    println!("raw DELETE metadata {path}: HTTP {}", response.status());
}

fn pem_leaf_sha(pem_text: &str) -> String {
    use sha2::Digest;
    let blocks = pem::parse_many(pem_text.as_bytes()).expect("parse PEM");
    let leaf = blocks
        .iter()
        .find(|block| block.tag() == "CERTIFICATE")
        .expect("PEM has a CERTIFICATE block");
    hex::encode(sha2::Sha256::digest(leaf.contents()))
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
#[ignore = "talks to a real Vault server and mutates live KV entries"]
async fn live_vault_kv_sink_full_lifecycle() {
    let Some(config) = config() else {
        eprintln!("{SKIP_MESSAGE}");
        return;
    };
    let path = format!("acmex-live-{}", jiff::Timestamp::now().as_second());
    let staging_path = format!("{path}-staging");
    println!("live kv path: {path} (mount {})", config.mount);

    let client = reqwest::Client::new();
    let raw_token = resolve_token_reference(&config.token);
    // Sanity: the mount must actually be a KV v2 engine before staging.
    let mount_probe = client
        .get(format!(
            "{}/v1/sys/mounts/{}",
            config.endpoint, config.mount
        ))
        .header("X-Vault-Token", &raw_token)
        .send()
        .await
        .expect("probe mount tuning");
    assert!(
        mount_probe.status().is_success(),
        "mount `{}` is not readable (HTTP {})",
        config.mount,
        mount_probe.status()
    );
    let mount_tuning: Value = mount_probe.json().await.expect("mount tuning JSON");
    assert_eq!(
        mount_tuning["data"]["options"]["version"], "2",
        "mount must be KV v2"
    );

    // The token is either an already-resolved value or a `env:`/`file:`
    // SecretRef, matching the sink's no-literal-token convention.
    let auth = if config.token.starts_with("env:") || config.token.starts_with("file:") {
        VaultAuth::Resolved {
            reference: SecretRef::parse(&config.token).expect("valid SecretRef"),
            resolver: std::sync::Arc::new(EnvFileSecretResolver),
        }
    } else {
        VaultAuth::Token(config.token.clone())
    };
    let sink = VaultKvSink::new(
        VaultKvConfig {
            endpoint: config.endpoint.clone(),
            mount: config.mount.clone(),
            ..VaultKvConfig::default()
        },
        auth,
    )
    .expect("sink construction");
    assert_eq!(sink.mount(), config.mount);

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
        target_id: TargetId::new("live-vault").unwrap(),
        kind: DeliveryTargetKind::VaultKv,
        reference: path.clone(),
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
    assert_eq!(
        old_staged.resource_version, 0,
        "no active entry existed yet"
    );
    assert!(
        raw_read(&client, &config.endpoint, &config.mount, &raw_token, &path)
            .await
            .is_none(),
        "raw cross-check: active path untouched by stage"
    );
    let (staging_version, staging_sha) = raw_read(
        &client,
        &config.endpoint,
        &config.mount,
        &raw_token,
        &staging_path,
    )
    .await
    .expect("raw cross-check: staging entry exists after stage");
    // Phase 1 stages the previous material, so the shared staging slot must
    // carry the old fingerprint here (it only switches to the new one in
    // phase 2).
    assert_eq!(
        staging_sha, old_sha,
        "staging entry carries the staged (previous) fingerprint"
    );
    println!(
        "raw cross-check after stage: {staging_path} version={staging_version} leaf_sha256={staging_sha}"
    );
    sink.activate(&old_staged)
        .await
        .expect("activate previous version");
    let (active_version, active_sha) =
        raw_read(&client, &config.endpoint, &config.mount, &raw_token, &path)
            .await
            .expect("raw cross-check: active entry exists after activate");
    assert_eq!(
        active_sha, old_sha,
        "raw cross-check: active serves the previous certificate"
    );
    println!(
        "raw cross-check after activate: {path} version={active_version} leaf_sha256={active_sha}"
    );
    assert_eq!(
        sink.health_check(&old_staged).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // ---- Phase 2: stage + activate the new version (CAS-guarded switch).
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
    assert_eq!(
        new_staged.resource_version, active_version,
        "CAS base equals the active version observed at stage time"
    );
    assert!(new_staged.previous_active_ref.is_some());
    sink.activate(&new_staged)
        .await
        .expect("activate new version");
    let (switched_version, switched_sha) =
        raw_read(&client, &config.endpoint, &config.mount, &raw_token, &path)
            .await
            .expect("raw cross-check after switch");
    assert_eq!(
        switched_sha, new_sha,
        "raw cross-check: switched to the new certificate"
    );
    println!(
        "raw cross-check after switch: {path} version={switched_version} leaf_sha256={switched_sha}"
    );
    assert_eq!(
        sink.health_check(&new_staged).await.unwrap(),
        DeploymentHealth::Healthy,
        "health check Healthy right after activate"
    );

    // ---- Phase 3: external tamper → Unhealthy.
    raw_write_certificate(
        &client,
        &config.endpoint,
        &config.mount,
        &raw_token,
        &path,
        &old_material.cert_pem,
    )
    .await;
    let (tampered_version, tampered_sha) =
        raw_read(&client, &config.endpoint, &config.mount, &raw_token, &path)
            .await
            .expect("raw cross-check after tamper");
    assert_eq!(
        tampered_sha, old_sha,
        "raw cross-check: tamper really replaced the certificate field"
    );
    println!(
        "raw cross-check after tamper: {path} version={tampered_version} leaf_sha256={tampered_sha}"
    );
    match sink.health_check(&new_staged).await.unwrap() {
        DeploymentHealth::Unhealthy(reason) => {
            println!("tampered entry correctly reported Unhealthy: {reason}");
        }
        other => panic!("expected Unhealthy after tamper, got {other:?}"),
    }

    // ---- Phase 4: rollback restores the stage-time version.
    sink.rollback(&new_staged)
        .await
        .expect("rollback to the stage-time version");
    let (restored_version, restored_sha) =
        raw_read(&client, &config.endpoint, &config.mount, &raw_token, &path)
            .await
            .expect("raw cross-check after rollback");
    assert_eq!(
        restored_sha, old_sha,
        "raw cross-check: rollback restored the previous certificate"
    );
    println!(
        "raw cross-check after rollback: {path} version={restored_version} leaf_sha256={restored_sha} (KV v2 history preserved the snapshot)"
    );
    assert_eq!(
        sink.health_check(&old_staged).await.unwrap(),
        DeploymentHealth::Healthy,
        "health check recovers after rollback"
    );

    // ---- Phase 5: cleanup hard-deletes the staging path (idempotent).
    assert_eq!(
        sink.cleanup(&new_staged).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert!(
        raw_read(
            &client,
            &config.endpoint,
            &config.mount,
            &raw_token,
            &staging_path
        )
        .await
        .is_none(),
        "raw cross-check: staging path is gone"
    );
    assert_eq!(
        sink.cleanup(&old_staged).await.unwrap(),
        CleanupOutcome::Cleaned,
        "cleanup is idempotent across staged handles of the same slot; Vault \
         answers 204 for a metadata DELETE even when the path is already gone, \
         so the sink reports Cleaned — the raw 404 above proves the slot is \
         actually absent (AlreadyClean is unobservable on KV v2)"
    );

    // ---- Leave no residue behind (hard-delete history of the active path).
    raw_delete_metadata(&client, &config.endpoint, &config.mount, &raw_token, &path).await;
    assert!(
        raw_read(&client, &config.endpoint, &config.mount, &raw_token, &path)
            .await
            .is_none(),
        "test entry removed from the mount"
    );
    println!(
        "✅ live Vault KV v2 sink contract passed against {} (mount {})",
        config.endpoint, config.mount
    );
}
