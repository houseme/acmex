//! HashiCorp Vault KV v2 sink: delivers certificate material as KV entries.
//!
//! Endpoints used (KV v2 secret engine, `<mount>` configured):
//!
//! * `PUT    /v1/<mount>/data/<path>`          — write (with CAS via `options.cas`)
//! * `GET    /v1/<mount>/data/<path>?version=N` — read latest or a specific version
//! * `PUT    /v1/<mount>/delete/<path>`        — soft delete (rollback to "nothing")
//! * `DELETE /v1/<mount>/metadata/<path>`      — hard delete (staging cleanup)
//!
//! Contract:
//!
//! * `stage` — observes the active entry's version (the future CAS base and
//!   rollback point; KV v2 keeps version history so the content does not need
//!   to be duplicated) and writes the new material to `<path>-staging`.
//!   Idempotent: staging writes are last-writer-wins on the same path.
//! * `activate` — first verifies the staging entry still carries the staged
//!   fingerprint (SHA-256 of the `certificate` field): the path is shared per
//!   target and a newer stage overwrites it, so a mismatch is the retryable
//!   `Conflict` class instead of promoting foreign material. It then
//!   CAS-writes the active path with `options.cas` equal to the version
//!   observed at stage time, so a concurrent activation is detected instead
//!   of overwritten (Vault reports a mismatch as HTTP 400 with a
//!   "check-and-set" marker, surfaced as the retryable `Conflict` class).
//!   Idempotent: a CAS loss converges to success when the target already
//!   serves the staged fingerprint.
//! * `health_check` — reads the active entry and compares the SHA-256 of the
//!   `certificate` field (leaf PEM) with the staged fingerprint. Reachable
//!   but wrong is `Unhealthy`; unreachable, unauthorized or absent is
//!   `Unknown` so transient conditions never trigger rollbacks.
//! * `rollback` — rewrites the version recorded at stage time (guarded by a
//!   fresh CAS); when nothing was active before, the active entry is soft
//!   deleted instead. Idempotent: repeated rollbacks append identical
//!   restore versions.
//! * `cleanup` — hard deletes the staging path (absent counts as clean).
//!
//! The Vault token is supplied as an already-resolved value or resolved
//! lazily through a [`SecretResolver`] (`env:`/`file:`/`vault:`/`provider:`
//! references — never literals), matching `src/dns/factory.rs`.
//!
//! mount: add `pub mod vault_sink;` to `src/delivery/mod.rs` and re-export
//! `VaultKvSink` (plus its config/auth types) from the crate root;
//! registration happens via `DeploymentOrchestrator::register_sink`.

// mount: 在 delivery/mod.rs 加 pub mod k8s_sink; pub mod vault_sink;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::dns::spec::{SecretRef, SecretResolver};
use crate::domain::{CertificateVersion, DeliveryTargetKind};
use crate::error::{AcmeError, Result};

use super::{
    CertificateMaterialRef, CertificateSink, CleanupOutcome, DeploymentHealth, DeploymentSpec,
    StagedDeployment,
};

/// Suffix of the staging path that mirrors the active path.
const STAGING_SUFFIX: &str = "-staging";
/// Marker Vault puts into HTTP 400 bodies when a KV v2 CAS check fails.
const CAS_ERROR_MARKER: &str = "check-and-set";

const KEY_CERTIFICATE: &str = "certificate";
const KEY_PRIVATE_KEY: &str = "private_key";
const KEY_FULLCHAIN: &str = "fullchain";
const KEY_METADATA: &str = "metadata";

/// Connection settings for the Vault server.
#[derive(Debug, Clone)]
pub struct VaultKvConfig {
    /// Vault base URL (e.g. `https://vault.internal:8200`).
    pub endpoint: String,
    /// KV v2 engine mount (e.g. `secret`).
    pub mount: String,
    /// Enterprise namespace sent as `X-Vault-Namespace` (optional).
    pub namespace: Option<String>,
    /// TCP connect timeout.
    pub connect_timeout_secs: u64,
    /// Whole-request timeout (connect and request timeouts are both set).
    pub request_timeout_secs: u64,
}

impl Default for VaultKvConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:8200".to_string(),
            mount: "secret".to_string(),
            namespace: None,
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        }
    }
}

/// Authentication for the Vault server.
pub enum VaultAuth {
    /// Already-resolved token (kept out of `Debug` output).
    Token(String),
    /// Resolve the reference before each request (supports token rotation).
    Resolved {
        /// Secret reference (`env:`/`file:`/`vault:`/`provider:`).
        reference: SecretRef,
        /// Resolver that turns the reference into a token.
        resolver: Arc<dyn SecretResolver>,
    },
}

impl fmt::Debug for VaultAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.write_str("VaultAuth::Token(**redacted**)"),
            Self::Resolved { reference, .. } => f
                .debug_struct("VaultAuth::Resolved")
                .field("reference", &reference.describe())
                .finish(),
        }
    }
}

/// Delivers certificate material to Vault KV v2 entries.
///
/// Every operation is idempotent and safe to call concurrently (`&self`
/// only). The token is resolved per request and never appears in `Debug`
/// output, error messages or logs.
pub struct VaultKvSink {
    endpoint: String,
    mount: String,
    namespace: Option<String>,
    client: reqwest::Client,
    auth: VaultAuth,
}

impl fmt::Debug for VaultKvSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKvSink")
            .field("endpoint", &self.endpoint)
            .field("mount", &self.mount)
            .field("auth", &"**redacted**")
            .finish_non_exhaustive()
    }
}

impl VaultKvSink {
    /// Builds a sink for the KV v2 mount at `config`.
    pub fn new(config: VaultKvConfig, auth: VaultAuth) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("acmex/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs.max(1)))
            .timeout(Duration::from_secs(config.request_timeout_secs.max(1)))
            .build()
            .map_err(|err| AcmeError::configuration(format!("vault HTTP client: {err}")))?;
        Ok(Self {
            endpoint: config.endpoint.trim_end_matches('/').to_owned(),
            mount: config.mount,
            namespace: config.namespace,
            client,
            auth,
        })
    }

    /// The KV v2 mount this sink writes into.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    fn data_url(&self, path: &str) -> String {
        format!("{}/v1/{}/data/{}", self.endpoint, self.mount, path)
    }

    fn metadata_url(&self, path: &str) -> String {
        format!("{}/v1/{}/metadata/{}", self.endpoint, self.mount, path)
    }

    fn soft_delete_url(&self, path: &str) -> String {
        format!("{}/v1/{}/delete/{}", self.endpoint, self.mount, path)
    }

    /// Resolves the Vault token; failures name the reference, never the value.
    async fn token(&self) -> Result<String> {
        match &self.auth {
            VaultAuth::Token(token) => Ok(token.clone()),
            VaultAuth::Resolved {
                reference,
                resolver,
            } => {
                let value = resolver.resolve(reference).await?;
                value.expose_utf8().map(str::to_owned).ok_or_else(|| {
                    AcmeError::configuration(format!(
                        "secret {} is not valid UTF-8",
                        reference.describe()
                    ))
                })
            }
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<String>,
    ) -> Result<reqwest::Response> {
        let token = self.token().await?;
        let mut builder = self
            .client
            .request(method, url)
            .header("X-Vault-Token", token);
        if let Some(namespace) = self.namespace.as_ref() {
            builder = builder.header("X-Vault-Namespace", namespace);
        }
        if body.is_some() {
            builder = builder.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        builder
            .body(body.unwrap_or_default())
            .send()
            .await
            .map_err(|err| AcmeError::transport(format!("vault request failed: {err}")))
    }

    /// Reads an entry; `Ok(None)` for 404 (also covers soft-deleted latest).
    async fn read_kv(
        &self,
        path: &str,
        version: Option<u64>,
    ) -> Result<Option<(u64, Map<String, Value>)>> {
        let mut url = self.data_url(path);
        if let Some(version) = version {
            url.push_str(&format!("?version={version}"));
        }
        let response = self.send(reqwest::Method::GET, &url, None).await?;
        match response.status().as_u16() {
            200 => {
                let parsed: KvRead = response.json().await.map_err(|err| {
                    AcmeError::transport(format!("vault kv `{path}` body is invalid: {err}"))
                })?;
                let version = parsed
                    .data
                    .metadata
                    .and_then(|meta| meta.version)
                    .unwrap_or(0);
                let data = parsed.data.data.unwrap_or_default();
                Ok(Some((version, data)))
            }
            404 => Ok(None),
            status => Err(classify_status(status, "read", path)),
        }
    }

    async fn require_kv(&self, path: &str) -> Result<(u64, Map<String, Value>)> {
        self.read_kv(path, None)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("vault kv `{path}` is missing")))
    }

    /// Writes an entry. `cas` turns the write into a KV v2 check-and-set:
    /// the write only applies when `cas` equals the current version
    /// (`Some(0)` enforces "entry must not exist yet"). Vault reports a CAS
    /// mismatch as HTTP 400 with the marker body, classified as `Conflict`.
    async fn write_kv(
        &self,
        path: &str,
        data: &Map<String, Value>,
        cas: Option<u64>,
    ) -> Result<()> {
        let mut payload = Map::new();
        payload.insert("data".to_string(), Value::Object(data.clone()));
        if let Some(cas) = cas {
            payload.insert("options".to_string(), serde_json::json!({ "cas": cas }));
        }
        let response = self
            .send(
                reqwest::Method::PUT,
                &self.data_url(path),
                Some(Value::Object(payload).to_string()),
            )
            .await?;
        let status = response.status();
        if status.as_u16() == 400 {
            let body = response.text().await.unwrap_or_default();
            if body.contains(CAS_ERROR_MARKER) {
                return Err(AcmeError::conflict(format!(
                    "vault CAS mismatch writing `{path}`: a concurrent writer created a newer version; safe to retry"
                )));
            }
            return Err(AcmeError::invalid_input(format!(
                "vault rejected the write to `{path}`: HTTP 400"
            )));
        }
        let status = status.as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(classify_status(status, "write", path))
        }
    }

    /// Soft delete keeps the version history but hides every version.
    async fn soft_delete_kv(&self, path: &str) -> Result<()> {
        let response = self
            .send(reqwest::Method::PUT, &self.soft_delete_url(path), None)
            .await?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(classify_status(status, "rollback", path))
        }
    }

    /// Hard delete of a path's metadata (staging cleanup only).
    async fn delete_metadata(&self, path: &str) -> Result<CleanupOutcome> {
        let response = self
            .send(reqwest::Method::DELETE, &self.metadata_url(path), None)
            .await?;
        match response.status().as_u16() {
            200..=299 => Ok(CleanupOutcome::Cleaned),
            404 => Ok(CleanupOutcome::AlreadyClean),
            status => Err(classify_status(status, "cleanup", path)),
        }
    }

    /// Extracts the staging path from a `vault://<mount>/<path>` staged
    /// reference and validates the mount.
    fn staged_kv_path<'a>(&self, staged_ref: &'a str) -> Result<&'a str> {
        let rest = staged_ref.strip_prefix("vault://").ok_or_else(|| {
            AcmeError::invalid_input("vault staged reference must start with vault://")
        })?;
        let (mount, path) = rest.split_once('/').ok_or_else(|| {
            AcmeError::invalid_input("vault staged reference must be vault://<mount>/<path>")
        })?;
        if mount != self.mount {
            return Err(AcmeError::invalid_input(format!(
                "staged reference mount `{mount}` does not match sink mount `{}`",
                self.mount
            )));
        }
        Ok(path)
    }

    /// The active path that belongs to a staged reference.
    fn active_path<'a>(&self, staged_ref: &'a str) -> Result<&'a str> {
        let staging_path = self.staged_kv_path(staged_ref)?;
        staging_path
            .strip_suffix(STAGING_SUFFIX)
            .ok_or_else(|| AcmeError::invalid_input("vault staged reference is not a staging path"))
    }
}

#[async_trait]
impl CertificateSink for VaultKvSink {
    /// Observes the active version (CAS base + rollback point) and writes the
    /// new material to `<path>-staging`. Idempotent: re-staging overwrites the
    /// same staging path; the active entry is never touched.
    #[tracing::instrument(skip(self, spec, version, material), fields(version_id = %version.id, target_id = %spec.target_id))]
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment> {
        if spec.kind != DeliveryTargetKind::VaultKv {
            return Err(AcmeError::invalid_input(
                "vault sink requires a vault_kv target",
            ));
        }
        let path = kv_path(&spec.reference)?;
        let staging_path = format!("{path}{STAGING_SUFFIX}");
        let previous_version = match self.read_kv(path, None).await? {
            Some((version, _)) => version,
            None => 0,
        };

        let mut data = Map::new();
        data.insert(
            KEY_CERTIFICATE.to_string(),
            Value::String(material.material.cert_pem.clone()),
        );
        data.insert(
            KEY_FULLCHAIN.to_string(),
            Value::String(material.material.fullchain_pem.clone()),
        );
        if let Some(key) = material.material.private_key_pem.as_ref() {
            let pem = std::str::from_utf8(key.expose_secret())
                .map_err(|err| AcmeError::pem(format!("private key is not UTF-8 PEM: {err}")))?;
            data.insert(KEY_PRIVATE_KEY.to_string(), Value::String(pem.to_owned()));
        }
        let metadata = serde_json::json!({
            "version_id": version.id.as_str(),
            "lineage_id": version.lineage_id.as_str(),
            "target_id": spec.target_id.as_str(),
            "leaf_sha256": material.material.leaf_sha256,
            "key_provider": version.key_ref.provider,
            "key_id": version.key_ref.key_id.as_str(),
            "staged_at": Timestamp::now().to_string(),
        });
        data.insert(
            KEY_METADATA.to_string(),
            Value::String(metadata.to_string()),
        );

        self.write_kv(&staging_path, &data, None).await?;

        Ok(StagedDeployment {
            kind: spec.kind,
            target_id: spec.target_id.clone(),
            version_id: version.id.clone(),
            staged_ref: format!("vault://{}/{}", self.mount, staging_path),
            previous_active_ref: (previous_version > 0)
                .then(|| format!("vault://{}/{}", self.mount, path)),
            leaf_sha256: material.material.leaf_sha256.clone(),
            resource_version: previous_version,
        })
    }

    /// CAS-writes the active path (`options.cas` = version observed at stage
    /// time). Before writing, verifies the staging entry still carries the
    /// staged fingerprint: the staging path is shared per target and a newer
    /// stage overwrites it, so a mismatch is the retryable `Conflict` class
    /// instead of promoting foreign material. Idempotent: an already-serving
    /// target converges to success; a lost CAS race is the retryable
    /// `Conflict` class.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let staging_path = self.staged_kv_path(&staged.staged_ref)?;
        let path = self.active_path(&staged.staged_ref)?;
        let (_, data) = self.require_kv(staging_path).await?;
        let staged_leaf_sha = kv_leaf_sha(&data).ok_or_else(|| {
            AcmeError::conflict(format!(
                "vault staging entry `{staging_path}` has no certificate field; \
                 it was overwritten by a non-acmex writer; re-stage and retry"
            ))
        })?;
        if staged_leaf_sha != staged.leaf_sha256 {
            return Err(AcmeError::conflict(format!(
                "vault staging entry `{staging_path}` was overwritten by a newer stage \
                 (fingerprint mismatch); re-stage and retry"
            )));
        }
        match self
            .write_kv(path, &data, Some(staged.resource_version))
            .await
        {
            Ok(()) => Ok(()),
            Err(err) if is_conflict(&err) => {
                // Lost the CAS race: converge only when the concurrent writer
                // activated the same material.
                match self.read_kv(path, None).await? {
                    Some((_, current))
                        if kv_leaf_sha(&current).as_deref()
                            == Some(staged.leaf_sha256.as_str()) =>
                    {
                        Ok(())
                    }
                    _ => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Reads the active entry and compares the `certificate` field's leaf
    /// SHA-256 with the staged fingerprint. Reachable-but-wrong is
    /// `Unhealthy`; unreachable, unauthorized or absent is `Unknown` so
    /// transient conditions never trigger rollbacks.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let path = self.active_path(&staged.staged_ref)?;
        match self.read_kv(path, None).await {
            Ok(Some((_, data))) => match kv_leaf_sha(&data) {
                Some(sha) if sha == staged.leaf_sha256 => Ok(DeploymentHealth::Healthy),
                Some(_) => Ok(DeploymentHealth::Unhealthy(
                    "active vault entry serves a different certificate".into(),
                )),
                None => Ok(DeploymentHealth::Unhealthy(
                    "active vault entry has no certificate field".into(),
                )),
            },
            Ok(None) => Ok(DeploymentHealth::Unknown(format!(
                "active vault entry `{path}` is absent"
            ))),
            Err(err) => Ok(DeploymentHealth::Unknown(format!(
                "vault unreachable: {err}"
            ))),
        }
    }

    /// Restores the version recorded at stage time under a fresh CAS guard.
    /// Idempotent: repeated rollbacks append identical restore versions;
    /// when nothing was active before, the entry is soft deleted.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let path = self.active_path(&staged.staged_ref)?;
        let current_version = match self.read_kv(path, None).await? {
            Some((version, _)) => version,
            None => 0,
        };
        if staged.resource_version == 0 {
            // Nothing was active before staging: roll back to "no entry".
            return self.soft_delete_kv(path).await;
        }
        let (_, previous) = self
            .read_kv(path, Some(staged.resource_version))
            .await?
            .ok_or_else(|| {
                AcmeError::not_found(format!(
                    "vault kv `{path}` version {} is missing (history pruned?)",
                    staged.resource_version
                ))
            })?;
        self.write_kv(path, &previous, Some(current_version)).await
    }

    /// Hard deletes the staging path. Idempotent: an absent staging path is
    /// `AlreadyClean`.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome> {
        let staging_path = self.staged_kv_path(&staged.staged_ref)?;
        self.delete_metadata(staging_path).await
    }
}

/// Wire shape of a KV v2 read response.
#[derive(Debug, Deserialize)]
struct KvRead {
    data: KvReadData,
}

#[derive(Debug, Deserialize)]
struct KvReadData {
    #[serde(default)]
    data: Option<Map<String, Value>>,
    #[serde(default)]
    metadata: Option<KvReadMeta>,
}

#[derive(Debug, Deserialize)]
struct KvReadMeta {
    #[serde(default)]
    version: Option<u64>,
}

/// SHA-256 of the leaf certificate stored under `certificate`.
fn kv_leaf_sha(data: &Map<String, Value>) -> Option<String> {
    let pem = data.get(KEY_CERTIFICATE)?.as_str()?;
    leaf_sha256_from_pem(pem.as_bytes())
}

fn leaf_sha256_from_pem(pem_bytes: &[u8]) -> Option<String> {
    let blocks = pem::parse_many(pem_bytes).ok()?;
    let leaf = blocks.iter().find(|block| block.tag() == "CERTIFICATE")?;
    Some(sha256_hex(leaf.contents()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Error classification shared by every API call.
///
/// * 409 → `Conflict` (retryable), 401/403 → `Configuration` (operator action
///   required: token/policy), 5xx → `Transport` (retryable), otherwise
///   `Transport` with the status in the message.
fn classify_status(status: u16, action: &str, path: &str) -> AcmeError {
    match status {
        401 | 403 => AcmeError::configuration(format!(
            "vault {action} on `{path}` rejected with HTTP {status}: token/policy requires operator action"
        )),
        404 => AcmeError::not_found(format!("vault {action}: `{path}` not found")),
        409 => AcmeError::conflict(format!(
            "vault {action} on `{path}` conflicted with a concurrent writer (HTTP 409); safe to retry"
        )),
        500..=599 => AcmeError::transport(format!(
            "vault server error during {action} of `{path}` (HTTP {status}); retryable"
        )),
        status => AcmeError::transport(format!(
            "vault {action} on `{path}` failed with HTTP {status}"
        )),
    }
}

fn is_conflict(err: &AcmeError) -> bool {
    matches!(err, AcmeError::Conflict(_))
}

/// KV paths are relative to the mount; reject empty or malformed references.
fn kv_path(reference: &str) -> Result<&str> {
    let path = reference.trim().trim_start_matches('/');
    let valid = !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'));
    if valid {
        Ok(path)
    } else {
        Err(AcmeError::invalid_input(format!(
            "vault KV reference {reference:?} must be a relative KV v2 path"
        )))
    }
}
