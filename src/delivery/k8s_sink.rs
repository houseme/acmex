//! Kubernetes Secret sink: delivers certificate material as native
//! `kubernetes.io/tls` Secrets through the standard Kubernetes API
//! (see `docs/roadmap/v0.9.0/T10_KEY_PROVIDER_AND_SINKS.md`).
//!
//! Contract:
//!
//! * `stage` — snapshots the active Secret (data, type, annotations) into a
//!   `staging-<name>` Secret together with the new material and never touches
//!   the target. Idempotent: re-staging replaces the same staging Secret.
//! * `activate` — first verifies the staging Secret still carries the staged
//!   fingerprint (`acmex.acme/leaf-sha256`): the slot is shared per target and
//!   a newer stage overwrites it, so a mismatch is the retryable `Conflict`
//!   class instead of promoting foreign material. It then replaces the target
//!   Secret (`tls.crt`/`tls.key`/`ca.crt` plus `acmex.acme/version`
//!   annotations) under `metadata.resourceVersion` optimistic concurrency.
//!   Idempotent: when the target already serves the staged fingerprint it is
//!   a no-op; a 409 is reported as the retryable `Conflict` class unless a
//!   re-read shows the staged material went live concurrently.
//! * `health_check` — GETs the target Secret and compares the SHA-256 of the
//!   decoded leaf certificate with the staged fingerprint. Reachable but
//!   wrong is `Unhealthy`; unreachable, unauthorized or absent is `Unknown`
//!   so transient conditions never trigger rollbacks.
//! * `rollback` — writes the stage-time snapshot back to the target; when no
//!   previous Secret existed the target is deleted instead. A missing staging
//!   Secret is a no-op only when nothing was active before staging; if a
//!   previous Secret existed but its snapshot is gone, the rollback fails so
//!   the operator can investigate. Idempotent.
//! * `cleanup` — deletes the staging Secret (absent counts as clean).
//!
//! Authentication supports in-cluster service accounts (endpoint, token and
//! CA derived from `KUBERNETES_SERVICE_HOST`/`PORT` and
//! `/var/run/secrets/kubernetes.io/serviceaccount`) or an explicit API
//! endpoint. Tokens are either already-resolved values or lazily resolved
//! through a [`SecretResolver`] (`env:`/`file:`/`vault:`/`provider:`
//! references — never literals), matching the conventions of
//! `src/dns/factory.rs`.
//!
//! mount: add `pub mod k8s_sink;` to `src/delivery/mod.rs` and re-export
//! `KubernetesSecretSink` (plus its config/auth types) from the crate root;
//! registration happens via `DeploymentOrchestrator::register_sink`.

// mount: 在 delivery/mod.rs 加 pub mod k8s_sink; pub mod vault_sink;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jiff::Timestamp;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::dns::spec::{SecretRef, SecretResolver};
use crate::domain::{CertificateVersion, DeliveryTargetKind};
use crate::error::{AcmeError, Result};

use super::{
    CertificateMaterial, CertificateMaterialRef, CertificateSink, CleanupOutcome, DeploymentHealth,
    DeploymentSpec, StagedDeployment,
};

/// Prefix of the staging Secret that mirrors the target name.
const STAGING_PREFIX: &str = "staging-";
/// Service account projection mounted inside every pod.
const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
/// Native Kubernetes TLS Secret type.
const TYPE_TLS: &str = "kubernetes.io/tls";
/// Fallback type for keyless material (External CSR deployments).
const TYPE_OPAQUE: &str = "kubernetes.io/opaque";

const ANN_MANAGED_BY: &str = "acmex.acme/managed-by";
const ANN_VERSION: &str = "acmex.acme/version";
const ANN_LEAF_SHA: &str = "acmex.acme/leaf-sha256";
const ANN_TARGET: &str = "acmex.acme/target-secret";
const ANN_STAGED_AT: &str = "acmex.acme/staged-at";
const ANN_PREV_EXISTED: &str = "acmex.acme/previous-existed";
const ANN_PREV_DATA: &str = "acmex.acme/previous-data";
const ANN_PREV_TYPE: &str = "acmex.acme/previous-type";
const ANN_PREV_ANNOTATIONS: &str = "acmex.acme/previous-annotations";

/// Connection settings for the Kubernetes API server.
#[derive(Debug, Clone)]
pub struct KubernetesSecretConfig {
    /// API server base URL. `None` discovers the in-cluster endpoint from
    /// `KUBERNETES_SERVICE_HOST`/`KUBERNETES_SERVICE_PORT` and verifies the
    /// connection with the service account `ca.crt`.
    pub endpoint: Option<String>,
    /// Namespace that owns the target and staging Secrets.
    pub namespace: String,
    /// PEM bundle used to verify the API server; defaults to the in-cluster
    /// `ca.crt` when the endpoint is discovered.
    pub ca_path: Option<PathBuf>,
    /// TCP connect timeout.
    pub connect_timeout_secs: u64,
    /// Whole-request timeout (connect and request timeouts are both set).
    pub request_timeout_secs: u64,
}

impl Default for KubernetesSecretConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            namespace: "default".to_string(),
            ca_path: None,
            connect_timeout_secs: 5,
            request_timeout_secs: 30,
        }
    }
}

/// Authentication for the Kubernetes API server.
pub enum KubernetesAuth {
    /// Already-resolved bearer token (kept out of `Debug` output).
    Token(String),
    /// Resolve the reference before each request (supports token rotation).
    Resolved {
        /// Secret reference (`env:`/`file:`/`vault:`/`provider:`).
        reference: SecretRef,
        /// Resolver that turns the reference into a token.
        resolver: Arc<dyn SecretResolver>,
    },
    /// Read the in-cluster service account token file before each request.
    ServiceAccount,
}

impl fmt::Debug for KubernetesAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.write_str("KubernetesAuth::Token(**redacted**)"),
            Self::Resolved { reference, .. } => f
                .debug_struct("KubernetesAuth::Resolved")
                .field("reference", &reference.describe())
                .finish(),
            Self::ServiceAccount => f.write_str("KubernetesAuth::ServiceAccount"),
        }
    }
}

/// Delivers certificate material to Kubernetes TLS Secrets.
///
/// Every operation is idempotent and safe to call concurrently (`&self`
/// only). The bearer token is resolved per request and never appears in
/// `Debug` output, error messages or logs.
pub struct KubernetesSecretSink {
    endpoint: String,
    namespace: String,
    client: reqwest::Client,
    auth: KubernetesAuth,
}

impl fmt::Debug for KubernetesSecretSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KubernetesSecretSink")
            .field("endpoint", &self.endpoint)
            .field("namespace", &self.namespace)
            .field("auth", &"**redacted**")
            .finish_non_exhaustive()
    }
}

impl KubernetesSecretSink {
    /// Builds a sink from explicit settings.
    pub fn new(config: KubernetesSecretConfig, auth: KubernetesAuth) -> Result<Self> {
        let (endpoint, default_ca) = match config.endpoint {
            Some(url) => (url.trim_end_matches('/').to_owned(), None),
            None => (
                in_cluster_endpoint()?,
                Some(PathBuf::from(format!("{SERVICE_ACCOUNT_DIR}/ca.crt"))),
            ),
        };
        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("acmex/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs.max(1)))
            .timeout(Duration::from_secs(config.request_timeout_secs.max(1)));
        if let Some(ca_path) = config.ca_path.or(default_ca).as_ref() {
            let pem = std::fs::read(ca_path).map_err(|err| {
                AcmeError::configuration(format!("read kubernetes CA {}: {err}", ca_path.display()))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|err| {
                AcmeError::configuration(format!(
                    "parse kubernetes CA {}: {err}",
                    ca_path.display()
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|err| AcmeError::configuration(format!("kubernetes HTTP client: {err}")))?;
        Ok(Self {
            endpoint,
            namespace: config.namespace,
            client,
            auth,
        })
    }

    /// In-cluster shortcut: the endpoint and CA come from the service account
    /// environment, so this only works inside a pod (or with a proxied API).
    pub fn in_cluster(namespace: impl Into<String>, auth: KubernetesAuth) -> Result<Self> {
        Self::new(
            KubernetesSecretConfig {
                namespace: namespace.into(),
                ..KubernetesSecretConfig::default()
            },
            auth,
        )
    }

    /// The namespace this sink writes into.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn secret_url(&self, name: &str) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets/{name}",
            self.endpoint, self.namespace
        )
    }

    fn collection_url(&self) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets",
            self.endpoint, self.namespace
        )
    }

    /// Resolves the bearer token; failures name the reference, never the value.
    async fn bearer_token(&self) -> Result<String> {
        match &self.auth {
            KubernetesAuth::Token(token) => Ok(token.clone()),
            KubernetesAuth::Resolved {
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
            KubernetesAuth::ServiceAccount => {
                let path = format!("{SERVICE_ACCOUNT_DIR}/token");
                let raw = std::fs::read_to_string(&path)
                    .map_err(|err| AcmeError::configuration(format!("read {path}: {err}")))?;
                Ok(raw.trim().to_owned())
            }
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<String>,
    ) -> Result<reqwest::Response> {
        let token = self.bearer_token().await?;
        let mut builder = self.client.request(method, url).bearer_auth(token);
        if body.is_some() {
            builder = builder.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        builder
            .body(body.unwrap_or_default())
            .send()
            .await
            .map_err(|err| AcmeError::transport(format!("kubernetes API request failed: {err}")))
    }

    /// `Ok(None)` for 404; every other non-success is a classified error.
    async fn get_secret(&self, name: &str) -> Result<Option<K8sSecret>> {
        let response = self
            .send(reqwest::Method::GET, &self.secret_url(name), None)
            .await?;
        match response.status().as_u16() {
            200 => {
                let secret: K8sSecret = response.json().await.map_err(|err| {
                    AcmeError::transport(format!(
                        "kubernetes secret `{name}` body is invalid: {err}"
                    ))
                })?;
                Ok(Some(secret))
            }
            404 => Ok(None),
            status => Err(classify_status(status, "read", name)),
        }
    }

    async fn require_secret(&self, name: &str) -> Result<K8sSecret> {
        self.get_secret(name)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("kubernetes secret `{name}` is missing")))
    }

    async fn create_secret(
        &self,
        name: &str,
        secret_type: &str,
        data: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
    ) -> Result<()> {
        let payload = secret_payload(&self.namespace, name, None, secret_type, data, annotations);
        let response = self
            .send(
                reqwest::Method::POST,
                &self.collection_url(),
                Some(payload.to_string()),
            )
            .await?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(classify_status(status, "create", name))
        }
    }

    /// Guarded replace: `resourceVersion` makes concurrent modifications fail
    /// with 409 instead of being overwritten.
    async fn replace_secret(
        &self,
        name: &str,
        resource_version: u64,
        secret_type: &str,
        data: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
    ) -> Result<()> {
        let payload = secret_payload(
            &self.namespace,
            name,
            Some(resource_version),
            secret_type,
            data,
            annotations,
        );
        let response = self
            .send(
                reqwest::Method::PUT,
                &self.secret_url(name),
                Some(payload.to_string()),
            )
            .await?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(classify_status(status, "replace", name))
        }
    }

    async fn delete_secret(&self, name: &str) -> Result<CleanupOutcome> {
        let response = self
            .send(reqwest::Method::DELETE, &self.secret_url(name), None)
            .await?;
        match response.status().as_u16() {
            200..=299 => Ok(CleanupOutcome::Cleaned),
            404 => Ok(CleanupOutcome::AlreadyClean),
            status => Err(classify_status(status, "delete", name)),
        }
    }

    /// Extracts the target Secret name from a `k8s://<namespace>/<staging-name>`
    /// staged reference.
    fn staging_target_name<'a>(&self, staged_ref: &'a str) -> Result<&'a str> {
        let rest = staged_ref.strip_prefix("k8s://").ok_or_else(|| {
            AcmeError::invalid_input("kubernetes staged reference must start with k8s://")
        })?;
        let (namespace, staging_name) = rest.split_once('/').ok_or_else(|| {
            AcmeError::invalid_input("kubernetes staged reference must be k8s://<namespace>/<name>")
        })?;
        if namespace != self.namespace {
            return Err(AcmeError::invalid_input(format!(
                "staged reference namespace `{namespace}` does not match sink namespace `{}`",
                self.namespace
            )));
        }
        staging_name.strip_prefix(STAGING_PREFIX).ok_or_else(|| {
            AcmeError::invalid_input("kubernetes staged reference must name a staging secret")
        })
    }
}

#[async_trait]
impl CertificateSink for KubernetesSecretSink {
    /// Stages material in `staging-<name>` with a snapshot of the active
    /// Secret for rollback. Idempotent: the staging Secret is replaced, the
    /// target untouched, and re-staging the same version converges.
    #[tracing::instrument(skip(self, spec, version, material), fields(version_id = %version.id, target_id = %spec.target_id))]
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment> {
        if spec.kind != DeliveryTargetKind::KubernetesSecret {
            return Err(AcmeError::invalid_input(
                "kubernetes sink requires a kubernetes_secret target",
            ));
        }
        let name = secret_name(&spec.reference)?;
        let staging_name = format!("{STAGING_PREFIX}{name}");

        // Snapshot the active Secret — rollback restores exactly this content.
        let previous = self.get_secret(name).await?;
        let previous_resource_version = match previous.as_ref() {
            Some(secret) => secret.resource_version(name)?,
            None => 0,
        };

        let mut annotations = HashMap::new();
        annotations.insert(ANN_MANAGED_BY.to_string(), "acmex".to_string());
        annotations.insert(ANN_VERSION.to_string(), version.id.to_string());
        annotations.insert(
            ANN_LEAF_SHA.to_string(),
            material.material.leaf_sha256.clone(),
        );
        annotations.insert(ANN_TARGET.to_string(), name.to_string());
        annotations.insert(ANN_STAGED_AT.to_string(), Timestamp::now().to_string());
        if let Some(active) = previous.as_ref() {
            annotations.insert(ANN_PREV_EXISTED.to_string(), "true".to_string());
            let previous_data = serde_json::to_string(&active.data)?;
            annotations.insert(
                ANN_PREV_DATA.to_string(),
                STANDARD.encode(previous_data.as_bytes()),
            );
            annotations.insert(
                ANN_PREV_TYPE.to_string(),
                active
                    .secret_type
                    .clone()
                    .unwrap_or_else(|| TYPE_OPAQUE.to_string()),
            );
            let previous_annotations = serde_json::to_string(&active.metadata.annotations)?;
            annotations.insert(
                ANN_PREV_ANNOTATIONS.to_string(),
                STANDARD.encode(previous_annotations.as_bytes()),
            );
        }

        let data = tls_secret_data(material.material)?;
        match self.get_secret(&staging_name).await? {
            None => {
                self.create_secret(&staging_name, TYPE_OPAQUE, &data, &annotations)
                    .await?;
            }
            Some(existing) => {
                // Replace keeps staging idempotent across re-runs.
                self.replace_secret(
                    &staging_name,
                    existing.resource_version(&staging_name)?,
                    TYPE_OPAQUE,
                    &data,
                    &annotations,
                )
                .await?;
            }
        }

        Ok(StagedDeployment {
            kind: spec.kind,
            target_id: spec.target_id.clone(),
            version_id: version.id.clone(),
            staged_ref: format!("k8s://{}/{}", self.namespace, staging_name),
            previous_active_ref: previous
                .is_some()
                .then(|| format!("k8s://{}/{}", self.namespace, name)),
            leaf_sha256: material.material.leaf_sha256.clone(),
            resource_version: previous_resource_version,
        })
    }

    /// Replaces the target Secret under `metadata.resourceVersion` optimistic
    /// concurrency. Idempotent: an already-serving target is a no-op, and a
    /// lost race degrades to `Conflict` (retryable) unless the concurrent
    /// writer activated the same material.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let name = self.staging_target_name(&staged.staged_ref)?;
        let staging_name = format!("{STAGING_PREFIX}{name}");
        let staging = self.require_secret(&staging_name).await?;
        // The staging slot is shared per target and re-staging overwrites it:
        // promote only the exact material this handle staged, otherwise a
        // newer stage would go live under this version's identity.
        let staged_leaf_sha = staging
            .metadata
            .annotations
            .get(ANN_LEAF_SHA)
            .ok_or_else(|| {
                AcmeError::conflict(format!(
                    "kubernetes staging secret `{staging_name}` has no {ANN_LEAF_SHA} annotation; \
                     it was overwritten by a non-acmex writer; re-stage and retry"
                ))
            })?;
        if staged_leaf_sha != &staged.leaf_sha256 {
            return Err(AcmeError::conflict(format!(
                "kubernetes staging secret `{staging_name}` was overwritten by a newer stage \
                 (fingerprint mismatch); re-stage and retry"
            )));
        }
        let data = staging.data;
        let secret_type = secret_type_for(&data);
        let annotations = active_annotations(staged);

        match self.get_secret(name).await? {
            Some(current) => {
                if current.serves(&staged.leaf_sha256) {
                    return Ok(()); // already active — idempotent activate
                }
                match self
                    .replace_secret(
                        name,
                        current.resource_version(name)?,
                        secret_type,
                        &data,
                        &annotations,
                    )
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(err) if is_conflict(&err) => {
                        // Lost the race: converge only when the concurrent
                        // writer activated the same material.
                        match self.get_secret(name).await? {
                            Some(current) if current.serves(&staged.leaf_sha256) => Ok(()),
                            _ => Err(err),
                        }
                    }
                    Err(err) => Err(err),
                }
            }
            None => match self
                .create_secret(name, secret_type, &data, &annotations)
                .await
            {
                Ok(()) => Ok(()),
                Err(err) if is_conflict(&err) => match self.get_secret(name).await? {
                    Some(current) if current.serves(&staged.leaf_sha256) => Ok(()),
                    _ => Err(err),
                },
                Err(err) => Err(err),
            },
        }
    }

    /// GETs the target Secret and compares the decoded leaf certificate's
    /// SHA-256 with the staged fingerprint. Reachable-but-wrong is
    /// `Unhealthy`; unreachable, unauthorized or absent is `Unknown` so
    /// transient conditions never trigger rollbacks.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let name = self.staging_target_name(&staged.staged_ref)?;
        match self.get_secret(name).await {
            Ok(Some(secret)) => match leaf_sha_of(&secret.data) {
                Some(sha) if sha == staged.leaf_sha256 => Ok(DeploymentHealth::Healthy),
                Some(_) => Ok(DeploymentHealth::Unhealthy(
                    "active secret serves a different certificate".into(),
                )),
                None => Ok(DeploymentHealth::Unhealthy(
                    "active secret has no tls.crt leaf certificate".into(),
                )),
            },
            Ok(None) => Ok(DeploymentHealth::Unknown(format!(
                "target secret `{name}` is absent"
            ))),
            Err(err) => Ok(DeploymentHealth::Unknown(format!(
                "target secret unreachable: {err}"
            ))),
        }
    }

    /// Restores the stage-time snapshot. Idempotent: repeated calls rewrite
    /// the same previous content; with no snapshot (staging already cleaned)
    /// and no previously active Secret it is a no-op; a missing snapshot with
    /// a previously active Secret is an error for operator attention.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let name = self.staging_target_name(&staged.staged_ref)?;
        let Some(staging) = self.get_secret(&format!("{STAGING_PREFIX}{name}")).await? else {
            if staged.resource_version > 0 {
                // A previous Secret existed at stage time, but its snapshot is
                // gone (concurrent cleanup or manual deletion): the restore
                // outcome cannot be proven. Fail loudly instead of silently
                // pretending the active Secret was restored.
                return Err(AcmeError::storage(format!(
                    "kubernetes staging secret `{STAGING_PREFIX}{name}` is missing but a \
                     previous target Secret existed; cannot restore the rollback snapshot \
                     (operator action required)"
                )));
            }
            // Snapshot already cleaned up and nothing was active before
            // staging: there is nothing left to restore.
            return Ok(());
        };
        if staging
            .metadata
            .annotations
            .get(ANN_PREV_EXISTED)
            .map(String::as_str)
            != Some("true")
        {
            // Nothing was active before staging: restore by removing the target.
            return self.delete_secret(name).await.map(|_| ());
        }
        let data = decoded_snapshot(&staging.metadata.annotations, ANN_PREV_DATA, "data")?;
        let secret_type = staging
            .metadata
            .annotations
            .get(ANN_PREV_TYPE)
            .cloned()
            .unwrap_or_else(|| TYPE_OPAQUE.to_string());
        let annotations = match staging.metadata.annotations.get(ANN_PREV_ANNOTATIONS) {
            Some(_) => decoded_snapshot(
                &staging.metadata.annotations,
                ANN_PREV_ANNOTATIONS,
                "annotations",
            )?,
            None => HashMap::new(),
        };
        match self.get_secret(name).await? {
            Some(current) => {
                self.replace_secret(
                    name,
                    current.resource_version(name)?,
                    &secret_type,
                    &data,
                    &annotations,
                )
                .await
            }
            None => {
                match self
                    .create_secret(name, &secret_type, &data, &annotations)
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(err) if is_conflict(&err) => match self.get_secret(name).await? {
                        // Reappeared concurrently: force one more guarded replace.
                        Some(current) => {
                            self.replace_secret(
                                name,
                                current.resource_version(name)?,
                                &secret_type,
                                &data,
                                &annotations,
                            )
                            .await
                        }
                        None => Ok(()),
                    },
                    Err(err) => Err(err),
                }
            }
        }
    }

    /// Deletes the staging Secret. Idempotent: an absent staging Secret is
    /// `AlreadyClean`.
    #[tracing::instrument(skip(self, staged), fields(version_id = %staged.version_id))]
    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome> {
        let name = self.staging_target_name(&staged.staged_ref)?;
        self.delete_secret(&format!("{STAGING_PREFIX}{name}")).await
    }
}

/// Wire shape of a Kubernetes Secret (only the fields this sink consumes).
#[derive(Debug, Deserialize)]
struct K8sSecret {
    #[serde(default)]
    metadata: K8sObjectMeta,
    #[serde(rename = "type", default)]
    secret_type: Option<String>,
    #[serde(default)]
    data: HashMap<String, String>,
}

impl K8sSecret {
    /// The parsed `metadata.resourceVersion`. A missing or unparseable value
    /// is a hard error: falling back to `0` would turn every guarded replace
    /// into an unconditional overwrite.
    fn resource_version(&self, name: &str) -> Result<u64> {
        self.metadata
            .resource_version
            .as_deref()
            .and_then(|rv| rv.parse().ok())
            .ok_or_else(|| {
                AcmeError::transport(format!(
                    "kubernetes secret `{name}` has no parseable metadata.resourceVersion; \
                     refusing an unguarded write"
                ))
            })
    }

    /// Whether the Secret's `tls.crt` leaf matches the expected fingerprint.
    fn serves(&self, leaf_sha256: &str) -> bool {
        leaf_sha_of(&self.data).as_deref() == Some(leaf_sha256)
    }
}

#[derive(Debug, Default, Deserialize)]
struct K8sObjectMeta {
    #[serde(rename = "resourceVersion", default)]
    resource_version: Option<String>,
    #[serde(default)]
    annotations: HashMap<String, String>,
}

fn active_annotations(staged: &StagedDeployment) -> HashMap<String, String> {
    let mut annotations = HashMap::new();
    annotations.insert(ANN_MANAGED_BY.to_string(), "acmex".to_string());
    annotations.insert(ANN_VERSION.to_string(), staged.version_id.to_string());
    annotations.insert(ANN_LEAF_SHA.to_string(), staged.leaf_sha256.clone());
    annotations.insert(ANN_STAGED_AT.to_string(), Timestamp::now().to_string());
    annotations
}

fn secret_payload(
    namespace: &str,
    name: &str,
    resource_version: Option<u64>,
    secret_type: &str,
    data: &HashMap<String, String>,
    annotations: &HashMap<String, String>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "name": name,
        "namespace": namespace,
        "labels": { "app.kubernetes.io/managed-by": "acmex" },
        "annotations": annotations,
    });
    if let Some(resource_version) = resource_version {
        metadata["resourceVersion"] = serde_json::Value::from(resource_version.to_string());
    }
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": secret_type,
        "metadata": metadata,
        "data": data,
    })
}

/// `kubernetes.io/tls` when the staged data carries a key, Opaque otherwise.
fn secret_type_for(data: &HashMap<String, String>) -> &'static str {
    if data.contains_key("tls.key") {
        TYPE_TLS
    } else {
        TYPE_OPAQUE
    }
}

/// Builds the Secret data map: `tls.crt` (full chain), `tls.key` (when the
/// material carries a key) and `ca.crt` (issuer chain, omitted when the chain
/// has a single certificate). Values are base64 as the API server expects.
fn tls_secret_data(material: &CertificateMaterial) -> Result<HashMap<String, String>> {
    let mut data = HashMap::new();
    data.insert(
        "tls.crt".to_string(),
        STANDARD.encode(material.fullchain_pem.as_bytes()),
    );
    if let Some(key) = material.private_key_pem.as_ref() {
        data.insert("tls.key".to_string(), STANDARD.encode(key.expose_secret()));
    }
    let chain = issuer_chain_pem(&material.fullchain_pem);
    if !chain.is_empty() {
        data.insert("ca.crt".to_string(), STANDARD.encode(chain.as_bytes()));
    }
    Ok(data)
}

/// Every PEM CERTIFICATE block after the leaf.
fn issuer_chain_pem(fullchain: &str) -> String {
    let Ok(blocks) = pem::parse_many(fullchain.as_bytes()) else {
        return String::new();
    };
    blocks
        .iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .skip(1)
        .map(encode_pem)
        .collect()
}

fn encode_pem(block: &pem::Pem) -> String {
    pem::encode_config(
        block,
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

/// Decodes a base64(JSON map) staging annotation.
fn decoded_snapshot(
    annotations: &HashMap<String, String>,
    key: &str,
    what: &str,
) -> Result<HashMap<String, String>> {
    let encoded = annotations.get(key).ok_or_else(|| {
        AcmeError::storage(format!(
            "staging secret is missing the previous-{what} snapshot"
        ))
    })?;
    let decoded = STANDARD.decode(encoded.as_bytes()).map_err(|err| {
        AcmeError::storage(format!("previous-{what} snapshot is not base64: {err}"))
    })?;
    Ok(serde_json::from_slice(&decoded)?)
}

/// SHA-256 of the leaf certificate in a Secret's `tls.crt` value.
fn leaf_sha_of(data: &HashMap<String, String>) -> Option<String> {
    let encoded = data.get("tls.crt")?;
    let decoded = STANDARD.decode(encoded.as_bytes()).ok()?;
    leaf_sha256_from_pem(&decoded)
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

fn is_conflict(err: &AcmeError) -> bool {
    matches!(err, AcmeError::Conflict(_))
}

/// Error classification shared by every API call.
///
/// * 409 → `Conflict` (retryable; the orchestrator re-runs the deployment),
/// * 401/403 → `Configuration` (operator action required: token/RBAC),
/// * 5xx → `Transport` (retryable server-side failure),
/// * everything else → `Transport` with the status in the message.
fn classify_status(status: u16, action: &str, name: &str) -> AcmeError {
    match status {
        401 | 403 => AcmeError::configuration(format!(
            "kubernetes {action} on secret `{name}` rejected with HTTP {status}: token/RBAC requires operator action"
        )),
        404 => AcmeError::not_found(format!("kubernetes {action}: secret `{name}` not found")),
        409 => AcmeError::conflict(format!(
            "kubernetes {action} on secret `{name}` conflicted with a concurrent writer (HTTP 409); safe to retry"
        )),
        500..=599 => AcmeError::transport(format!(
            "kubernetes API server error during {action} of secret `{name}` (HTTP {status}); retryable"
        )),
        status => AcmeError::transport(format!(
            "kubernetes {action} on secret `{name}` failed with HTTP {status}"
        )),
    }
}

/// Secret names must be DNS-1123 subdomains; reject anything else early.
fn secret_name(reference: &str) -> Result<&str> {
    let name = reference.trim();
    let valid = !name.is_empty()
        && name.len() <= 245
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
    if valid {
        Ok(name)
    } else {
        Err(AcmeError::invalid_input(format!(
            "kubernetes secret reference {reference:?} must be a DNS-1123 subdomain"
        )))
    }
}

fn in_cluster_endpoint() -> Result<String> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
        AcmeError::configuration(
            "in-cluster mode requires KUBERNETES_SERVICE_HOST (or set endpoint explicitly)",
        )
    })?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT").map_err(|_| {
        AcmeError::configuration(
            "in-cluster mode requires KUBERNETES_SERVICE_PORT (or set endpoint explicitly)",
        )
    })?;
    Ok(format!("https://{host}:{port}"))
}
