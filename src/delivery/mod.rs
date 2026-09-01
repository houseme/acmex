//! Certificate material rendering and downstream delivery sinks.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use x509_parser::prelude::*;

use crate::domain::{
    CertificateVersion, DeliveryRequirement, DeliveryTargetKind, TargetId, VersionId,
};
use crate::error::{AcmeError, Result};
use crate::key::SecretBytes;

/// Rendered certificate material for a sink invocation.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificateMaterial {
    /// PEM leaf plus intermediates.
    pub fullchain_pem: String,
    /// PEM leaf certificate only.
    pub cert_pem: String,
    /// Optional private key PEM for sinks that install TLS keypairs.
    pub private_key_pem: Option<SecretBytes>,
    /// SHA-256 fingerprint of the leaf certificate DER.
    pub leaf_sha256: String,
}

impl fmt::Debug for CertificateMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateMaterial")
            .field("fullchain_len", &self.fullchain_pem.len())
            .field("cert_len", &self.cert_pem.len())
            .field("has_private_key", &self.private_key_pem.is_some())
            .field("leaf_sha256", &self.leaf_sha256)
            .finish()
    }
}

/// Builder that centralizes certificate/key rendering and verification.
#[derive(Debug, Clone)]
pub struct CertificateMaterialBuilder {
    require_private_key: bool,
}

impl CertificateMaterialBuilder {
    /// Creates a builder that allows keyless material.
    pub fn new() -> Self {
        Self {
            require_private_key: false,
        }
    }

    /// Requires a private key and verifies it matches the leaf certificate.
    pub fn require_private_key(mut self) -> Self {
        self.require_private_key = true;
        self
    }

    /// Builds material from a certificate version and optional private key.
    pub fn build(
        &self,
        version: &CertificateVersion,
        private_key_pem: Option<SecretBytes>,
    ) -> Result<CertificateMaterial> {
        if self.require_private_key && private_key_pem.is_none() {
            return Err(AcmeError::invalid_input(
                "certificate sink requires private key material",
            ));
        }
        let certs = ::pem::parse_many(version.certificate_chain_pem.as_bytes())
            .map_err(|err| AcmeError::certificate(format!("parse certificate chain: {err}")))?;
        let leaf = certs
            .iter()
            .find(|block| block.tag() == "CERTIFICATE")
            .ok_or_else(|| AcmeError::certificate("certificate chain is empty"))?;
        let cert_pem = ::pem::encode_config(
            &::pem::Pem::new("CERTIFICATE", leaf.contents().to_vec()),
            ::pem::EncodeConfig::new().set_line_ending(::pem::LineEnding::LF),
        );
        let leaf_sha256 = sha256_hex(leaf.contents());
        if let Some(key) = private_key_pem.as_ref() {
            verify_key_matches_certificate(key.expose_secret(), leaf.contents())?;
        }
        Ok(CertificateMaterial {
            fullchain_pem: version.certificate_chain_pem.clone(),
            cert_pem,
            private_key_pem,
            leaf_sha256,
        })
    }
}

impl Default for CertificateMaterialBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed material passed to a sink for one operation.
#[derive(Debug, Clone, Copy)]
pub struct CertificateMaterialRef<'a> {
    /// Rendered material.
    pub material: &'a CertificateMaterial,
}

/// One delivery target invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSpec {
    /// Target identity.
    pub target_id: TargetId,
    /// Sink type.
    pub kind: DeliveryTargetKind,
    /// Opaque target reference.
    pub reference: String,
    /// Whether this target gates lineage activation.
    pub requirement: DeliveryRequirement,
}

/// Sink-specific staged deployment pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedDeployment {
    /// Sink type.
    pub kind: DeliveryTargetKind,
    /// Target identity.
    pub target_id: TargetId,
    /// Version being deployed.
    pub version_id: VersionId,
    /// Sink-local staged reference.
    pub staged_ref: String,
    /// Previous active sink pointer, used for rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_active_ref: Option<String>,
    /// Material fingerprint staged by the sink.
    pub leaf_sha256: String,
    /// Optimistic version for remote/agent sinks.
    #[serde(default)]
    pub resource_version: u64,
}

/// Health check result for one sink target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentHealth {
    /// Active target serves the expected material.
    Healthy,
    /// Target is reachable but serves other material.
    Unhealthy(String),
    /// Target cannot currently be observed.
    Unknown(String),
}

/// Cleanup result for staged or old artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOutcome {
    /// Something was removed.
    Cleaned,
    /// Nothing needed removal.
    AlreadyClean,
}

/// Downstream delivery lifecycle.
#[async_trait]
pub trait CertificateSink: Send + Sync {
    /// Writes versioned material without switching active traffic.
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment>;

    /// Atomically switches the target to the staged material.
    async fn activate(&self, staged: &StagedDeployment) -> Result<()>;
    /// Observes whether the active target serves the staged fingerprint.
    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth>;
    /// Restores the previous active target.
    async fn rollback(&self, staged: &StagedDeployment) -> Result<()>;
    /// Cleans staged artifacts.
    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome>;
}

/// Versioned filesystem sink using `versions/<id>` and an atomic `current` pointer.
#[derive(Debug, Clone)]
pub struct FileCertificateSink;

impl FileCertificateSink {
    /// Creates a file sink.
    pub fn new() -> Self {
        Self
    }
}

impl Default for FileCertificateSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CertificateSink for FileCertificateSink {
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment> {
        if spec.kind != DeliveryTargetKind::File {
            return Err(AcmeError::invalid_input("file sink requires file target"));
        }
        let root = PathBuf::from(&spec.reference);
        let versions = root.join("versions");
        let version_dir = versions.join(version.id.as_str());
        fs::create_dir_all(&version_dir).await?;
        write_material_file(
            &version_dir.join("fullchain.pem"),
            material.material.fullchain_pem.as_bytes(),
            0o644,
        )
        .await?;
        write_material_file(
            &version_dir.join("cert.pem"),
            material.material.cert_pem.as_bytes(),
            0o644,
        )
        .await?;
        if let Some(key) = material.material.private_key_pem.as_ref() {
            write_material_file(&version_dir.join("key.pem"), key.expose_secret(), 0o600).await?;
        }
        let metadata = serde_json::json!({
            "version_id": version.id.as_str(),
            "target_id": spec.target_id.as_str(),
            "leaf_sha256": material.material.leaf_sha256,
            "key_provider": version.key_ref.provider,
            "key_id": version.key_ref.key_id.as_str(),
        });
        write_material_file(
            &version_dir.join("metadata.json"),
            serde_json::to_vec_pretty(&metadata)?.as_slice(),
            0o644,
        )
        .await?;
        sync_dir(&version_dir)?;
        sync_dir(&versions)?;
        let previous_active_ref = current_target(&root).await?;
        Ok(StagedDeployment {
            kind: spec.kind,
            target_id: spec.target_id.clone(),
            version_id: version.id.clone(),
            staged_ref: version_dir.to_string_lossy().into_owned(),
            previous_active_ref,
            leaf_sha256: material.material.leaf_sha256.clone(),
            resource_version: 0,
        })
    }

    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let version_dir = PathBuf::from(&staged.staged_ref);
        let root = version_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| AcmeError::invalid_input("invalid staged file sink reference"))?;
        set_current(root, &version_dir).await
    }

    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let version_dir = PathBuf::from(&staged.staged_ref);
        let root = version_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| AcmeError::invalid_input("invalid staged file sink reference"))?;
        let Some(current) = current_target(root).await? else {
            return Ok(DeploymentHealth::Unknown(
                "current pointer is absent".into(),
            ));
        };
        if current != staged.staged_ref {
            return Ok(DeploymentHealth::Unhealthy(format!(
                "current points at {current}, expected {}",
                staged.staged_ref
            )));
        }
        let metadata = fs::read(version_dir.join("metadata.json")).await?;
        let metadata: serde_json::Value = serde_json::from_slice(&metadata)?;
        if metadata
            .get("leaf_sha256")
            .and_then(serde_json::Value::as_str)
            == Some(staged.leaf_sha256.as_str())
        {
            Ok(DeploymentHealth::Healthy)
        } else {
            Ok(DeploymentHealth::Unhealthy(
                "active metadata fingerprint mismatch".into(),
            ))
        }
    }

    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let version_dir = PathBuf::from(&staged.staged_ref);
        let root = version_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| AcmeError::invalid_input("invalid staged file sink reference"))?;
        match staged.previous_active_ref.as_ref() {
            Some(previous) => set_current(root, &PathBuf::from(previous)).await,
            None => remove_current(root).await,
        }
    }

    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome> {
        let path = PathBuf::from(&staged.staged_ref);
        if path.exists() {
            fs::remove_dir_all(path).await?;
            Ok(CleanupOutcome::Cleaned)
        } else {
            Ok(CleanupOutcome::AlreadyClean)
        }
    }
}

/// In-memory agent sink used as a contract-compatible remote/platform adapter.
#[derive(Clone, Default)]
pub struct FakeAgentCertificateSink {
    state: Arc<Mutex<HashMap<String, AgentTargetState>>>,
}

#[derive(Debug, Clone, Default)]
struct AgentTargetState {
    active: Option<String>,
    staged: HashMap<String, String>,
    resource_version: u64,
}

impl FakeAgentCertificateSink {
    /// Creates an empty fake agent sink.
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for FakeAgentCertificateSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeAgentCertificateSink")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CertificateSink for FakeAgentCertificateSink {
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment> {
        if spec.kind != DeliveryTargetKind::Webhook {
            return Err(AcmeError::invalid_input(
                "fake agent sink requires webhook target",
            ));
        }
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let state = states.entry(spec.reference.clone()).or_default();
        state.resource_version += 1;
        let staged_ref = format!("agent://{}/versions/{}", spec.reference, version.id);
        state
            .staged
            .insert(staged_ref.clone(), material.material.leaf_sha256.clone());
        Ok(StagedDeployment {
            kind: spec.kind,
            target_id: spec.target_id.clone(),
            version_id: version.id.clone(),
            staged_ref,
            previous_active_ref: state.active.clone(),
            leaf_sha256: material.material.leaf_sha256.clone(),
            resource_version: state.resource_version,
        })
    }

    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let state = states
            .get_mut(reference)
            .ok_or_else(|| AcmeError::not_found("agent target not staged"))?;
        if state.resource_version != staged.resource_version {
            return Err(AcmeError::conflict("agent resource version changed"));
        }
        if !state.staged.contains_key(&staged.staged_ref) {
            return Err(AcmeError::not_found("staged agent version not found"));
        }
        state.resource_version += 1;
        state.active = Some(staged.staged_ref.clone());
        Ok(())
    }

    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let Some(state) = states.get(reference) else {
            return Ok(DeploymentHealth::Unknown("agent target missing".into()));
        };
        if state.active.as_deref() != Some(staged.staged_ref.as_str()) {
            return Ok(DeploymentHealth::Unhealthy(
                "agent active pointer mismatch".into(),
            ));
        }
        if state.staged.get(&staged.staged_ref) == Some(&staged.leaf_sha256) {
            Ok(DeploymentHealth::Healthy)
        } else {
            Ok(DeploymentHealth::Unhealthy(
                "agent fingerprint mismatch".into(),
            ))
        }
    }

    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let state = states
            .get_mut(reference)
            .ok_or_else(|| AcmeError::not_found("agent target missing"))?;
        state.resource_version += 1;
        state.active = staged.previous_active_ref.clone();
        Ok(())
    }

    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome> {
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let Some(state) = states.get_mut(reference) else {
            return Ok(CleanupOutcome::AlreadyClean);
        };
        if state.staged.remove(&staged.staged_ref).is_some() {
            Ok(CleanupOutcome::Cleaned)
        } else {
            Ok(CleanupOutcome::AlreadyClean)
        }
    }
}

fn verify_key_matches_certificate(private_key_pem: &[u8], cert_der: &[u8]) -> Result<()> {
    let pem = std::str::from_utf8(private_key_pem)
        .map_err(|err| AcmeError::crypto(format!("private key is not UTF-8 PEM: {err}")))?;
    let key = rcgen::KeyPair::from_pem(pem)
        .map_err(|err| AcmeError::crypto(format!("parse private key: {err}")))?;
    let public_pem = key.public_key_pem();
    let public = ::pem::parse(public_pem.as_bytes())
        .map_err(|err| AcmeError::pem(format!("parse public key PEM: {err}")))?;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|err| AcmeError::certificate(format!("parse leaf certificate: {err}")))?;
    if cert.tbs_certificate.subject_pki.raw != public.contents() {
        return Err(AcmeError::crypto(
            "private key does not match certificate public key",
        ));
    }
    Ok(())
}

async fn write_material_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    fs::write(path, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    }
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

async fn current_target(root: &Path) -> Result<Option<String>> {
    let current = root.join("current");
    #[cfg(unix)]
    {
        match fs::read_link(&current).await {
            Ok(path) => Ok(Some(path.to_string_lossy().into_owned())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
    #[cfg(not(unix))]
    {
        match fs::read_to_string(&current).await {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

async fn set_current(root: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(root).await?;
    let tmp = root.join(format!(".current-{}.tmp", std::process::id()));
    if tmp.exists() {
        remove_path(&tmp).await?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, &tmp)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, target.to_string_lossy().as_bytes()).await?;
    }
    fs::rename(&tmp, root.join("current")).await?;
    sync_dir(root)?;
    Ok(())
}

async fn remove_current(root: &Path) -> Result<()> {
    let current = root.join("current");
    if current.exists() {
        remove_path(&current).await?;
    }
    Ok(())
}

async fn remove_path(path: &Path) -> Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn parse_agent_ref(staged_ref: &str) -> Result<(&str, &str)> {
    let rest = staged_ref
        .strip_prefix("agent://")
        .ok_or_else(|| AcmeError::invalid_input("invalid agent staged reference"))?;
    let (reference, version) = rest
        .split_once("/versions/")
        .ok_or_else(|| AcmeError::invalid_input("invalid agent staged reference"))?;
    Ok((version, reference))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
