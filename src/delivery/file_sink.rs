//! File sink: versioned directory layout with atomic pointer switch.
//!
//! Layout:
//!
//! ```text
//! <root>/
//! ├── versions/<version-id>/{fullchain.pem, cert.pem, key.pem, metadata.json}
//! └── current -> versions/<version-id>      (atomic symlink swap)
//! ```
//!
//! `stage` writes a fresh directory without touching `current`; `activate`
//! swaps the pointer via temp-symlink + rename (atomic on POSIX); health
//! re-reads the pointer and compares the certificate fingerprint;
//! `rollback` restores the previous pointer recorded at activate time.
//! Platforms without symlink support fall back to a `current.txt` pointer
//! file (documented; activation remains atomic via rename).

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::certificate::CertificateChain;
use crate::domain::CertificateVersion;
use crate::error::{AcmeError, Result};

use super::{
    CertificateMaterial, CertificateSink, DeploymentHealth, DeploymentSpec, SinkCleanupOutcome,
    StagedDeployment,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    version_id: String,
    lineage_id: String,
    serial: String,
    not_after: String,
    fingerprint: String,
}

fn fingerprint(chain_pem: &str) -> Result<String> {
    let chain = CertificateChain::from_pem(chain_pem.as_bytes())?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&chain.leaf);
    Ok(hex::encode(hasher.finalize()))
}

/// The file-backed sink.
#[derive(Clone)]
pub struct FileSink {
    root: PathBuf,
}

impl FileSink {
    /// A sink rooted at `root` (created on first stage).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn version_dir(&self, version_id: &str) -> PathBuf {
        self.root.join("versions").join(version_id)
    }

    fn pointer(&self) -> PathBuf {
        self.root.join("current")
    }

    fn previous_pointer(&self, version_id: &str) -> PathBuf {
        self.root.join(format!("current.previous.{version_id}"))
    }

    /// The directory the live pointer currently resolves to, if any.
    pub fn current_version(&self) -> Option<String> {
        let pointer = self.pointer();
        if !pointer.exists() {
            return None;
        }
        let link = std::fs::read_link(&pointer)
            .ok()
            .or_else(|| std::fs::read_to_string(&pointer).ok().map(PathBuf::from))?;
        let name = link.file_name()?.to_string_lossy().to_string();
        Some(name)
    }

    /// Reads the fingerprint of the certificate the pointer serves.
    async fn current_fingerprint(&self) -> Result<Option<String>> {
        let Some(version_id) = self.current_version() else {
            return Ok(None);
        };
        let metadata_path = self.version_dir(&version_id).join("metadata.json");
        let bytes = match fs::read(&metadata_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AcmeError::storage(format!("metadata read failed: {e}"))),
        };
        let metadata: Metadata = serde_json::from_slice(&bytes)
            .map_err(|e| AcmeError::storage(format!("corrupt metadata: {e}")))?;
        Ok(Some(metadata.fingerprint))
    }

    async fn write_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| AcmeError::storage(format!("mkdir failed: {e}")))?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)
            .await
            .map_err(|e| AcmeError::storage(format!("write failed: {e}")))?;
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
        }
        // fsync the staged file so the renamed content is durable.
        if let Ok(handle) = fs::File::open(&tmp).await {
            let _ = handle.sync_all().await;
        }
        fs::rename(&tmp, path)
            .await
            .map_err(|e| AcmeError::storage(format!("rename failed: {e}")))?;
        Ok(())
    }

    fn swap_pointer(&self, target_version: &str) -> Result<()> {
        let pointer = self.pointer();
        // Record the previous pointer for rollback.
        if pointer.exists() {
            let previous = self.previous_pointer(target_version);
            let _ = std::fs::rename(&pointer, &previous);
        }
        let staged_link = self.root.join("current.next");
        let _ = std::fs::remove_file(&staged_link);
        #[cfg(unix)]
        std::os::unix::fs::symlink(format!("versions/{target_version}"), &staged_link)
            .map_err(|e| AcmeError::storage(format!("symlink failed: {e}")))?;
        #[cfg(not(unix))]
        std::fs::write(&staged_link, format!("versions/{target_version}"))
            .map_err(|e| AcmeError::storage(format!("pointer write failed: {e}")))?;
        std::fs::rename(&staged_link, &pointer)
            .map_err(|e| AcmeError::storage(format!("pointer swap failed: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl CertificateSink for FileSink {
    fn sink_id(&self) -> &str {
        "file"
    }

    async fn stage(
        &self,
        _spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: &CertificateMaterial,
    ) -> Result<StagedDeployment> {
        let version_id = version.id.to_string();
        let dir = self.version_dir(&version_id);
        fs::create_dir_all(&dir)
            .await
            .map_err(|e| AcmeError::storage(format!("version dir create failed: {e}")))?;

        Self::write_atomic(
            &dir.join("fullchain.pem"),
            material.full_chain_pem.as_bytes(),
            false,
        )
        .await?;
        Self::write_atomic(&dir.join("cert.pem"), material.leaf_pem.as_bytes(), false).await?;
        if let Some(key_pem) = &material.key_pem {
            Self::write_atomic(&dir.join("key.pem"), key_pem.as_bytes(), true).await?;
        }
        let metadata = Metadata {
            version_id: version_id.clone(),
            lineage_id: version.lineage_id.to_string(),
            serial: version.serial.clone(),
            not_after: version.not_after.clone(),
            fingerprint: fingerprint(&material.full_chain_pem)?,
        };
        let metadata_bytes = serde_json::to_vec_pretty(&metadata)?;
        Self::write_atomic(&dir.join("metadata.json"), &metadata_bytes, false).await?;

        Ok(StagedDeployment {
            sink_id: self.sink_id().to_string(),
            version_id: version.id.clone(),
            staged_ref: dir.to_string_lossy().to_string(),
            deployment_id: None,
        })
    }

    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let version_id = staged.version_id.to_string();
        let dir = self.version_dir(&version_id);
        if !dir.exists() {
            return Err(AcmeError::NotFound(format!(
                "staged version {version_id} missing"
            )));
        }
        self.swap_pointer(&version_id)
    }

    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let staged_dir = PathBuf::from(&staged.staged_ref);
        let expected = match fs::read(staged_dir.join("metadata.json")).await {
            Ok(bytes) => {
                serde_json::from_slice::<Metadata>(&bytes)
                    .map_err(|e| AcmeError::storage(format!("corrupt staged metadata: {e}")))?
                    .fingerprint
            }
            Err(e) => {
                return Ok(DeploymentHealth {
                    healthy: false,
                    detail: Some(format!("staged metadata unreadable: {e}")),
                });
            }
        };
        match self.current_fingerprint().await? {
            Some(current) if current == expected => Ok(DeploymentHealth {
                healthy: true,
                detail: None,
            }),
            Some(current) => Ok(DeploymentHealth {
                healthy: false,
                detail: Some(format!(
                    "current serves fingerprint {current}, expected {expected}"
                )),
            }),
            None => Ok(DeploymentHealth {
                healthy: false,
                detail: Some("no live pointer".to_string()),
            }),
        }
    }

    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let version_id = staged.version_id.to_string();
        let previous = self.previous_pointer(&version_id);
        if !previous.exists() {
            return Err(AcmeError::NotFound(format!(
                "no previous pointer recorded for {version_id}; cannot roll back"
            )));
        }
        let pointer = self.pointer();
        let _ = std::fs::remove_file(&pointer);
        std::fs::rename(&previous, &pointer)
            .map_err(|e| AcmeError::storage(format!("rollback failed: {e}")))?;
        Ok(())
    }

    async fn cleanup(&self, staged: &StagedDeployment) -> Result<SinkCleanupOutcome> {
        let dir = PathBuf::from(&staged.staged_ref);
        // Never remove the version the pointer serves.
        if let Some(current) = self.current_version()
            && dir.ends_with(&current)
        {
            return Ok(SinkCleanupOutcome::AlreadyAbsent);
        }
        match fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(SinkCleanupOutcome::Removed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(SinkCleanupOutcome::AlreadyAbsent)
            }
            Err(e) => Err(AcmeError::storage(format!("cleanup failed: {e}"))),
        }
    }
}
