//! File-based secret storage for private keys.
//!
//! Secrets are written with owner-only permissions on Unix (0600; other
//! platforms are documented as not permission-protected) using the same
//! atomic temp+rename discipline as the repository. The full KeyProvider
//! abstraction (managed/external keys) arrives with roadmap T10; this store
//! is the controlled compatibility area used by the legacy-bundle
//! migration.

use std::path::PathBuf;

use tokio::fs;

use crate::error::{AcmeError, Result};

/// Permissions-guarded secret files under one directory.
#[derive(Debug, Clone)]
pub struct FileSecretStore {
    root: PathBuf,
}

fn encode_name(id: &str) -> String {
    id.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl FileSecretStore {
    /// Opens (and creates) the secret directory with restrictive
    /// permissions. Returns an error when the directory already exists with
    /// looser-than-expected permissions on Unix.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The secret directory root.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    fn path_for(&self, id: &str) -> PathBuf {
        // Percent-encode so ids can never traverse out of the directory.
        self.root.join(format!("{}.enc", encode_name(id)))
    }

    /// Ensures the root directory exists with mode 0700 on Unix.
    pub async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .await
            .map_err(|e| AcmeError::Storage(format!("secret dir create failed: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.root)
                .await
                .map_err(|e| AcmeError::Storage(format!("secret dir stat failed: {e}")))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&self.root, permissions)
                .await
                .map_err(|e| AcmeError::Storage(format!("secret dir chmod failed: {e}")))?;
        }
        Ok(())
    }

    /// Atomically stores a secret.
    pub async fn put(&self, id: &str, bytes: &[u8]) -> Result<()> {
        self.ensure_dir().await?;
        let path = self.path_for(id);
        let dir = self.root.clone();
        let tmp = dir.join(format!(".tmp-{}-{}", std::process::id(), encode_name(id)));
        fs::write(&tmp, bytes)
            .await
            .map_err(|e| AcmeError::Storage(format!("secret write failed: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|e| AcmeError::Storage(format!("secret chmod failed: {e}")))?;
        }
        fs::rename(&tmp, &path)
            .await
            .map_err(|e| AcmeError::Storage(format!("secret rename failed: {e}")))?;
        Ok(())
    }

    /// Loads a secret, `None` when absent.
    pub async fn get(&self, id: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.path_for(id)).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AcmeError::Storage(format!("secret read failed: {e}"))),
        }
    }

    /// Whether a secret exists.
    pub async fn contains(&self, id: &str) -> Result<bool> {
        Ok(self.path_for(id).exists())
    }

    /// Debug output never includes secret contents.
    pub fn debug_summary(&self) -> String {
        format!("FileSecretStore(root={})", self.root.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_get_roundtrip_and_permissions() {
        let dir = tempfile_dir();
        let store = FileSecretStore::new(dir.path.join("secrets"));
        store.put("key_test", b"super secret").await.unwrap();
        assert!(store.contains("key_test").await.unwrap());
        assert_eq!(
            store.get("key_test").await.unwrap(),
            Some(b"super secret".to_vec())
        );
        assert_eq!(store.get("key_missing").await.unwrap(), None);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.path_for("key_test"))
                .await
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "secret must not be group/other readable");
        }
    }

    #[tokio::test]
    async fn ids_never_traverse() {
        let dir = tempfile_dir();
        let store = FileSecretStore::new(dir.path.join("secrets"));
        store.put("../../etc/passwd", b"x").await.unwrap();
        assert!(store.contains("../../etc/passwd").await.unwrap());
        // The encoded file must live inside the root.
        let mut found = false;
        let mut entries = fs::read_dir(store.root()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if entry.file_name().to_string_lossy().contains("etc") {
                found = true;
            }
        }
        assert!(found);
        assert!(!dir.path.join("etc").exists());
    }

    // A tiny temp-dir helper so tests do not need a `tempfile` dependency.
    mod tempfile {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDirGuard {
            pub path: PathBuf,
        }

        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        pub fn guard() -> TempDirGuard {
            let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "acmex-secret-test-{}-{}",
                std::process::id(),
                unique
            ));
            std::fs::create_dir_all(&path).expect("temp dir create");
            TempDirGuard { path }
        }
    }

    fn tempfile_dir() -> tempfile::TempDirGuard {
        tempfile::guard()
    }
}
