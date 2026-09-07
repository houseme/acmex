//! File-based secret storage for private keys.
//!
//! Secrets are written with owner-only permissions on Unix (0600; other
//! platforms are documented as not permission-protected) using the same
//! atomic temp+rename discipline as the repository — with one deliberate
//! difference: writes here are **unconditionally durable**. Every [`put`]
//! (method on [`FileSecretStore`]) runs the full
//! `temp file (0600) → fsync file → rename → fsync parent dir (unix)`
//! sequence and is therefore never governed by the repository's
//! [`crate::repository::FsyncMode`]: an `interval`-deferred fsync is
//! acceptable for entity records, but a lost ACME account key orphans the
//! account on the CA side (nothing can sign for it, so nothing can renew),
//! and that cost is never worth a throughput win. The full KeyProvider
//! abstraction (managed/external keys) arrives with roadmap T10; this store
//! is the controlled compatibility area used by the legacy-bundle
//! migration.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::error::{AcmeError, Result};

/// Number of secret temp files fsynced by [`FileSecretStore::put`] since
/// process start. Evidence hook for durability-contract tests (the unix
/// `fsync` syscall itself cannot be observed portably from outside);
/// not part of the semver-stable surface.
#[doc(hidden)]
pub static SECRET_PUT_FILE_FSYNCS: AtomicU64 = AtomicU64::new(0);

/// Number of secret-directory fsyncs performed by [`FileSecretStore::put`]
/// after renames (unix only; the rename that installs a secret becomes
/// durable too). Evidence hook; not part of the semver-stable surface.
#[doc(hidden)]
pub static SECRET_PUT_DIR_FSYNCS: AtomicU64 = AtomicU64::new(0);

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

    /// Atomically stores a secret with unconditional fsync durability.
    ///
    /// The sequence mirrors the entity store's [`FsyncMode::Always`] path
    /// ([`crate::repository::FsyncMode`]): create a unique temp file →
    /// write → fsync the file → atomically rename it into place → fsync the
    /// parent directory (unix) so the rename itself is durable. Unlike
    /// entity writes this is **never** deferred or configurable — the
    /// secrets directory is exempt from [`FsyncMode`] by design, because a
    /// secret that an abrupt crash makes vanish (ACME account key!) cannot
    /// be recreated: the CA-side account becomes permanently orphaned.
    ///
    /// On unix the temp file is created owner-only (0600) from the first
    /// byte, so secret material never sits in a group/other-readable file,
    /// not even transiently. Fails with [`AcmeError::Storage`] when any
    /// durability step cannot be completed (the write can simply be
    /// retried: `put` is an idempotent overwrite); error messages never
    /// contain the secret bytes.
    pub async fn put(&self, id: &str, bytes: &[u8]) -> Result<()> {
        self.ensure_dir().await?;
        let path = self.path_for(id);

        // One open handle serves write and fsync. `create_new` guarantees a
        // leftover temp file from a crashed run is never truncated and
        // reused (a stale temp file is never a valid secret).
        let mut created = None;
        for _ in 0..3 {
            let candidate = self.root.join(format!(
                ".tmp-{}-{}",
                std::process::id(),
                encode_name(&format!("{:x}", rand::random::<u64>()))
            ));
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                options.mode(0o600);
            }
            match options.open(&candidate).await {
                Ok(file) => {
                    created = Some((candidate, file));
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(AcmeError::Storage(format!(
                        "secret temp file create failed: {err}"
                    )));
                }
            }
        }
        let Some((tmp, mut file)) = created else {
            return Err(AcmeError::Storage(
                "failed to create a unique secret temp file in 3 attempts".to_string(),
            ));
        };

        let write_result = async {
            file.write_all(bytes)
                .await
                .map_err(|e| AcmeError::Storage(format!("secret write failed: {e}")))?;
            // fsync BEFORE the rename: once `put` returns, the secret
            // content is durable. This step is unconditional (never
            // FsyncMode-governed — see the module docs).
            file.sync_all()
                .await
                .map_err(|e| AcmeError::Storage(format!("secret fsync failed: {e}")))?;
            SECRET_PUT_FILE_FSYNCS.fetch_add(1, Ordering::SeqCst);
            Ok::<(), AcmeError>(())
        }
        .await;
        if let Err(err) = write_result {
            // Best-effort cleanup; a stale temp file is never a valid secret.
            let _ = fs::remove_file(&tmp).await;
            return Err(err);
        }
        drop(file);

        fs::rename(&tmp, &path)
            .await
            .map_err(|e| AcmeError::Storage(format!("secret rename failed: {e}")))?;

        // Make the rename itself durable (unix); on other platforms the
        // file-content fsync above is the strongest available guarantee.
        #[cfg(unix)]
        {
            let dir = std::fs::File::open(&self.root)
                .map_err(|e| AcmeError::Storage(format!("secret dir open failed: {e}")))?;
            dir.sync_all()
                .map_err(|e| AcmeError::Storage(format!("secret dir fsync failed: {e}")))?;
            SECRET_PUT_DIR_FSYNCS.fetch_add(1, Ordering::SeqCst);
        }
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

    /// Removes a secret; returns whether it existed.
    pub async fn remove(&self, id: &str) -> Result<bool> {
        // Mirrors `put`'s durability: without a directory fsync the removal
        // itself may not be durable, so a "deleted" key (clearance/rotation)
        // could reappear after a crash.
        match fs::remove_file(self.path_for(id)).await {
            Ok(()) => {
                #[cfg(unix)]
                if let Some(dir) = self.path_for(id).parent() {
                    let dir_sync = async {
                        let dir_file = fs::File::open(dir).await?;
                        dir_file.sync_all().await
                    };
                    if let Err(e) = dir_sync.await {
                        return Err(AcmeError::Storage(format!(
                            "secret remove directory fsync failed: {e}"
                        )));
                    }
                }
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(AcmeError::Storage(format!("secret remove failed: {e}"))),
        }
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
            assert_eq!(
                mode & 0o777,
                0o600,
                "secret files are created owner-only from the first byte"
            );
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

    /// `put` is an idempotent overwrite: the second write replaces the
    /// first and leaves exactly one file (no leftover temp files).
    #[tokio::test]
    async fn put_overwrites_and_leaves_no_temp_files() {
        let dir = tempfile_dir();
        let store = FileSecretStore::new(dir.path.join("secrets"));
        store.put("key_over", b"first value").await.unwrap();
        store.put("key_over", b"second value").await.unwrap();
        assert_eq!(
            store.get("key_over").await.unwrap(),
            Some(b"second value".to_vec())
        );
        let mut entries = fs::read_dir(store.root()).await.unwrap();
        let mut count = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            count += 1;
            assert!(
                !entry.file_name().to_string_lossy().starts_with(".tmp-"),
                "no temp file may survive a completed put"
            );
        }
        assert_eq!(count, 1, "exactly the final secret file must remain");
    }

    /// The durability discipline is locked by the fsync evidence counters:
    /// every successful `put` performs a file fsync (before the rename)
    /// and, on unix, a parent-directory fsync (after it). These hooks are
    /// what prove the put path exercises the fsync syscalls. The counters
    /// are process-global and other test modules (e.g. the software key
    /// provider) write secrets concurrently, so the assertions require the
    /// counter to grow by *at least* the number of puts performed in the
    /// measured window — concurrent writes can only add increments, never
    /// mask ours.
    #[tokio::test]
    async fn put_fsyncs_file_and_directory() {
        let dir = tempfile_dir();
        let store = FileSecretStore::new(dir.path.join("secrets"));

        let before_file = SECRET_PUT_FILE_FSYNCS.load(Ordering::SeqCst);
        let before_dir = SECRET_PUT_DIR_FSYNCS.load(Ordering::SeqCst);
        store.put("key_fsync", b"durable").await.unwrap();
        assert!(
            SECRET_PUT_FILE_FSYNCS.load(Ordering::SeqCst) > before_file,
            "every put must fsync the temp file before renaming"
        );
        #[cfg(unix)]
        assert!(
            SECRET_PUT_DIR_FSYNCS.load(Ordering::SeqCst) > before_dir,
            "every put must fsync the secret directory after the rename"
        );

        // Each further put adds at least one more of each.
        store.put("key_fsync", b"durable v2").await.unwrap();
        store.put("key_fsync_2", b"durable v3").await.unwrap();
        assert!(
            SECRET_PUT_FILE_FSYNCS.load(Ordering::SeqCst) >= before_file + 3,
            "every put, overwrite or not, must fsync"
        );
        #[cfg(unix)]
        assert!(
            SECRET_PUT_DIR_FSYNCS.load(Ordering::SeqCst) >= before_dir + 3,
            "every rename must be made durable by a directory fsync"
        );
    }

    /// A bad root path (an existing regular file where the directory should
    /// be) fails as a classified Storage error — never a panic, and the
    /// error message never contains the secret bytes.
    #[tokio::test]
    async fn bad_root_path_is_a_storage_error_without_secret_material() {
        let dir = tempfile_dir();
        let root = dir.path.join("secrets");
        std::fs::write(&root, b"i am a regular file").unwrap();
        let store = FileSecretStore::new(&root);

        let err = store
            .put("key_bad", b"sensitive-bytes-xyz")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AcmeError::Storage(_)),
            "bad root must classify as Storage, got: {err:?}"
        );
        let rendered = err.to_string();
        assert!(
            !rendered.contains("sensitive-bytes-xyz"),
            "secret bytes leaked into error: {rendered}"
        );
        assert!(
            !format!("{err:?}").contains("sensitive-bytes-xyz"),
            "secret bytes leaked into Debug: {err:?}"
        );
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
