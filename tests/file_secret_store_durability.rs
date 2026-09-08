//! Durability-contract tests for the file secret store.
//!
//! Secret writes (ACME account keys!) must be unconditionally durable:
//! every `put` runs the full `temp file (0600) → fsync → rename → fsync
//! parent dir (unix)` sequence and is never governed by the repository's
//! `FsyncMode`. These tests lock that contract from outside the crate: the
//! fsync syscalls themselves cannot be observed portably, so the store
//! exposes the `SECRET_PUT_*` evidence counters (see
//! `acmex::repository::secret_store`), and every test below asserts on
//! counter deltas around real `put` calls.

use std::sync::atomic::Ordering;

use acmex::error::AcmeError;
use acmex::repository::secret_store::{
    FileSecretStore, SECRET_PUT_DIR_FSYNCS, SECRET_PUT_FILE_FSYNCS,
};

// A tiny temp-dir helper so the test does not need a `tempfile` dependency
// (mirrors the unit-test helper in `src/repository/secret_store.rs`).
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

    pub fn guard(label: &str) -> TempDirGuard {
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "acmex-secret-durability-{label}-{}-{}",
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&path).expect("temp dir create");
        TempDirGuard { path }
    }
}

/// A successful `put` performs a file fsync per call and, on unix, a
/// parent-directory fsync per call — the observable proof that the
/// durability sequence is exercised end to end. The counters are
/// process-global and other tests write secrets concurrently, so the
/// assertions require growth by *at least* the number of puts performed in
/// the measured window: concurrent writes can only add increments, never
/// mask ours.
#[tokio::test]
async fn put_exercises_fsync_on_every_write() {
    let dir = tempfile::guard("fsync-counts");
    let store = FileSecretStore::new(dir.path.join("secrets"));

    let before_file = SECRET_PUT_FILE_FSYNCS.load(Ordering::SeqCst);
    let before_dir = SECRET_PUT_DIR_FSYNCS.load(Ordering::SeqCst);

    store.put("key_one", b"payload one").await.unwrap();
    assert!(
        SECRET_PUT_FILE_FSYNCS.load(Ordering::SeqCst) > before_file,
        "the first put must fsync the temp file before the rename"
    );
    #[cfg(unix)]
    assert!(
        SECRET_PUT_DIR_FSYNCS.load(Ordering::SeqCst) > before_dir,
        "the first put must fsync the secret directory after the rename"
    );

    // Overwrites are full writes: same durability per call.
    store.put("key_two", b"payload two").await.unwrap();
    store.put("key_one", b"payload one v2").await.unwrap();
    assert!(
        SECRET_PUT_FILE_FSYNCS.load(Ordering::SeqCst) >= before_file + 3,
        "every put, overwrite or not, must fsync"
    );
    #[cfg(unix)]
    assert!(
        SECRET_PUT_DIR_FSYNCS.load(Ordering::SeqCst) >= before_dir + 3,
        "every rename must be made durable by a directory fsync"
    );

    // The values are readable afterwards, through a fresh store handle
    // (i.e. from disk, not from any in-process cache).
    let reopened = FileSecretStore::new(dir.path.join("secrets"));
    assert_eq!(
        reopened.get("key_one").await.unwrap(),
        Some(b"payload one v2".to_vec())
    );
}

/// Secrets are created owner-only (0600) on unix — from the first byte,
/// not merely after a post-write chmod — and overwrites replace the value
/// without leaving temp files behind.
#[tokio::test]
async fn put_creates_owner_only_files_and_no_leftover_temps() {
    let dir = tempfile::guard("permissions");
    let store = FileSecretStore::new(dir.path.join("secrets"));
    store.put("key_perm", b"first").await.unwrap();
    store.put("key_perm", b"second").await.unwrap();

    assert_eq!(
        store.get("key_perm").await.unwrap(),
        Some(b"second".to_vec())
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = store.root().join(format!(
            "{}.enc",
            // The store percent-encodes ids; `key_perm` is already safe.
            "key_perm"
        ));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "secret file must be exactly 0600");
    }

    // Exactly one file remains: the final secret, never a temp file.
    let mut names = Vec::new();
    let mut entries = tokio::fs::read_dir(store.root()).await.unwrap();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        names.push(entry.file_name().to_string_lossy().to_string());
    }
    assert_eq!(names.len(), 1, "no temp files may survive: {names:?}");
    assert!(names[0].ends_with(".enc"));
}

/// A bad root path (a regular file where the secret directory should be)
/// fails as a classified Storage error — a terminal setup failure for this
/// call, retryable only after removing the blocker — and neither the error
/// message nor its Debug output ever contains the secret bytes.
#[tokio::test]
async fn bad_root_path_classifies_as_storage_and_never_leaks_secret() {
    let dir = tempfile::guard("bad-root");
    let root = dir.path.join("secrets");
    std::fs::write(&root, b"i am a regular file").unwrap();
    let store = FileSecretStore::new(&root);

    let secret = b"never-leak-me-42";
    let err = store.put("key_bad", secret).await.unwrap_err();
    assert!(
        matches!(err, AcmeError::Storage(_)),
        "bad root must classify as Storage, got: {err:?}"
    );
    let rendered = format!("{err}{err:?}");
    assert!(
        !rendered.contains("never-leak-me-42"),
        "secret bytes leaked into error output: {rendered}"
    );
}
