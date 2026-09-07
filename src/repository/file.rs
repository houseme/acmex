//! File-backed repository with atomic writes and optimistic concurrency.
//!
//! Layout (one JSON file per entity):
//!
//! ```text
//! <root>/
//! ├── intents/<id>.json
//! ├── lineages/<id>.json
//! ├── versions/<id>.json
//! ├── operations/<id>.json
//! ├── challenge-leases/<id>.json
//! ├── deployments/<id>.json
//! ├── accounts/<id>.json
//! ├── outbox/<sequence>.json
//! ├── migration/manifest-<seq>.json
//! ├── locks/<key>.lock
//! └── secrets/            (FileSecretStore compatibility area)
//! ```
//!
//! Guarantees:
//! * writes go to a sibling temp file, are atomically renamed, and are made
//!   durable according to the store's [`FsyncMode`] (default
//!   [`FsyncMode::Always`]: fsync before the rename, exactly as in previous
//!   releases);
//! * IDs are filename-encoded so `/`, `..` and friends cannot escape;
//! * list returns entity IDs (never file names with extensions);
//! * corrupt JSON surfaces as an explicit `CorruptData` error;
//! * a stale temp file is never a valid entity.
//!
//! Atomicity caveat: the compare-and-set read/verify happens under an
//! in-process lock; cross-process mutation is guarded by the revision check
//! on write. Same-filesystem rename is required (documented).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use jiff::Timestamp;

use super::secret_store::FileSecretStore;
use super::{
    AccountRepository, CasOutcome, Clock, CreateOutcome, EntityStore, Envelope, FencingToken,
    LeaseGrant, LeaseManager, LeaseOutcome, MigrationManifestEntry, MigrationManifestStore,
    OutboxEvent, OutboxRepository, RepositorySet, Revision, Versioned, bump_envelope, corrupt,
    envelope_revision, make_envelope,
};
use crate::domain::AccountRecord;
use crate::error::{AcmeError, Result};

/// Freshness stamp of a cached parse: modification time, length and inode.
///
/// Every cache access re-stats the file, so writes from any process (this
/// one or an external one) invalidate the entry before the next read: the
/// repository's own writes (and any correctly implemented external writer)
/// go through atomic rename, which changes mtime, length *and* inode. The
/// inode component keeps the stamp reliable on filesystems with coarse mtime
/// granularity, where a same-length rewrite could otherwise reuse the old
/// mtime and slip a stale cached parse past the CAS revision check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    len: u64,
    /// Unix inode; `0` where the platform does not expose one (the stamp
    /// then degrades to mtime+len, see the `parse_cache` caveat).
    ino: u64,
}

/// Extracts the stamp of `meta`; `None` when the filesystem does not expose
/// modification times (caching is skipped for such files).
#[cfg(unix)]
fn file_stamp(meta: &std::fs::Metadata) -> Option<FileStamp> {
    use std::os::unix::fs::MetadataExt;
    Some(FileStamp {
        mtime: meta.modified().ok()?,
        len: meta.len(),
        ino: meta.ino(),
    })
}

/// Extracts the stamp of `meta`; `None` when the filesystem does not expose
/// modification times (caching is skipped for such files).
#[cfg(not(unix))]
fn file_stamp(meta: &std::fs::Metadata) -> Option<FileStamp> {
    Some(FileStamp {
        mtime: meta.modified().ok()?,
        len: meta.len(),
        ino: 0,
    })
}

/// A parsed entity JSON plus the stamp it was read at.
struct ParsedFile {
    stamp: FileStamp,
    /// Insertion sequence used to evict roughly-oldest entries first.
    stamp_seq: u64,
    value: Arc<Value>,
}

/// Maximum number of cached parsed entities. Bounded memory beats an
/// unbounded hit rate: misses only cost one extra read+parse.
const PARSE_CACHE_CAPACITY: usize = 8192;

/// Durability policy for file-backed writes.
///
/// The trade-off is between write throughput and how much an abrupt crash
/// (process kill, power loss) can undo:
///
/// * [`FsyncMode::Always`] — the default, and the behavior of every release
///   before the mode existed. Each write goes to a temp file that is fsynced
///   *before* it is atomically renamed into place, so once a write call
///   returns, the entity is durable. A crash can lose at most the single
///   write that was in flight. Choose this unless the workload explicitly
///   tolerates a bounded durability window.
/// * [`FsyncMode::Interval`] — explicit opt-in group commit, similar in
///   spirit to Redis AOF `everysec`. Writes become visible immediately (the
///   atomic rename still happens on the write path), but the fsync is
///   performed by a background sweeper at most one `interval` window later;
///   dropping the store performs a final flush and joins the sweeper. A
///   crash can lose up to one interval window of acknowledged writes. On
///   unix the sweeper also fsyncs each affected directory, so the renames
///   (and deletions) themselves become durable; on other platforms only the
///   file contents are synced. Choose this for bulk-write-heavy workloads
///   (imports, mass issuance, benchmarking) that can tolerate that window;
///   call [`FileEntityStore::sync_pending`] to force durability before a
///   checkpoint.
///
/// The mode governs entity, lock, lease, manifest and outbox files written
/// by this store. It does not extend to the separate `secrets/` store
/// ([`crate::repository::secret_store::FileSecretStore`]), which always
/// writes through its own path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FsyncMode {
    /// fsync every write before its rename (durable per write; historical
    /// behavior and the default).
    #[default]
    Always,
    /// fsync deferred to a background sweeper at most `interval` after the
    /// write; final flush on drop.
    Interval(Duration),
}

/// Files and directories written since the last completed fsync sweep.
#[derive(Default)]
struct FsyncQueue {
    /// Final entity paths (post-rename) awaiting fsync.
    files: HashSet<PathBuf>,
    /// Directories whose renames/deletions await fsync.
    dirs: HashSet<PathBuf>,
    /// Set on drop of the last store clone; the sweeper performs one final
    /// flush and exits.
    shutdown: bool,
}

impl FsyncQueue {
    fn take_batch(&mut self) -> (HashSet<PathBuf>, HashSet<PathBuf>) {
        (
            std::mem::take(&mut self.files),
            std::mem::take(&mut self.dirs),
        )
    }
}

/// Shared state of the [`FsyncMode::Interval`] background sweeper.
struct FsyncShared {
    queue: Mutex<FsyncQueue>,
    /// Wakes the sweeper for shutdown; sweeps are interval-driven, so
    /// ordinary writes do not signal.
    signal: Condvar,
    /// Sweeper thread handle; `None` after join or if the thread could not
    /// be spawned (in which case only `sync_pending`/drop flush).
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Files fsynced so far. `Always` mode fsyncs inline and never counts
    /// through this counter.
    fsynced_files: AtomicU64,
    /// Live [`FileEntityStore`] clones sharing this sweeper state. The
    /// store that created it registers `1`; every `Clone` increments and
    /// every `Drop` decrements. The last one out shuts the sweeper down.
    /// An explicit counter beats `Arc::strong_count`: the sweeper thread
    /// itself holds an `Arc`, so a strong-count check needs fragile
    /// offset arithmetic, and observation handles would keep the sweeper
    /// alive forever.
    store_clones: AtomicUsize,
}

impl FsyncShared {
    fn new() -> Self {
        Self {
            queue: Mutex::new(FsyncQueue::default()),
            signal: Condvar::new(),
            worker: Mutex::new(None),
            fsynced_files: AtomicU64::new(0),
            store_clones: AtomicUsize::new(0),
        }
    }

    fn mark_file(&self, path: PathBuf) {
        self.queue
            .lock()
            .expect("fsync queue poisoned")
            .files
            .insert(path);
    }

    fn mark_dir(&self, path: PathBuf) {
        self.queue
            .lock()
            .expect("fsync queue poisoned")
            .dirs
            .insert(path);
    }

    fn take_batch(&self) -> (HashSet<PathBuf>, HashSet<PathBuf>) {
        self.queue
            .lock()
            .expect("fsync queue poisoned")
            .take_batch()
    }

    fn request_shutdown(&self) {
        self.queue.lock().expect("fsync queue poisoned").shutdown = true;
        self.signal.notify_all();
    }
}

/// Maximum worker threads [`fsync_batch`] uses to fsync one batch of dirty
/// files in parallel, further capped by the CPU count and the batch size.
///
/// Trade-offs: fsync is pure IO wait, so N independent files complete in
/// roughly `ceil(N / workers)` device round-trips instead of N serial ones.
/// 8 workers keep a typical SSD/NVMe queue busy without oversaturating it;
/// on a seek-bound spinning disk concurrent fsyncs can actually be *slower*
/// than the serial sweep, so this is a deliberately conservative constant
/// (not `available_parallelism()`) — a future device probe could pick it at
/// runtime, but no such probe exists today.
const FSYNC_BATCH_WORKERS: usize = 8;

/// Result of fsyncing one deferred file (see [`fsync_batch`]).
enum DeferredFsync {
    /// File fsynced; already counted through the shared counter.
    Synced,
    /// File vanished before its fsync window elapsed (deleted): nothing
    /// left to make durable, but the parent directory is still synced so
    /// the deletion itself becomes durable.
    Vanished,
    /// Could not be fsynced (already warned); must be requeued.
    Failed,
}

/// fsyncs one deferred file. Shared by the serial and the parallel path of
/// [`fsync_batch`] so both keep identical semantics: per-file counting
/// through `counter`, a warning plus requeue on failure, and a vanished
/// file whose parent directory still gets synced.
fn fsync_one_file(path: &Path, counter: &AtomicU64) -> DeferredFsync {
    match std::fs::File::open(path) {
        Ok(file) => match file.sync_all() {
            Ok(()) => {
                counter.fetch_add(1, Ordering::Relaxed);
                DeferredFsync::Synced
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "file repository: deferred fsync failed"
                );
                DeferredFsync::Failed
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DeferredFsync::Vanished,
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "file repository: deferred fsync failed"
            );
            DeferredFsync::Failed
        }
    }
}

/// fsyncs every file in `files`, then every affected parent directory, so
/// both the file contents and the renames that installed them become
/// durable. Returns the paths that could not be synced; files deleted
/// before their fsync window elapsed are dropped (nothing left to make
/// durable) but their directories are still synced so the deletion itself
/// becomes durable.
///
/// The per-file fsyncs are mutually independent pure-IO waits, so batches of
/// two or more files are handed to a bounded pool of scoped threads (see
/// [`FSYNC_BATCH_WORKERS`]); each worker collects its own failures and
/// parent directories in thread-local `Vec`s that are merged after the
/// join, and the shared `counter` is still bumped per successfully fsynced
/// file. Directories are always fsynced afterwards on the calling thread,
/// so a directory fsync never races the fsync of a file it contains.
fn fsync_batch(
    files: &HashSet<PathBuf>,
    dirs: &HashSet<PathBuf>,
    counter: &AtomicU64,
) -> (u64, Vec<PathBuf>, Vec<PathBuf>) {
    let mut synced = 0u64;
    let mut pending_dirs: HashSet<PathBuf> = dirs.clone();
    let mut failed_files = Vec::new();
    // Stable task list: `HashSet` order is arbitrary, and workers pull the
    // next index atomically, so every file is fsynced exactly once no
    // matter which worker takes it.
    let ordered: Vec<&Path> = files.iter().map(|path| path.as_path()).collect();
    // Below two files there is nothing to parallelize and thread spawns
    // would cost more than the fsyncs save.
    if ordered.len() >= 2 {
        let workers = FSYNC_BATCH_WORKERS
            .min(std::thread::available_parallelism().map_or(1, |n| n.get()))
            .min(ordered.len());
        let next_index = AtomicUsize::new(0);
        let per_worker: Vec<(u64, Vec<PathBuf>, Vec<PathBuf>)> = std::thread::scope(|scope| {
            (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        let mut synced = 0u64;
                        let mut failed = Vec::new();
                        let mut parents = Vec::new();
                        loop {
                            let index = next_index.fetch_add(1, Ordering::Relaxed);
                            let Some(path) = ordered.get(index) else {
                                break;
                            };
                            // Per-file catch_unwind: a panic (a bug — the
                            // IO paths are infallible classifications)
                            // degrades exactly that file to Failed so the
                            // requeue keeps durability honest instead of
                            // unwinding the worker or the batch.
                            let outcome =
                                std::panic::catch_unwind(|| fsync_one_file(path, counter))
                                    .unwrap_or(DeferredFsync::Failed);
                            match outcome {
                                DeferredFsync::Synced => {
                                    synced += 1;
                                    if let Some(dir) = path.parent() {
                                        parents.push(dir.to_path_buf());
                                    }
                                }
                                DeferredFsync::Vanished => {
                                    if let Some(dir) = path.parent() {
                                        parents.push(dir.to_path_buf());
                                    }
                                }
                                DeferredFsync::Failed => failed.push(path.to_path_buf()),
                            }
                        }
                        (synced, failed, parents)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| {
                    // Unreachable in practice after the per-file
                    // catch_unwind above; degrade rather than panic the
                    // sweep. Per-file failures are still requeued by the
                    // caller, so no durability claim is lost.
                    handle.join().unwrap_or((0_u64, Vec::new(), Vec::new()))
                })
                .collect()
        });
        for (worker_synced, worker_failed, worker_parents) in per_worker {
            synced += worker_synced;
            pending_dirs.extend(worker_parents);
            failed_files.extend(worker_failed);
        }
    } else {
        for path in &ordered {
            match fsync_one_file(path, counter) {
                DeferredFsync::Synced => {
                    synced += 1;
                    if let Some(dir) = path.parent() {
                        pending_dirs.insert(dir.to_path_buf());
                    }
                }
                DeferredFsync::Vanished => {
                    if let Some(dir) = path.parent() {
                        pending_dirs.insert(dir.to_path_buf());
                    }
                }
                DeferredFsync::Failed => failed_files.push(path.to_path_buf()),
            }
        }
    }
    let mut failed_dirs = Vec::new();
    #[cfg(unix)]
    for dir in &pending_dirs {
        match std::fs::File::open(dir) {
            Ok(dir_file) => {
                if let Err(err) = dir_file.sync_all() {
                    tracing::warn!(
                        error = %err,
                        dir = %dir.display(),
                        "file repository: deferred directory fsync failed"
                    );
                    failed_dirs.push(dir.clone());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    dir = %dir.display(),
                    "file repository: deferred directory fsync failed"
                );
                failed_dirs.push(dir.clone());
            }
        }
    }
    #[cfg(not(unix))]
    let _ = pending_dirs; // directory sync (rename durability) is unix-only
    (synced, failed_files, failed_dirs)
}

/// Number of `Interval`-mode sweeper threads that ran to a clean shutdown
/// (drop of the last store clone). Evidence hook for durability-contract
/// tests; not part of the semver-stable surface.
#[doc(hidden)]
pub static FSYNC_SWEEPER_SHUTDOWNS: AtomicU64 = AtomicU64::new(0);

/// Files fsynced by `Drop`'s final flush across all stores. Evidence hook
/// for durability-contract tests; not part of the semver-stable surface.
#[doc(hidden)]
pub static FSYNC_DROP_FLUSHES: AtomicU64 = AtomicU64::new(0);

/// Background sweeper for [`FsyncMode::Interval`]: sleeps in `interval`-sized
/// windows, then fsyncs everything written in the last window (batched, so a
/// burst of writes costs one sweep, not one fsync each). Shutdown interrupts
/// the wait immediately for a final flush.
fn fsync_sweeper(shared: Arc<FsyncShared>, interval: Duration) {
    loop {
        let (files, dirs, shutdown) = {
            let mut queue = shared.queue.lock().expect("fsync queue poisoned");
            if !queue.shutdown {
                let (guard, _timeout) = shared
                    .signal
                    .wait_timeout(queue, interval)
                    .expect("fsync queue poisoned");
                queue = guard;
            }
            let (files, dirs) = queue.take_batch();
            (files, dirs, queue.shutdown)
        };
        let (synced, failed_files, failed_dirs) = fsync_batch(&files, &dirs, &shared.fsynced_files);
        if !failed_files.is_empty() || !failed_dirs.is_empty() {
            let failed_file_count = failed_files.len();
            let failed_dir_count = failed_dirs.len();
            let mut queue = shared.queue.lock().expect("fsync queue poisoned");
            // Requeue in both cases: on shutdown the Drop final flush makes
            // one synchronous last attempt and warns (never pretends) if
            // durability still cannot be reached; otherwise the next sweep
            // retries.
            queue.files.extend(failed_files);
            queue.dirs.extend(failed_dirs);
            if queue.shutdown {
                tracing::warn!(
                    files = failed_file_count,
                    dirs = failed_dir_count,
                    "file repository: fsync failed during final sweep; retrying once more from the drop flush"
                );
            } else {
                tracing::warn!(
                    "file repository: deferred fsync failed; failed paths requeued for the next sweep"
                );
            }
        }
        if shutdown {
            // The final sweep is what makes the last window's writes
            // durable; record it alongside the Drop flush fallback.
            FSYNC_DROP_FLUSHES.fetch_add(synced, Ordering::SeqCst);
            FSYNC_SWEEPER_SHUTDOWNS.fetch_add(1, Ordering::SeqCst);
            return;
        }
    }
}

/// Internal durability state of a [`FileEntityStore`].
#[derive(Clone)]
enum FsyncState {
    Always,
    Interval {
        shared: Arc<FsyncShared>,
        interval: Duration,
    },
}

/// Filesystem store shared by all aggregates. Clones share state locks
/// (and, in `Interval` mode, register themselves in the sweeper's clone
/// count — see [`Self::clone`]).
pub struct FileEntityStore {
    root: PathBuf,
    /// Serializes read-modify-write cycles within this process.
    write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Cached next outbox sequence (initialized on first use).
    outbox_next: Arc<tokio::sync::Mutex<Option<u64>>>,
    manifest_next: Arc<tokio::sync::Mutex<Option<u64>>>,
    lease_tokens: Arc<tokio::sync::Mutex<HashMap<String, FencingToken>>>,
    /// Parsed entity files keyed by path, validated against the on-disk
    /// (mtime, len) stamp on every read (see [`Self::read_entity_json`]).
    /// Bounded by [`PARSE_CACHE_CAPACITY`] with oldest-first eviction.
    /// Plain `Mutex` is sufficient: no await happens while it is held.
    ///
    /// Cross-process caveat: correctness against external writers relies on
    /// the on-disk stamp changing. Atomic-rename writers (AcmeX itself, and
    /// any correctly implemented external writer) always change the inode on
    /// unix, so the stamp is detected even on coarse-mtime filesystems. An
    /// external writer that rewrites files *in place* with the same length
    /// on a coarse-mtime filesystem (NFS attribute caching, FAT) could
    /// evade the stamp; deploy one AcmeX instance per file repository root
    /// where that applies.
    parse_cache: Arc<Mutex<HashMap<PathBuf, ParsedFile>>>,
    /// Monotonic insertion sequence for approximate-LRU eviction.
    parse_cache_seq: Arc<AtomicU64>,
    /// Durability policy (see [`FsyncMode`]).
    fsync: FsyncState,
    /// Aggregate directories already confirmed to exist. Spares one `mkdir`
    /// syscall per write; [`Self::durable_write`] clears the cache entry for
    /// a directory whose write failed, so an externally removed directory is
    /// recreated by the retry exactly as an uncached store would.
    created_dirs: Arc<Mutex<HashSet<PathBuf>>>,
}

impl Clone for FileEntityStore {
    fn clone(&self) -> Self {
        if let FsyncState::Interval { shared, .. } = &self.fsync {
            shared.store_clones.fetch_add(1, Ordering::SeqCst);
        }
        Self {
            root: self.root.clone(),
            write_lock: Arc::clone(&self.write_lock),
            outbox_next: Arc::clone(&self.outbox_next),
            manifest_next: Arc::clone(&self.manifest_next),
            lease_tokens: Arc::clone(&self.lease_tokens),
            parse_cache: Arc::clone(&self.parse_cache),
            parse_cache_seq: Arc::clone(&self.parse_cache_seq),
            fsync: self.fsync.clone(),
            created_dirs: Arc::clone(&self.created_dirs),
        }
    }
}

impl FileEntityStore {
    /// Opens (or creates) a store rooted at `root` with the default
    /// durability policy ([`FsyncMode::Always`]).
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self::with_mode(root, FsyncMode::Always)
    }

    /// Opens (or creates) a store rooted at `root` with an explicit
    /// [`FsyncMode`]. Read the mode's documentation for the durability
    /// trade-offs before opting into [`FsyncMode::Interval`].
    pub fn with_mode(root: impl AsRef<Path>, mode: FsyncMode) -> Self {
        let fsync = match mode {
            FsyncMode::Always => FsyncState::Always,
            FsyncMode::Interval(interval) => {
                debug_assert!(
                    !interval.is_zero(),
                    "FsyncMode::Interval(0) would busy-loop the fsync sweeper"
                );
                let shared = Arc::new(FsyncShared::new());
                shared.store_clones.fetch_add(1, Ordering::SeqCst);
                match std::thread::Builder::new()
                    .name("acmex-file-fsync".to_string())
                    .spawn({
                        let shared = Arc::clone(&shared);
                        move || fsync_sweeper(shared, interval)
                    }) {
                    Ok(handle) => {
                        *shared.worker.lock().expect("fsync worker poisoned") = Some(handle);
                    }
                    Err(err) => {
                        // Durability degrades to explicit sync_pending/drop
                        // flushes; say so instead of pretending.
                        tracing::error!(
                            error = %err,
                            "file repository: failed to spawn fsync sweeper; Interval mode will only fsync on sync_pending and drop"
                        );
                    }
                }
                FsyncState::Interval { shared, interval }
            }
        };
        Self {
            root: root.as_ref().to_path_buf(),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            outbox_next: Arc::new(tokio::sync::Mutex::new(None)),
            manifest_next: Arc::new(tokio::sync::Mutex::new(None)),
            lease_tokens: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            parse_cache: Arc::new(Mutex::new(HashMap::new())),
            parse_cache_seq: Arc::new(AtomicU64::new(0)),
            fsync,
            created_dirs: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// The durability policy this store was opened with.
    pub fn fsync_mode(&self) -> FsyncMode {
        match &self.fsync {
            FsyncState::Always => FsyncMode::Always,
            FsyncState::Interval { interval, .. } => FsyncMode::Interval(*interval),
        }
    }

    /// Number of files fsynced by the background sweeper or by
    /// [`Self::sync_pending`] so far (always `0` for [`FsyncMode::Always`],
    /// which fsyncs inline and does not count through this counter).
    pub fn fsynced_file_count(&self) -> u64 {
        match &self.fsync {
            FsyncState::Always => 0,
            FsyncState::Interval { shared, .. } => shared.fsynced_files.load(Ordering::Relaxed),
        }
    }

    /// Forces a synchronous fsync of every write that is not yet durable.
    ///
    /// A no-op for [`FsyncMode::Always`] (every write already fsynced before
    /// it returned; returns `Ok(0)`). For [`FsyncMode::Interval`] this
    /// sweeps the deferred queue immediately and returns the number of files
    /// fsynced — use it to bound the durability window before a checkpoint.
    /// Fails if any file could not be fsynced (the failed paths stay queued
    /// for the sweeper); the rest of the batch is still attempted.
    /// fsyncs every path queued since the last completed sweep and returns
    /// the number of files *this call* synced. With a running background
    /// sweeper the count can be lower than the number of acknowledged
    /// writes (the sweeper may have drained some already); a returned count
    /// of `0` therefore does not imply "nothing was written".
    pub async fn sync_pending(&self) -> Result<u64> {
        let FsyncState::Interval { shared, .. } = &self.fsync else {
            return Ok(0);
        };
        let (files, dirs) = shared.take_batch();
        if files.is_empty() && dirs.is_empty() {
            return Ok(0);
        }
        let shared_for_task = Arc::clone(shared);
        let queued = tokio::task::spawn_blocking(move || {
            // catch_unwind: if fsync_batch panics, the outcome degrades to
            // "nothing synced, everything pending" so the requeue below
            // keeps every path queued and the error is surfaced.
            std::panic::catch_unwind(|| fsync_batch(&files, &dirs, &shared_for_task.fsynced_files))
                .unwrap_or_else(|_| {
                    (
                        0_u64,
                        files.iter().cloned().collect(),
                        dirs.iter().cloned().collect(),
                    )
                })
        })
        .await;
        // A JoinError here would mean the blocking task died before its
        // own catch_unwind could answer — practically impossible, and the
        // taken batch would be unrecoverable either way; surface it
        // loudly instead of pretending the sync happened.
        let (fsynced, failed_files, failed_dirs) = match queued {
            Ok(outcome) => outcome,
            Err(err) => {
                return Err(AcmeError::Storage(format!("fsync task failed: {err}")));
            }
        };
        if !failed_files.is_empty() || !failed_dirs.is_empty() {
            let mut queue = shared.queue.lock().expect("fsync queue poisoned");
            queue.files.extend(failed_files);
            queue.dirs.extend(failed_dirs);
            return Err(AcmeError::Storage(
                "deferred fsync failed for some pending writes; they stay queued for retry"
                    .to_string(),
            ));
        }
        Ok(fsynced)
    }

    /// The repository root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A file-based secret store under `<root>/secrets`.
    pub fn secret_store(&self) -> FileSecretStore {
        FileSecretStore::new(self.root.join("secrets"))
    }

    fn aggregate_dir(&self, aggregate: &str) -> PathBuf {
        self.root.join(aggregate)
    }

    fn entity_path(&self, aggregate: &str, id: &str) -> PathBuf {
        self.aggregate_dir(aggregate)
            .join(format!("{}.json", encode_file_name(id)))
    }

    /// Drops any cached parse for `path`. Called after every write so a
    /// rewrite can never be shadowed by a stale cached value.
    fn invalidate_parse_cache(&self, path: &Path) {
        self.parse_cache
            .lock()
            .expect("parse cache poisoned")
            .remove(path);
    }

    /// Reads and parses an entity file, returning cached parses while the
    /// on-disk (mtime, len) stamp is unchanged.
    ///
    /// The file is stat'ed on *every* call (cheap) before the cache is
    /// consulted, so a rewrite by any process invalidates the entry before
    /// the next read: every write lands through an atomic rename with a
    /// fresh mtime, which can never equal the stamp observed before the
    /// rewrite. On a miss the file is read and cached under the stamp taken
    /// *before* the read — if a write raced the read, its different stamp
    /// simply forces a miss next time, so no stale parse is ever served.
    async fn read_entity_json(&self, path: &Path) -> Result<Option<Arc<Value>>> {
        let stamp = match fs::metadata(path).await {
            Ok(meta) => file_stamp(&meta),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.invalidate_parse_cache(path);
                return Ok(None);
            }
            Err(err) => {
                return Err(AcmeError::Storage(format!(
                    "failed to read {}: {err}",
                    path.display()
                )));
            }
        };

        if let Some(stamp) = stamp {
            let cached = self
                .parse_cache
                .lock()
                .expect("parse cache poisoned")
                .get(path)
                .filter(|cached| cached.stamp == stamp)
                .map(|cached| Arc::clone(&cached.value));
            if let Some(value) = cached {
                return Ok(Some(value));
            }
        }

        let Some(value) = read_json(path).await? else {
            self.invalidate_parse_cache(path);
            return Ok(None);
        };
        let value = Arc::new(value);

        if let Some(stamp) = stamp {
            let mut cache = self.parse_cache.lock().expect("parse cache poisoned");
            // Bound the cache so a long-running daemon does not pin every
            // entity ever read (operations and outbox accumulate forever).
            // Eviction is purely a memory measure: correctness never depends
            // on a cached entry surviving, because every hit revalidates the
            // stat stamp first.
            if !cache.contains_key(path) && cache.len() >= PARSE_CACHE_CAPACITY {
                let mut oldest: Vec<(PathBuf, u64)> = cache
                    .iter()
                    .map(|(p, parsed)| (p.clone(), parsed.stamp_seq))
                    .collect();
                oldest.sort_unstable_by_key(|(_, seq)| *seq);
                for (path, _) in oldest.iter().take(cache.len() / 4) {
                    cache.remove(path);
                }
            }
            cache.insert(
                path.to_path_buf(),
                ParsedFile {
                    stamp,
                    stamp_seq: self.parse_cache_seq.fetch_add(1, Ordering::Relaxed),
                    value: Arc::clone(&value),
                },
            );
        }
        Ok(Some(value))
    }
}

/// Encodes an arbitrary entity id into a safe file name component.
///
/// Everything outside `[A-Za-z0-9._-]` is percent-encoded, so `..`, `/`,
/// `\`, `:` and Unicode never escape the aggregate directory or collide
/// with the `.json`/`.lock` suffixes.
pub(crate) fn encode_file_name(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for byte in id.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    if out.is_empty() {
        out.push_str("%00");
    }
    out
}

impl FileEntityStore {
    /// Atomically writes `bytes` to `path` (sibling temp file → rename),
    /// applying this store's [`FsyncMode`]. Under [`FsyncMode::Always`] the
    /// temp file is fsynced before the rename (historical behavior, byte
    /// -for-byte identical on-disk results); under [`FsyncMode::Interval`]
    /// the rename happens immediately and the fsync is deferred to the
    /// background sweeper.
    async fn durable_write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        match self.write_once(path, bytes).await {
            Ok(()) => Ok(()),
            Err(first) => {
                // `created_dirs` skips a mkdir per write; if a write failed
                // anyway, an external process may have removed the directory.
                // Drop the cache entry and retry once so the failure mode
                // matches an uncached store.
                let Some(dir) = path.parent() else {
                    return Err(first);
                };
                let cached = self
                    .created_dirs
                    .lock()
                    .expect("created dirs poisoned")
                    .remove(dir);
                if cached {
                    self.ensure_dir(dir).await?;
                    self.write_once(path, bytes).await
                } else {
                    Err(first)
                }
            }
        }
    }

    async fn write_once(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let dir = path
            .parent()
            .ok_or_else(|| AcmeError::Storage("entity path has no parent".to_string()))?;
        self.ensure_dir(dir).await?;

        // One open handle serves write and fsync (the previous implementation
        // wrote through `fs::write` and reopened the temp file just to fsync
        // it). `create_new` guarantees a stale temp file is never truncated.
        let mut created = None;
        for _ in 0..3 {
            let candidate = dir.join(format!(
                ".tmp-{}-{}",
                std::process::id(),
                encode_file_name(&format!("{:x}", rand::random::<u64>()))
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
                .await
            {
                Ok(file) => {
                    created = Some((candidate, file));
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(AcmeError::Storage(format!(
                        "failed to create temp file in {}: {err}",
                        dir.display()
                    )));
                }
            }
        }
        let Some((tmp, mut file)) = created else {
            return Err(AcmeError::Storage(
                "failed to create a unique temp file in 3 attempts".to_string(),
            ));
        };

        let write_result = async {
            file.write_all(bytes).await.map_err(|e| {
                AcmeError::Storage(format!("failed to write {}: {e}", tmp.display()))
            })?;
            #[cfg(unix)]
            if matches!(&self.fsync, FsyncState::Always) {
                // fsync the temp file before rename so the renamed content
                // is durable.
                file.sync_all().await.map_err(|e| {
                    AcmeError::Storage(format!("failed to fsync {}: {e}", tmp.display()))
                })?;
            }
            Ok::<(), AcmeError>(())
        }
        .await;
        if let Err(err) = write_result {
            // Best-effort cleanup; a stale temp file is never a valid entity.
            let _ = fs::remove_file(&tmp).await;
            return Err(err);
        }
        drop(file);

        fs::rename(&tmp, path).await.map_err(|e| {
            AcmeError::Storage(format!("failed to rename into {}: {e}", path.display()))
        })?;

        if let FsyncState::Interval { shared, .. } = &self.fsync {
            shared.mark_file(path.to_path_buf());
        }
        Ok(())
    }

    /// Creates `dir` unless it is already verified to exist (see
    /// [`Self::durable_write`] for the failure-path cache invalidation).
    async fn ensure_dir(&self, dir: &Path) -> Result<()> {
        if self
            .created_dirs
            .lock()
            .expect("created dirs poisoned")
            .contains(dir)
        {
            return Ok(());
        }
        fs::create_dir_all(dir)
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to create {}: {e}", dir.display())))?;
        self.created_dirs
            .lock()
            .expect("created dirs poisoned")
            .insert(dir.to_path_buf());
        Ok(())
    }

    /// Under [`FsyncMode::Interval`], queues the parent directory of `path`
    /// so a later sweep makes a rename or deletion itself durable. No-op for
    /// [`FsyncMode::Always`] (whose synchronous fsync + rename ordering is
    /// unchanged).
    fn mark_dir_durable(&self, path: &Path) {
        if let FsyncState::Interval { shared, .. } = &self.fsync
            && let Some(dir) = path.parent()
        {
            shared.mark_dir(dir.to_path_buf());
        }
    }
}

async fn read_json(path: &Path) -> Result<Option<Value>> {
    match fs::read(path).await {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .map(Some)
            .map_err(|e| {
                AcmeError::Storage(format!("corrupt entity file {}: {e}", path.display()))
            }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(AcmeError::Storage(format!(
            "failed to read {}: {err}",
            path.display()
        ))),
    }
}

impl Drop for FileEntityStore {
    fn drop(&mut self) {
        let FsyncState::Interval { shared, .. } = &self.fsync else {
            return;
        };
        // Only the last surviving clone owns the sweeper thread and the
        // final flush; earlier drops must not touch state shared with the
        // clones that outlive them. The explicit `store_clones` counter
        // (not `Arc::strong_count` — the sweeper thread holds an `Arc`
        // too) makes "last one out" exact.
        if shared.store_clones.fetch_sub(1, Ordering::SeqCst) > 1 {
            return;
        }
        shared.request_shutdown();
        let handle = shared.worker.lock().expect("fsync worker poisoned").take();
        if let Some(handle) = handle {
            // The sweeper performs its final sweep before exiting. A
            // panicked sweeper must not turn this Drop into a panic; the
            // synchronous last attempt below still covers whatever stayed
            // queued.
            if handle.join().is_err() {
                tracing::warn!(
                    "file repository: fsync sweeper thread ended abnormally; \
                     falling back to the synchronous final flush"
                );
            }
        }
        // Whatever remains are failed-retry paths from the final sweep: one
        // synchronous last attempt, warning (never pretending) on failure.
        let (files, dirs) = shared.take_batch();
        if !files.is_empty() || !dirs.is_empty() {
            let (synced, failed_files, failed_dirs) =
                fsync_batch(&files, &dirs, &shared.fsynced_files);
            FSYNC_DROP_FLUSHES.fetch_add(synced, Ordering::SeqCst);
            if !failed_files.is_empty() || !failed_dirs.is_empty() {
                tracing::warn!(
                    files = failed_files.len(),
                    dirs = failed_dirs.len(),
                    "file repository: writes may not be durable; fsync failed during final flush"
                );
            }
        }
    }
}

#[async_trait]
impl EntityStore for FileEntityStore {
    async fn env_get(&self, aggregate: &str, id: &str) -> Result<Option<Arc<Value>>> {
        self.read_entity_json(&self.entity_path(aggregate, id))
            .await
    }

    async fn env_create(
        &self,
        aggregate: &str,
        id: &str,
        data: &Value,
        now: Timestamp,
    ) -> Result<CreateOutcome> {
        let path = self.entity_path(aggregate, id);
        let _guard = self.write_lock.lock().await;
        if path.exists() {
            return Ok(CreateOutcome::AlreadyExists);
        }
        let envelope = make_envelope(data, now);
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        self.durable_write(&path, &bytes).await?;
        self.invalidate_parse_cache(&path);
        Ok(CreateOutcome::Created)
    }

    async fn env_cas(
        &self,
        aggregate: &str,
        id: &str,
        expected: Revision,
        data: &Value,
        now: Timestamp,
    ) -> Result<CasOutcome> {
        let path = self.entity_path(aggregate, id);
        let _guard = self.write_lock.lock().await;
        // Stamp-validated parse cache: CAS re-reads the envelope on every
        // call, and workflow steps CAS constantly, so serve unchanged files
        // from cache under the exact same staleness rules as `env_get`
        // (every write lands through a rename with a fresh mtime/len).
        let Some(existing) = self.read_entity_json(&path).await? else {
            return Err(corrupt(format!("{aggregate} `{id}` missing for update")));
        };
        let current = envelope_revision(&existing)?;
        if current != expected {
            return Ok(CasOutcome::Conflict { current });
        }
        let envelope = bump_envelope(&existing, data, now)?;
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        self.durable_write(&path, &bytes).await?;
        self.invalidate_parse_cache(&path);
        Ok(CasOutcome::Updated(current + 1))
    }

    async fn env_list(&self, aggregate: &str) -> Result<Vec<Envelope>> {
        let dir = self.aggregate_dir(aggregate);
        let mut entries = fs::read_dir(&dir).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AcmeError::Storage(format!("aggregate directory {} is missing", dir.display()))
            } else {
                AcmeError::Storage(format!("failed to list {}: {e}", dir.display()))
            }
        })?;
        let mut out = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to scan {}: {e}", dir.display())))?
        {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if !name.ends_with(".json") || name.starts_with(".tmp-") {
                continue;
            }
            let id = decode_file_name(name.trim_end_matches(".json"))
                .map_err(|e| corrupt(format!("unencodable file name {name:?}: {e}")))?;
            let path = entry.path();
            // Stat first (cheap) and reuse the cached parse while the file
            // is unchanged; only cache misses hit the filesystem read.
            let stamp = entry
                .metadata()
                .await
                .ok()
                .and_then(|meta| file_stamp(&meta));
            let value = if let Some(stamp) = stamp {
                self.parse_cache
                    .lock()
                    .expect("parse cache poisoned")
                    .get(&path)
                    .filter(|cached| cached.stamp == stamp)
                    .map(|cached| Arc::clone(&cached.value))
            } else {
                None
            };
            let value = match value {
                Some(value) => value,
                None => {
                    let parsed = read_json(&path)
                        .await?
                        .ok_or_else(|| corrupt(format!("entity file vanished: {name}")))?;
                    let value = Arc::new(parsed);
                    // Cache under the pre-read stamp (see
                    // `read_entity_json`): a racing rewrite carries a
                    // different stamp and forces a miss next time.
                    if let Some(stamp) = stamp {
                        self.parse_cache
                            .lock()
                            .expect("parse cache poisoned")
                            .insert(
                                path.clone(),
                                ParsedFile {
                                    stamp,
                                    stamp_seq: self.parse_cache_seq.fetch_add(1, Ordering::Relaxed),
                                    value: Arc::clone(&value),
                                },
                            );
                    }
                    value
                }
            };
            out.push(Envelope { id, value });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn env_delete(&self, aggregate: &str, id: &str) -> Result<()> {
        let path = self.entity_path(aggregate, id);
        self.invalidate_parse_cache(&path);
        match fs::remove_file(&path).await {
            Ok(()) => {
                self.mark_dir_durable(&path);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AcmeError::Storage(format!(
                "failed to delete {}: {e}",
                path.display()
            ))),
        }
    }
}

fn decode_file_name(encoded: &str) -> std::result::Result<String, String> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex_pair = encoded
                .get(i + 1..i + 3)
                .ok_or_else(|| "truncated escape".to_string())?;
            let byte = u8::from_str_radix(hex_pair, 16).map_err(|e| e.to_string())?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}

/// The file-backed repository.
pub struct FileRepository {
    store: FileEntityStore,
    clock: Arc<dyn Clock>,
}

impl FileRepository {
    /// Opens a repository rooted at `root` with the given clock and the
    /// default [`FsyncMode::Always`] durability.
    pub async fn with_clock(root: impl AsRef<Path>, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::with_clock_and_mode(root, clock, FsyncMode::Always).await
    }

    /// Opens a repository rooted at `root` with an explicit [`FsyncMode`]
    /// and the system clock. See [`FsyncMode`] for the durability contract
    /// of each mode; [`FsyncMode::Interval`] is an explicit opt-in that can
    /// lose up to one interval window of writes on an abrupt crash.
    pub async fn with_mode(root: impl AsRef<Path>, mode: FsyncMode) -> Result<Self> {
        Self::with_clock_and_mode(root, Arc::new(super::SystemClock), mode).await
    }

    /// Opens a repository rooted at `root` with the given clock and
    /// durability policy.
    pub async fn with_clock_and_mode(
        root: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
        mode: FsyncMode,
    ) -> Result<Self> {
        let store = FileEntityStore::with_mode(root, mode);
        for aggregate in [
            "intents",
            "lineages",
            "versions",
            "operations",
            "challenge-leases",
            "challenge-sessions",
            "deployments",
            "accounts",
            "outbox",
            "migration",
            "locks",
            "secrets",
        ] {
            fs::create_dir_all(store.aggregate_dir(aggregate))
                .await
                .map_err(|e| {
                    AcmeError::Storage(format!(
                        "failed to create repository directory `{aggregate}`: {e}"
                    ))
                })?;
        }
        Ok(Self { store, clock })
    }

    /// Opens a repository rooted at `root` using the system clock.
    pub async fn new(root: impl AsRef<Path>) -> Result<Self> {
        Self::with_clock(root, Arc::new(super::SystemClock)).await
    }

    /// The backing store (for the migrator).
    pub fn store(&self) -> &FileEntityStore {
        &self.store
    }

    /// Forces a synchronous fsync of every write that is not yet durable.
    /// See [`FileEntityStore::sync_pending`]; a no-op (returns `Ok(0)`) for
    /// [`FsyncMode::Always`].
    pub async fn sync_pending(&self) -> Result<u64> {
        self.store.sync_pending().await
    }

    /// Assembles the trait-object set backed by this instance.
    pub fn into_set(self) -> RepositorySet {
        let arc = Arc::new(self);
        let mk = || {
            Arc::new(super::GenericRepository::new(
                arc.store.clone(),
                arc.clock.clone(),
            ))
        };
        RepositorySet {
            backend: "file",
            intents: mk(),
            lineages: mk(),
            versions: mk(),
            operations: mk(),
            challenge_leases: mk(),
            challenge_sessions: mk(),
            deployments: mk(),
            accounts: arc.clone(),
            outbox: arc.clone(),
            leases: arc.clone(),
            manifests: arc.clone(),
            clock: arc.clock.clone(),
        }
    }

    fn lock_path(&self, key: &str) -> PathBuf {
        self.store
            .aggregate_dir("locks")
            .join(format!("{}.lock", encode_file_name(key)))
    }

    async fn read_lock(&self, path: &Path) -> Result<Option<LockFile>> {
        // Stamp-validated parse cache: leases are re-read on every acquire/
        // renew, so serve unchanged lock files from cache under the same
        // staleness rules as every other read.
        match self.store.read_entity_json(path).await? {
            Some(value) => Ok(Some(
                LockFile::deserialize(value.as_ref())
                    .map_err(|e| corrupt(format!("lock file {}: {e}", path.display())))?,
            )),
            None => Ok(None),
        }
    }

    async fn next_outbox_sequence(&self) -> Result<u64> {
        let mut next = self.store.outbox_next.lock().await;
        if let Some(cached) = *next {
            *next = Some(cached + 1);
            return Ok(cached);
        }
        // First use: scan the directory for the highest sequence.
        let dir = self.store.aggregate_dir("outbox");
        let mut entries = fs::read_dir(&dir)
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to list {}: {e}", dir.display())))?;
        let mut max = 0u64;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to scan {}: {e}", dir.display())))?
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_suffix(".json")
                && let Ok(sequence) = stem.parse::<u64>()
            {
                max = max.max(sequence);
            }
        }
        let assigned = max + 1;
        *next = Some(assigned + 1);
        Ok(assigned)
    }

    async fn next_manifest_sequence(&self) -> Result<u64> {
        let mut next = self.store.manifest_next.lock().await;
        if let Some(cached) = *next {
            *next = Some(cached + 1);
            return Ok(cached);
        }
        let dir = self.store.aggregate_dir("migration");
        let mut entries = fs::read_dir(&dir)
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to list {}: {e}", dir.display())))?;
        let mut max = 0u64;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to scan {}: {e}", dir.display())))?
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_prefix("manifest-")
                && let Some(stem) = stem.strip_suffix(".json")
                && let Ok(sequence) = stem.parse::<u64>()
            {
                max = max.max(sequence);
            }
        }
        *next = Some(max + 1);
        Ok(max + 1)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LockFile {
    owner: String,
    fencing_token: FencingToken,
    /// Expiry as epoch milliseconds (numeric to avoid string parsing).
    expires_at_epoch_ms: i64,
}

fn epoch_ms(timestamp: Timestamp) -> i64 {
    timestamp.as_millisecond()
}

fn from_epoch_ms(ms: i64) -> Result<Timestamp> {
    Timestamp::from_millisecond(ms).map_err(|e| corrupt(format!("bad lock expiry: {e}")))
}

#[async_trait]
impl LeaseManager for FileRepository {
    async fn acquire(&self, key: &str, owner: &str, ttl: Duration) -> Result<LeaseOutcome> {
        let path = self.lock_path(key);
        let _guard = self.store.write_lock.lock().await;
        let now = self.clock.now();
        let expires = now
            .checked_add(jiff::Span::new().milliseconds(ttl.as_millis() as i64))
            .expect("lease ttl overflow");
        if let Some(existing) = self.read_lock(&path).await? {
            let expires_at = from_epoch_ms(existing.expires_at_epoch_ms)?;
            if expires_at > now && existing.owner != owner {
                return Ok(LeaseOutcome::HeldByOther {
                    owner: existing.owner,
                    expires_at,
                });
            }
        }
        // Fencing tokens must be strictly monotonic per key, including
        // across takeovers: persist max(previous, counter)+1.
        let token = {
            let mut tokens = self.store.lease_tokens.lock().await;
            let previous = tokens.get(key).copied().unwrap_or(0);
            let from_file = self
                .read_lock(&path)
                .await?
                .map(|l| l.fencing_token)
                .unwrap_or(0);
            let next = previous.max(from_file) + 1;
            tokens.insert(key.to_string(), next);
            next
        };
        let lock = LockFile {
            owner: owner.to_string(),
            fencing_token: token,
            expires_at_epoch_ms: epoch_ms(expires),
        };
        let bytes = serde_json::to_vec(&lock)?;
        self.store.durable_write(&path, &bytes).await?;
        self.store.invalidate_parse_cache(&path);
        Ok(LeaseOutcome::Granted(LeaseGrant {
            key: key.to_string(),
            owner: owner.to_string(),
            fencing_token: token,
            expires_at: expires,
        }))
    }

    async fn renew(
        &self,
        key: &str,
        owner: &str,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<Option<LeaseGrant>> {
        let path = self.lock_path(key);
        let _guard = self.store.write_lock.lock().await;
        let now = self.clock.now();
        let Some(existing) = self.read_lock(&path).await? else {
            return Ok(None);
        };
        let expires_at = from_epoch_ms(existing.expires_at_epoch_ms)?;
        if existing.owner != owner || existing.fencing_token != fencing_token || expires_at <= now {
            return Ok(None);
        }
        let new_expiry = now
            .checked_add(jiff::Span::new().milliseconds(ttl.as_millis() as i64))
            .expect("lease ttl overflow");
        let lock = LockFile {
            owner: owner.to_string(),
            fencing_token,
            expires_at_epoch_ms: epoch_ms(new_expiry),
        };
        let bytes = serde_json::to_vec(&lock)?;
        self.store.durable_write(&path, &bytes).await?;
        self.store.invalidate_parse_cache(&path);
        Ok(Some(LeaseGrant {
            key: key.to_string(),
            owner: owner.to_string(),
            fencing_token,
            expires_at: new_expiry,
        }))
    }

    async fn release(&self, key: &str, owner: &str, fencing_token: FencingToken) -> Result<()> {
        let path = self.lock_path(key);
        let _guard = self.store.write_lock.lock().await;
        if let Some(existing) = self.read_lock(&path).await?
            && existing.owner == owner
            && existing.fencing_token == fencing_token
        {
            let _ = fs::remove_file(&path).await;
            self.store.invalidate_parse_cache(&path);
            self.store.mark_dir_durable(&path);
        }
        Ok(())
    }
}

#[async_trait]
impl OutboxRepository for FileRepository {
    async fn append(
        &self,
        event_type: &str,
        payload: Value,
        event_id: Option<String>,
    ) -> Result<u64> {
        let sequence = self.next_outbox_sequence().await?;
        let event = OutboxEvent {
            sequence,
            event_id: event_id.unwrap_or_else(|| format!("evt_{sequence:012}")),
            event_type: event_type.to_string(),
            payload,
            created_at: self.clock.now(),
            attempts: 0,
            last_error: None,
            next_attempt_at: None,
            processed: false,
            dead_lettered: false,
        };
        let path = self
            .store
            .aggregate_dir("outbox")
            .join(format!("{sequence:012}.json"));
        let bytes = serde_json::to_vec_pretty(&event)?;
        self.store.durable_write(&path, &bytes).await?;
        self.store.invalidate_parse_cache(&path);
        Ok(sequence)
    }

    async fn list_pending(&self, limit: usize) -> Result<Vec<OutboxEvent>> {
        let dir = self.store.aggregate_dir("outbox");
        let mut entries = fs::read_dir(&dir)
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to list {}: {e}", dir.display())))?;
        let mut events = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to scan {}: {e}", dir.display())))?
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".json") {
                continue;
            }
            let value = read_json(&entry.path())
                .await?
                .ok_or_else(|| corrupt("outbox entry vanished"))?;
            let event: OutboxEvent = serde_json::from_value(value)
                .map_err(|e| corrupt(format!("outbox entry {name}: {e}")))?;
            if !event.processed
                && !event.dead_lettered
                && event
                    .next_attempt_at
                    .is_none_or(|retry_at| retry_at <= self.clock.now())
            {
                events.push(event);
            }
        }
        events.sort_by_key(|e| e.sequence);
        events.truncate(limit);
        Ok(events)
    }

    async fn mark_processed(&self, sequence: u64) -> Result<()> {
        self.update_outbox(sequence, |event| event.processed = true)
            .await
    }

    async fn mark_failed(
        &self,
        sequence: u64,
        error: &str,
        next_attempt_at: Option<jiff::Timestamp>,
    ) -> Result<()> {
        self.update_outbox(sequence, |event| {
            event.attempts += 1;
            event.last_error = Some(error.to_string());
            event.next_attempt_at = next_attempt_at;
        })
        .await
    }

    async fn dead_letter(&self, sequence: u64, reason: &str) -> Result<()> {
        self.update_outbox(sequence, |event| {
            event.dead_lettered = true;
            event.last_error = Some(format!("dead-letter: {reason}"));
            event.next_attempt_at = None;
        })
        .await
    }

    async fn requeue(&self, sequence: u64) -> Result<()> {
        self.update_outbox(sequence, |event| {
            event.dead_lettered = false;
            event.processed = false;
            // Manual replay restarts the retry budget, matching the redis
            // backend's `OUTBOX_REQUEUE_LUA` contract.
            event.attempts = 0;
            event.last_error = None;
            event.next_attempt_at = None;
        })
        .await
    }
}

impl FileRepository {
    async fn update_outbox(
        &self,
        sequence: u64,
        mutate: impl FnOnce(&mut OutboxEvent),
    ) -> Result<()> {
        let path = self
            .store
            .aggregate_dir("outbox")
            .join(format!("{sequence:012}.json"));
        let _guard = self.store.write_lock.lock().await;
        let value = self
            .store
            .read_entity_json(&path)
            .await?
            .ok_or_else(|| corrupt(format!("outbox entry {sequence} missing")))?;
        let mut event: OutboxEvent = OutboxEvent::deserialize(value.as_ref())
            .map_err(|e| corrupt(format!("outbox entry {sequence}: {e}")))?;
        mutate(&mut event);
        let bytes = serde_json::to_vec_pretty(&event)?;
        self.store.durable_write(&path, &bytes).await?;
        self.store.invalidate_parse_cache(&path);
        Ok(())
    }
}

#[async_trait]
impl MigrationManifestStore for FileRepository {
    async fn save_entry(&self, entry: MigrationManifestEntry) -> Result<()> {
        // Idempotent per source_key: scan existing manifests first.
        for existing in self.entries().await? {
            if existing.source_key == entry.source_key {
                return Ok(());
            }
        }
        let sequence = self.next_manifest_sequence().await?;
        let path = self
            .store
            .aggregate_dir("migration")
            .join(format!("manifest-{sequence:06}.json"));
        let bytes = serde_json::to_vec_pretty(&entry)?;
        self.store.durable_write(&path, &bytes).await?;
        self.store.invalidate_parse_cache(&path);
        Ok(())
    }

    async fn entries(&self) -> Result<Vec<MigrationManifestEntry>> {
        let dir = self.store.aggregate_dir("migration");
        let mut entries = fs::read_dir(&dir)
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to list {}: {e}", dir.display())))?;
        let mut out = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to scan {}: {e}", dir.display())))?
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_prefix("manifest-")
                && let Some(stem) = stem.strip_suffix(".json")
                && let Ok(sequence) = stem.parse::<u64>()
            {
                let value = read_json(&entry.path())
                    .await?
                    .ok_or_else(|| corrupt("manifest vanished"))?;
                let parsed: MigrationManifestEntry = serde_json::from_value(value)
                    .map_err(|e| corrupt(format!("manifest {sequence}: {e}")))?;
                out.push(parsed);
            }
        }
        out.sort_by(|a, b| a.source_key.cmp(&b.source_key));
        Ok(out)
    }
}

#[async_trait]
impl AccountRepository for FileRepository {
    async fn upsert(&self, account: AccountRecord) -> Result<()> {
        let data = serde_json::to_value(&account)?;
        match self
            .store
            .env_create("accounts", &account.id, &data, self.clock.now())
            .await?
        {
            CreateOutcome::Created => Ok(()),
            CreateOutcome::AlreadyExists => {
                let existing = self
                    .store
                    .env_get("accounts", &account.id)
                    .await?
                    .ok_or_else(|| corrupt("account vanished"))?;
                let revision = envelope_revision(&existing)?;
                self.store
                    .env_cas("accounts", &account.id, revision, &data, self.clock.now())
                    .await?;
                Ok(())
            }
        }
    }

    async fn get(&self, id: &str) -> Result<Option<Versioned<AccountRecord>>> {
        super::GenericRepository::new(self.store.clone(), self.clock.clone())
            .get_as("accounts", id)
            .await
    }

    async fn list(&self) -> Result<Vec<Versioned<AccountRecord>>> {
        super::GenericRepository::new(self.store.clone(), self.clock.clone())
            .list_as("accounts")
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_encoding_is_safe() {
        assert_eq!(encode_file_name("int_abc123"), "int_abc123");
        assert_eq!(encode_file_name("a/b"), "a%2Fb");
        assert_eq!(encode_file_name(".."), "..");
        // `..` alone would be dangerous as a whole component but is embedded
        // in a `<id>.json` name so it cannot traverse.
        let encoded = encode_file_name("ten_default:letsencrypt");
        assert!(!encoded.contains(':'));
        let decoded = decode_file_name(&encoded).unwrap();
        assert_eq!(decoded, "ten_default:letsencrypt");
        let unicode = encode_file_name("证书");
        assert!(unicode.starts_with('%'));
        assert_eq!(decode_file_name(&unicode).unwrap(), "证书");
    }

    // -- parse cache consistency ----------------------------------------------

    fn cache_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "acmex-file-parse-cache-{label}-{}-{}",
            std::process::id(),
            crate::repository::SystemClock.now().as_millisecond()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("intents")).expect("create aggregate dir");
        dir
    }

    async fn cached_data(store: &FileEntityStore, id: &str) -> Option<Value> {
        store
            .env_get("intents", id)
            .await
            .expect("env_get")
            .map(|value| value["data"].clone())
    }

    /// The parse cache must never shadow writes: rewrites performed by other
    /// processes (plain file IO that bypasses this store) change the on-disk
    /// mtime/len stamp and must be observed by the next `env_get`/`env_list`.
    #[tokio::test]
    async fn parse_cache_tracks_external_writes_same_length_writes_and_deletions() {
        let dir = cache_test_dir("external");
        let store = FileEntityStore::new(&dir);
        let path = dir.join("intents").join("int_a.json");
        let now = crate::repository::SystemClock.now();

        // Seed through the store, then warm the cache.
        let v1 = serde_json::json!({ "payload": "aaaa" });
        assert_eq!(
            store
                .env_create("intents", "int_a", &v1, now)
                .await
                .unwrap(),
            CreateOutcome::Created
        );
        assert_eq!(
            cached_data(&store, "int_a").await,
            Some(serde_json::json!({ "payload": "aaaa" }))
        );
        // Cache hit must return the same value.
        assert_eq!(
            cached_data(&store, "int_a").await,
            Some(serde_json::json!({ "payload": "aaaa" }))
        );

        // External rewrite with *identical file length*: only the mtime
        // changed, which must still invalidate the cache.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let bytes = std::fs::read(&path).expect("read entity file");
        let rewritten: String = std::string::String::from_utf8(bytes)
            .expect("utf8")
            .replace("aaaa", "bbbb");
        std::fs::write(&path, &rewritten).expect("external rewrite");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            rewritten.len() as u64,
            "test premise: the rewrite preserved the file length"
        );
        assert_eq!(
            cached_data(&store, "int_a").await,
            Some(serde_json::json!({ "payload": "bbbb" }))
        );
        // ... and the list path observes it too.
        let listed = store.env_list("intents").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].value["data"]["payload"], "bbbb");

        // Warm again, then an external *deletion* must be observed.
        assert!(cached_data(&store, "int_a").await.is_some());
        std::fs::remove_file(&path).expect("external delete");
        assert_eq!(cached_data(&store, "int_a").await, None);
        assert!(store.env_list("intents").await.unwrap().is_empty());

        // An external re-creation (no store involvement) is picked up.
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&make_envelope(
                &serde_json::json!({ "payload": "cccc" }),
                now,
            ))
            .unwrap(),
        )
        .expect("external recreate");
        assert_eq!(
            cached_data(&store, "int_a").await,
            Some(serde_json::json!({ "payload": "cccc" }))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Writes made through the store itself (create/CAS/delete) must also
    /// invalidate the cache so no stale value is ever served.
    #[tokio::test]
    async fn parse_cache_is_invalidated_by_store_writes() {
        let dir = cache_test_dir("store-writes");
        let store = FileEntityStore::new(&dir);
        let now = crate::repository::SystemClock.now();

        let v1 = serde_json::json!({ "payload": "aaaa" });
        assert_eq!(
            store
                .env_create("intents", "int_b", &v1, now)
                .await
                .unwrap(),
            CreateOutcome::Created
        );
        assert_eq!(
            cached_data(&store, "int_b").await,
            Some(serde_json::json!({ "payload": "aaaa" }))
        );

        // CAS bumps revision + data; the read must not serve revision 1.
        let envelope = store
            .env_get("intents", "int_b")
            .await
            .unwrap()
            .expect("envelope");
        let revision = envelope_revision(&envelope).unwrap();
        let v2 = serde_json::json!({ "payload": "dddd" });
        assert!(matches!(
            store
                .env_cas("intents", "int_b", revision, &v2, now)
                .await
                .unwrap(),
            CasOutcome::Updated(_)
        ));
        assert_eq!(
            cached_data(&store, "int_b").await,
            Some(serde_json::json!({ "payload": "dddd" }))
        );

        // Delete removes the entity and the (now stale) cache entry.
        store.env_delete("intents", "int_b").await.unwrap();
        assert_eq!(cached_data(&store, "int_b").await, None);
        assert!(store.env_list("intents").await.unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- fsync modes ------------------------------------------------------------

    fn fsync_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "acmex-file-fsync-{label}-{}-{}",
            std::process::id(),
            crate::repository::SystemClock.now().as_millisecond()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn fsync_mode_defaults_to_always() {
        assert_eq!(FsyncMode::default(), FsyncMode::Always);
        let dir = fsync_test_dir("mode-default");
        let store = FileEntityStore::new(&dir);
        assert_eq!(store.fsync_mode(), FsyncMode::Always);
        assert_eq!(store.fsynced_file_count(), 0);
        let store =
            FileEntityStore::with_mode(&dir, FsyncMode::Interval(Duration::from_secs(3600)));
        assert_eq!(
            store.fsync_mode(),
            FsyncMode::Interval(Duration::from_secs(3600))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Interval` mode defers fsync to the sweeper: writes are visible
    /// immediately (rename), and only `sync_pending` (or the sweeper's
    /// window) performs the fsyncs — proven by the fsynced-file counter.
    #[tokio::test]
    async fn interval_mode_defers_fsync_until_sweep() {
        let dir = fsync_test_dir("interval-defer");
        let store =
            FileEntityStore::with_mode(&dir, FsyncMode::Interval(Duration::from_secs(3600)));
        let now = crate::repository::SystemClock.now();

        for index in 0..3 {
            assert_eq!(
                store
                    .env_create(
                        "intents",
                        &format!("int_iv_{index}"),
                        &serde_json::json!({ "n": index }),
                        now
                    )
                    .await
                    .unwrap(),
                CreateOutcome::Created
            );
            // Visible immediately, before any fsync.
            let cached = store
                .env_get("intents", &format!("int_iv_{index}"))
                .await
                .unwrap()
                .expect("written entity is readable");
            assert_eq!(cached["data"]["n"], index);
        }
        assert_eq!(
            store.fsynced_file_count(),
            0,
            "no fsync may happen before the sweep in Interval mode"
        );

        // Forced sweep: exactly the three written files are fsynced.
        assert_eq!(store.sync_pending().await.unwrap(), 3);
        assert_eq!(store.fsynced_file_count(), 3);
        // Drained queue: a second sweep is a no-op.
        assert_eq!(store.sync_pending().await.unwrap(), 0);
        assert_eq!(store.fsynced_file_count(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Deleting a dirty file before its sweep is observed (NotFound is
    /// skipped) and the parent directory is still fsynced so the deletion
    /// itself becomes durable.
    #[tokio::test]
    async fn interval_mode_delete_then_sweep_succeeds() {
        let dir = fsync_test_dir("interval-delete");
        let store =
            FileEntityStore::with_mode(&dir, FsyncMode::Interval(Duration::from_secs(3600)));
        let now = crate::repository::SystemClock.now();

        store
            .env_create("intents", "int_gone", &serde_json::json!({}), now)
            .await
            .unwrap();
        store.env_delete("intents", "int_gone").await.unwrap();
        assert_eq!(store.sync_pending().await.unwrap(), 0);
        assert_eq!(store.fsynced_file_count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dropping the last store clone flushes pending writes and joins the
    /// sweeper (no hang, no panic); a fresh store observes the data.
    #[tokio::test]
    async fn interval_mode_drop_flushes_pending_writes() {
        let dir = fsync_test_dir("interval-drop");
        let now = crate::repository::SystemClock.now();
        {
            let store =
                FileEntityStore::with_mode(&dir, FsyncMode::Interval(Duration::from_secs(3600)));
            store
                .env_create("intents", "int_final", &serde_json::json!({ "v": 1 }), now)
                .await
                .unwrap();
            // store dropped here: final flush + join must complete.
        }
        let store = FileEntityStore::new(&dir);
        let cached = store
            .env_get("intents", "int_final")
            .await
            .unwrap()
            .expect("flushed entity is readable");
        assert_eq!(cached["data"]["v"], 1);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only the last clone shuts the sweeper down; earlier drops leave the
    /// background durability intact for the survivors.
    #[tokio::test]
    async fn interval_mode_surviving_clone_keeps_sweeper() {
        let dir = fsync_test_dir("interval-clone");
        let store =
            FileEntityStore::with_mode(&dir, FsyncMode::Interval(Duration::from_secs(3600)));
        let clone = store.clone();
        let now = crate::repository::SystemClock.now();

        drop(store);
        clone
            .env_create("intents", "int_survivor", &serde_json::json!({}), now)
            .await
            .unwrap();
        assert_eq!(clone.sync_pending().await.unwrap(), 1);
        assert_eq!(clone.fsynced_file_count(), 1);
        drop(clone);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Always` mode (the default) fsyncs inline: `sync_pending` is a no-op
    /// and the deferred counter never moves.
    #[tokio::test]
    async fn always_mode_sync_pending_is_noop() {
        let dir = fsync_test_dir("always-noop");
        let store = FileEntityStore::new(&dir);
        let now = crate::repository::SystemClock.now();
        store
            .env_create("intents", "int_always", &serde_json::json!({}), now)
            .await
            .unwrap();
        assert_eq!(store.sync_pending().await.unwrap(), 0);
        assert_eq!(store.fsynced_file_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
