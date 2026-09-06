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
//! * writes go to a sibling temp file, are fsynced, then atomically renamed;
//! * IDs are filename-encoded so `/`, `..` and friends cannot escape;
//! * list returns entity IDs (never file names with extensions);
//! * corrupt JSON surfaces as an explicit `CorruptData` error;
//! * a stale temp file is never a valid entity.
//!
//! Atomicity caveat: the compare-and-set read/verify happens under an
//! in-process lock; cross-process mutation is guarded by the revision check
//! on write. Same-filesystem rename is required (documented).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde_json::Value;
use tokio::fs;

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

/// Freshness stamp of a cached parse: modification time and length.
///
/// Every cache access re-stats the file, so writes from any process (this
/// one or an external one; both go through atomic rename, which changes
/// mtime/len) invalidate the entry before the next read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    len: u64,
}

/// Extracts the stamp of `meta`; `None` when the filesystem does not expose
/// modification times (caching is skipped for such files).
fn file_stamp(meta: &std::fs::Metadata) -> Option<FileStamp> {
    Some(FileStamp {
        mtime: meta.modified().ok()?,
        len: meta.len(),
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

/// Filesystem store shared by all aggregates. Clones share state locks.
#[derive(Clone)]
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
    /// the on-disk mtime changing. On filesystems with coarse mtime
    /// granularity (NFS attribute caching, FAT), a same-length in-place
    /// rewrite may keep the old stamp; deploy one AcmeX instance per file
    /// repository root (the CAS write path is unaffected — it always
    /// re-reads and fails on conflict).
    parse_cache: Arc<Mutex<HashMap<PathBuf, ParsedFile>>>,
    /// Monotonic insertion sequence for approximate-LRU eviction.
    parse_cache_seq: Arc<AtomicU64>,
}

impl FileEntityStore {
    /// Opens (or creates) a store rooted at `root`.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            outbox_next: Arc::new(tokio::sync::Mutex::new(None)),
            manifest_next: Arc::new(tokio::sync::Mutex::new(None)),
            lease_tokens: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            parse_cache: Arc::new(Mutex::new(HashMap::new())),
            parse_cache_seq: Arc::new(AtomicU64::new(0)),
        }
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

/// Atomically writes `bytes` to `path`: temp file → fsync → rename.
async fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| AcmeError::Storage("entity path has no parent".to_string()))?;
    fs::create_dir_all(dir)
        .await
        .map_err(|e| AcmeError::Storage(format!("failed to create {}: {e}", dir.display())))?;

    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        encode_file_name(&format!("{:x}", rand::random::<u64>()))
    ));
    fs::write(&tmp, bytes)
        .await
        .map_err(|e| AcmeError::Storage(format!("failed to write {}: {e}", tmp.display())))?;

    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to chmod {}: {e}", tmp.display())))?;
    }

    // fsync the temp file before rename so the renamed content is durable.
    let file = fs::File::open(&tmp)
        .await
        .map_err(|e| AcmeError::Storage(format!("failed to reopen {}: {e}", tmp.display())))?;
    file.sync_all()
        .await
        .map_err(|e| AcmeError::Storage(format!("failed to fsync {}: {e}", tmp.display())))?;
    drop(file);

    fs::rename(&tmp, path).await.map_err(|e| {
        AcmeError::Storage(format!("failed to rename into {}: {e}", path.display()))
    })?;
    Ok(())
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
        atomic_write(&path, &bytes, false).await?;
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
        let Some(existing) = read_json(&path).await? else {
            return Err(corrupt(format!("{aggregate} `{id}` missing for update")));
        };
        let current = envelope_revision(&existing)?;
        if current != expected {
            return Ok(CasOutcome::Conflict { current });
        }
        let envelope = bump_envelope(&existing, data, now)?;
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        atomic_write(&path, &bytes, false).await?;
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
            Ok(()) => Ok(()),
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
    /// Opens a repository rooted at `root` with the given clock.
    pub async fn with_clock(root: impl AsRef<Path>, clock: Arc<dyn Clock>) -> Result<Self> {
        let store = FileEntityStore::new(root);
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
        Ok(match read_json(path).await? {
            Some(value) => {
                // Round-trip through serde for typed access.
                Some(
                    serde_json::from_value(value)
                        .map_err(|e| corrupt(format!("lock file {}: {e}", path.display())))?,
                )
            }
            None => None,
        })
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
        atomic_write(&path, &bytes, false).await?;
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
        atomic_write(&path, &bytes, false).await?;
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
        atomic_write(&path, &bytes, false).await?;
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
        let value = read_json(&path)
            .await?
            .ok_or_else(|| corrupt(format!("outbox entry {sequence} missing")))?;
        let mut event: OutboxEvent = serde_json::from_value(value)
            .map_err(|e| corrupt(format!("outbox entry {sequence}: {e}")))?;
        mutate(&mut event);
        let bytes = serde_json::to_vec_pretty(&event)?;
        atomic_write(&path, &bytes, false).await?;
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
        atomic_write(&path, &bytes, false).await?;
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
}
