//! Redis-backed repository — the aggregate traits on a shared Redis server.
//!
//! Layout (one JSON value per entity, mirroring `file.rs`'s directory tree):
//!
//! ```text
//! acmex:v1:intents/<encoded-id>             → envelope JSON
//! acmex:v1:lineages/<encoded-id>            → envelope JSON
//! acmex:v1:versions/<encoded-id>            → envelope JSON
//! acmex:v1:operations/<encoded-id>          → envelope JSON
//! acmex:v1:challenge-leases/<encoded-id>    → envelope JSON
//! acmex:v1:challenge-sessions/<encoded-id>  → envelope JSON
//! acmex:v1:deployments/<encoded-id>         → envelope JSON
//! acmex:v1:accounts/<encoded-id>            → envelope JSON
//! acmex:v1:outbox/<sequence>                → outbox event JSON (immutable)
//! acmex:v1:outbox-state/<sequence>          → delivery-state hash (mutable)
//! acmex:v1:migration/manifest-<seq>         → manifest entry JSON
//! acmex:v1:locks/<encoded-key>              → lease hash {owner, token, expiry}
//! acmex:v1:lease-tokens/<encoded-key>       → per-key fencing-token counter
//! acmex:v1:counters/outbox                  → outbox sequence counter
//! acmex:v1:counters/manifest                → manifest sequence counter
//! ```
//!
//! Guarantees and how they map to Redis primitives:
//!
//! * IDs are percent-encoded exactly like the file backend, so `/`, `..`,
//!   `:` and Unicode cannot collide with the `:`-separated key namespaces
//!   (note `outbox-state` sits outside the `outbox:*` scan pattern);
//! * entity envelopes serialize identically to the file backend (same
//!   `make_envelope` / `bump_envelope` helpers);
//! * compare-and-set runs as a single Lua script (GET + revision compare +
//!   SET), so concurrent CAS races produce exactly one winner per revision;
//! * lease acquire/renew/release run as Lua scripts over a lock hash plus a
//!   per-key fencing-token counter, keeping tokens strictly monotonic
//!   across takeovers and processes. Expiry is judged against the injected
//!   [`Clock`] (passed in as an argument), not Redis `TIME`, so tests can
//!   virtualize time like the memory/file backends;
//! * outbox sequences come from `INCR` on a counter and the event JSON plus
//!   its delivery-state hash are written in one `MULTI`/`EXEC` block;
//!   delivery-state mutations (attempts, retry time, dead-letter, requeue)
//!   are single Lua scripts or hash commands, so they are atomic;
//! * a crash between `INCR` and the event write leaves a sequence gap,
//!   which is safe: consumers only observe written events (the file backend
//!   has the same property, just per-process).
//!
//! Values are plain strings (JSON), so `redis-cli` inspection works, but the
//! format is internal to this backend — cross-backend data migration goes
//! through the repository traits, not raw key copying.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde_json::Value;

use jiff::Timestamp;

use super::{
    AccountRepository, CasOutcome, Clock, CreateOutcome, EntityStore, Envelope, FencingToken,
    LeaseGrant, LeaseManager, LeaseOutcome, MigrationManifestEntry, MigrationManifestStore,
    OutboxEvent, OutboxRepository, RepositorySet, Revision, SystemClock, Versioned, bump_envelope,
    corrupt, make_envelope,
};
use crate::domain::AccountRecord;
use crate::error::{AcmeError, Result};

/// Namespace prefix for every key written by this backend. The version
/// segment (`v1`) allows future layout migrations to coexist.
const KEY_PREFIX: &str = "acmex:v1:";

/// Lua CAS: reads the stored envelope, compares the revision and swaps the
/// value — all in one atomic script. Returns
/// `{-1, ""}` (key missing), `{-2, ""}` (not an envelope),
/// `{0, current}` (conflict) or `{1, new_revision}` (applied).
static CAS_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
        local current = redis.call('GET', KEYS[1])
        if not current then
            return {-1, ''}
        end
        local ok, envelope = pcall(cjson.decode, current)
        if not ok or type(envelope) ~= 'table' then
            return {-2, ''}
        end
        local revision = envelope['revision']
        if type(revision) ~= 'number' then
            return {-2, ''}
        end
        revision = math.floor(revision)
        if revision ~= tonumber(ARGV[1]) then
            return {0, tostring(revision)}
        end
        redis.call('SET', KEYS[1], ARGV[2])
        return {1, tostring(revision + 1)}
        "#,
    )
});

/// Lua lease acquire: grants (or takes over an expired/own lease) with a
/// fencing token drawn from a per-key counter, atomically. ARGV:
/// `now_ms, ttl_ms, owner`. Returns
/// `{"held", owner, expires_at_ms}` or `{"granted", token, expires_at_ms}`.
static LEASE_ACQUIRE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
        local now = tonumber(ARGV[1])
        local ttl = tonumber(ARGV[2])
        local owner = redis.call('HGET', KEYS[1], 'owner')
        if owner then
            local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at_ms'))
            if expires_at and expires_at > now and owner ~= ARGV[3] then
                return {'held', owner, tostring(expires_at)}
            end
        end
        local token = redis.call('INCR', KEYS[2])
        local expires_at = now + ttl
        redis.call('HSET', KEYS[1],
            'owner', ARGV[3], 'fencing_token', token, 'expires_at_ms', expires_at)
        return {'granted', tostring(token), tostring(expires_at)}
        "#,
    )
});

/// Lua lease renew: extends the expiry only when owner, fencing token and
/// liveness all match. ARGV: `now_ms, ttl_ms, owner, fencing_token`.
/// Returns `0` (lost) or `{1, expires_at_ms}`.
static LEASE_RENEW_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
        local now = tonumber(ARGV[1])
        local ttl = tonumber(ARGV[2])
        local owner = redis.call('HGET', KEYS[1], 'owner')
        if not owner or owner ~= ARGV[3] then
            return 0
        end
        local token = tonumber(redis.call('HGET', KEYS[1], 'fencing_token'))
        if not token or token ~= tonumber(ARGV[4]) then
            return 0
        end
        local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at_ms'))
        if not expires_at or expires_at <= now then
            return 0
        end
        local new_expiry = now + ttl
        redis.call('HSET', KEYS[1], 'expires_at_ms', new_expiry)
        return {1, tostring(new_expiry)}
        "#,
    )
});

/// Lua lease release: deletes the lock only for the owner holding the
/// exact fencing token. ARGV: `owner, fencing_token`. Returns 1 (the
/// operation always succeeds; releasing a stale or foreign lease is a no-op).
static LEASE_RELEASE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
        local owner = redis.call('HGET', KEYS[1], 'owner')
        if owner and owner == ARGV[1] then
            local token = tonumber(redis.call('HGET', KEYS[1], 'fencing_token'))
            if token and token == tonumber(ARGV[2]) then
                redis.call('DEL', KEYS[1])
            end
        end
        return 1
        "#,
    )
});

/// Lua outbox failure recording: increments the attempt counter, stores the
/// error and sets (or clears) the retry time atomically. ARGV:
/// `error, next_attempt_at_ms_or_empty`. Returns the new attempt count.
static OUTBOX_MARK_FAILED_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
        local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
        redis.call('HSET', KEYS[1], 'last_error', ARGV[1])
        if ARGV[2] == '' then
            redis.call('HDEL', KEYS[1], 'next_attempt_at_ms')
        else
            redis.call('HSET', KEYS[1], 'next_attempt_at_ms', ARGV[2])
        end
        return attempts
        "#,
    )
});

/// Lua outbox dead-lettering: flags the event and clears its retry time.
/// ARGV: `reason`. Returns 1.
static OUTBOX_DEAD_LETTER_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
        redis.call('HSET', KEYS[1],
            'dead_lettered', 1, 'last_error', 'dead-letter: ' .. ARGV[1])
        redis.call('HDEL', KEYS[1], 'next_attempt_at_ms')
        return 1
        "#,
    )
});

/// Lua outbox requeue: clears the dead-letter and processed flags plus the
/// recorded error, making the event deliverable again. Returns 1.
static OUTBOX_REQUEUE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
        redis.call('HSET', KEYS[1], 'dead_lettered', 0, 'processed', 0)
        redis.call('HDEL', KEYS[1], 'last_error', 'next_attempt_at_ms')
        return 1
        "#,
    )
});

/// Encodes an arbitrary entity id into a safe Redis key component.
///
/// Everything outside `[A-Za-z0-9._-]` is percent-encoded — the same rule as
/// the file backend's file names — so `/`, `..`, `:`, spaces and Unicode
/// never collide with the `:`-separated namespace structure (`%` itself
/// becomes `%25`, keeping the encoding reversible).
pub(crate) fn encode_key_component(id: &str) -> String {
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

/// Reverses [`encode_key_component`]; `None` on truncated escapes or
/// non-UTF-8 sequences (which cannot be produced by the encoder).
fn decode_key_component(encoded: &str) -> Option<String> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex_pair = encoded.get(i + 1..i + 3)?;
            let byte = u8::from_str_radix(hex_pair, 16).ok()?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The full Redis key for one entity of an aggregate.
fn entity_key(aggregate: &str, id: &str) -> String {
    format!("{KEY_PREFIX}{aggregate}:{}", encode_key_component(id))
}

/// The SCAN pattern matching every entity key of an aggregate.
fn aggregate_pattern(aggregate: &str) -> String {
    format!("{KEY_PREFIX}{aggregate}:*")
}

/// Recovers the entity id from a key produced by [`entity_key`].
fn id_from_key(aggregate: &str, key: &str) -> Result<String> {
    let prefix = format!("{KEY_PREFIX}{aggregate}:");
    let encoded = key
        .strip_prefix(&prefix)
        .ok_or_else(|| corrupt(format!("key {key:?} is not a `{aggregate}` entity key")))?;
    decode_key_component(encoded)
        .ok_or_else(|| corrupt(format!("unencodable key {key:?} for `{aggregate}`")))
}

/// The delivery-state hash key for an outbox sequence. Lives outside the
/// `outbox:*` namespace so entity scans never see it.
fn outbox_state_key(sequence: u64) -> String {
    format!("{KEY_PREFIX}outbox-state:{sequence:012}")
}

/// The immutable outbox event JSON key for a sequence.
fn outbox_event_key(sequence: u64) -> String {
    entity_key("outbox", &format!("{sequence:012}"))
}

/// The migration manifest key for a sequence.
fn manifest_key(sequence: u64) -> String {
    entity_key("migration", &format!("manifest-{sequence:06}"))
}

/// Fencing-token counter for one lease key.
fn lease_token_counter_key(key: &str) -> String {
    format!("{KEY_PREFIX}lease-tokens:{}", encode_key_component(key))
}

/// Lease state hash for one lease key.
fn lease_lock_key(key: &str) -> String {
    format!("{KEY_PREFIX}locks:{}", encode_key_component(key))
}

/// Maps a Redis driver error into the storage error class.
fn redis_error(operation: &str, err: redis::RedisError) -> AcmeError {
    tracing::debug!(error = %err, operation, "redis command failed");
    AcmeError::Storage(format!("redis {operation} failed: {err}"))
}

/// Extracts a non-negative integer from a Lua script reply element.
fn redis_value_u64(value: &redis::Value) -> Option<u64> {
    match value {
        redis::Value::Int(int) if *int >= 0 => Some(u64::try_from(*int).ok()?),
        redis::Value::BulkString(bytes) => std::str::from_utf8(bytes).ok()?.parse().ok(),
        redis::Value::SimpleString(text) => text.parse().ok(),
        _ => None,
    }
}

/// Extracts a string from a Lua script reply element.
fn redis_value_str(value: &redis::Value) -> Option<&str> {
    match value {
        redis::Value::BulkString(bytes) => std::str::from_utf8(bytes).ok(),
        redis::Value::SimpleString(text) => Some(text.as_str()),
        _ => None,
    }
}

/// Interprets the [`CAS_SCRIPT`] reply.
fn interpret_cas_reply(reply: &[redis::Value], aggregate: &str, id: &str) -> Result<CasOutcome> {
    let malformed = || corrupt(format!("unexpected CAS reply for {aggregate} `{id}`"));
    match reply {
        [redis::Value::Int(-1), ..] => {
            Err(corrupt(format!("{aggregate} `{id}` missing for update")))
        }
        [redis::Value::Int(-2), ..] => Err(corrupt(format!(
            "{aggregate} `{id}` has no usable revision"
        ))),
        [redis::Value::Int(0), current] => Ok(CasOutcome::Conflict {
            current: redis_value_u64(current).ok_or_else(malformed)?,
        }),
        [redis::Value::Int(1), updated] => Ok(CasOutcome::Updated(
            redis_value_u64(updated).ok_or_else(malformed)?,
        )),
        _ => Err(malformed()),
    }
}

/// Interprets the [`LEASE_ACQUIRE_SCRIPT`] reply.
fn interpret_acquire_reply(
    reply: &[redis::Value],
    key: &str,
    requester: &str,
) -> Result<LeaseOutcome> {
    let malformed = || corrupt("unexpected lease acquire reply");
    match reply {
        [status, first, second] => match redis_value_str(status) {
            Some("granted") => Ok(LeaseOutcome::Granted(LeaseGrant {
                key: key.to_string(),
                owner: requester.to_string(),
                fencing_token: redis_value_u64(first).ok_or_else(malformed)?,
                expires_at: timestamp_from_ms(redis_value_u64(second).ok_or_else(malformed)?)?,
            })),
            Some("held") => Ok(LeaseOutcome::HeldByOther {
                owner: redis_value_str(first).ok_or_else(malformed)?.to_string(),
                expires_at: timestamp_from_ms(redis_value_u64(second).ok_or_else(malformed)?)?,
            }),
            _ => Err(malformed()),
        },
        _ => Err(malformed()),
    }
}

fn timestamp_from_ms(ms: u64) -> Result<Timestamp> {
    Timestamp::from_millisecond(i64::try_from(ms).unwrap_or(i64::MAX))
        .map_err(|e| corrupt(format!("bad lock expiry: {e}")))
}

/// Parses a "0"/"1" flag from the delivery-state hash (hash values are
/// always strings; Rust's `bool::from_str` would reject "1").
fn parse_flag(state: &HashMap<String, String>, field: &str) -> Option<bool> {
    state
        .get(field)
        .and_then(|v| v.parse::<i64>().ok())
        .map(|flag| flag != 0)
}

/// Composes the wire-format outbox event with its (authoritative) delivery
/// state hash. Mutable fields always win from the hash so a partially
/// written event cannot resurrect stale delivery state.
fn compose_outbox_event(mut event: OutboxEvent, state: &HashMap<String, String>) -> OutboxEvent {
    if let Some(attempts) = state.get("attempts").and_then(|v| v.parse().ok()) {
        event.attempts = attempts;
    }
    if let Some(processed) = parse_flag(state, "processed") {
        event.processed = processed;
    }
    if let Some(dead_lettered) = parse_flag(state, "dead_lettered") {
        event.dead_lettered = dead_lettered;
    }
    event.last_error = state.get("last_error").cloned();
    if let Some(next_ms) = state
        .get("next_attempt_at_ms")
        .and_then(|v| v.parse::<i64>().ok())
        .and_then(|ms| Timestamp::from_millisecond(ms).ok())
    {
        event.next_attempt_at = Some(next_ms);
    } else {
        event.next_attempt_at = None;
    }
    event
}

/// Redacts the password of a Redis URL for logging and `Debug` output.
///
/// `redis://:hunter2@host:6379/0` becomes `redis://:****@host:6379/0`.
/// URLs without credentials are returned unchanged.
fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let authority_len = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_len];
    let Some(at) = authority.rfind('@') else {
        return url.to_string();
    };
    let userinfo = &authority[..at];
    let host = &authority[at + 1..];
    let userinfo = match userinfo.split_once(':') {
        Some((user, _)) => format!("{user}:****"),
        None => userinfo.to_string(),
    };
    format!(
        "{}://{}@{}{}",
        &url[..scheme_end],
        userinfo,
        host,
        &rest[authority_len..]
    )
}

/// Per-aggregate entity store shared by every generic aggregate repository.
/// Clones share the same [`ConnectionManager`] (a cheap, reconnecting,
/// multiplexed handle — no per-operation connection setup).
#[derive(Clone)]
pub struct RedisEntityStore {
    conn: ConnectionManager,
}

impl RedisEntityStore {
    fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }
}

impl std::fmt::Debug for RedisEntityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connection manager embeds the client (and thus the URL); it is
        // deliberately kept out of Debug output so credentials never leak.
        f.debug_struct("RedisEntityStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl EntityStore for RedisEntityStore {
    async fn env_get(&self, aggregate: &str, id: &str) -> Result<Option<Value>> {
        let key = entity_key(aggregate, id);
        let mut conn = self.conn.clone();
        let raw: Option<String> = conn.get(&key).await.map_err(|e| redis_error("GET", e))?;
        match raw {
            None => Ok(None),
            Some(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| corrupt(format!("corrupt entity key {key}: {e}"))),
        }
    }

    async fn env_create(
        &self,
        aggregate: &str,
        id: &str,
        data: &Value,
        now: Timestamp,
    ) -> Result<CreateOutcome> {
        let envelope = make_envelope(data, now);
        let json = serde_json::to_string_pretty(&envelope)?;
        let mut conn = self.conn.clone();
        // `SET ... NX` is atomic in Redis: a nil reply means the id was
        // taken. (The crate's `set_nx` helper is the legacy SETNX command,
        // whose integer reply cannot distinguish the two outcomes.)
        let created: Option<()> = redis::cmd("SET")
            .arg(entity_key(aggregate, id))
            .arg(json)
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(|e| redis_error("SET NX", e))?;
        match created {
            Some(()) => Ok(CreateOutcome::Created),
            None => Ok(CreateOutcome::AlreadyExists),
        }
    }

    async fn env_cas(
        &self,
        aggregate: &str,
        id: &str,
        expected: Revision,
        data: &Value,
        now: Timestamp,
    ) -> Result<CasOutcome> {
        let key = entity_key(aggregate, id);
        // Read the current envelope to build the bumped one (preserving
        // created_at); the script re-validates the revision atomically
        // before writing, so a racing writer turns this into a Conflict.
        let mut conn = self.conn.clone();
        let raw: Option<String> = conn.get(&key).await.map_err(|e| redis_error("GET", e))?;
        let Some(raw) = raw else {
            return Err(corrupt(format!("{aggregate} `{id}` missing for update")));
        };
        let existing: Value = serde_json::from_str(&raw)
            .map_err(|e| corrupt(format!("corrupt entity key {key}: {e}")))?;
        let bumped = bump_envelope(&existing, data, now)?;
        let json = serde_json::to_string_pretty(&bumped)?;

        let reply: Vec<redis::Value> = CAS_SCRIPT
            .key(&key)
            .arg(expected.to_string())
            .arg(json)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| redis_error("EVAL cas", e))?;
        interpret_cas_reply(&reply, aggregate, id)
    }

    async fn env_list(&self, aggregate: &str) -> Result<Vec<Envelope>> {
        let keys = scan_keys(&self.conn, &aggregate_pattern(aggregate)).await?;
        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        for key in &keys {
            pipe.get(key);
        }
        let values: Vec<Option<String>> = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| redis_error("MGET", e))?;

        let mut out = Vec::with_capacity(keys.len());
        for (key, value) in keys.into_iter().zip(values) {
            let Some(json) = value else {
                return Err(corrupt(format!("entity key {key} vanished")));
            };
            let parsed: Value = serde_json::from_str(&json)
                .map_err(|e| corrupt(format!("corrupt entity key {key}: {e}")))?;
            out.push(Envelope {
                id: id_from_key(aggregate, &key)?,
                value: parsed,
            });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn env_delete(&self, aggregate: &str, id: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .del(entity_key(aggregate, id))
            .await
            .map_err(|e| redis_error("DEL", e))?;
        Ok(())
    }
}

/// Runs `SCAN MATCH <pattern>` to completion (cursor loop). SCAN is
/// stateless per call, so it is safe on the multiplexed connection.
async fn scan_keys(conn: &ConnectionManager, pattern: &str) -> Result<Vec<String>> {
    let mut conn = conn.clone();
    let mut cursor: u64 = 0;
    let mut keys = Vec::new();
    loop {
        let (next, page): (u64, Vec<String>) = redis::cmd("SCAN")
            .cursor_arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(500)
            .query_async(&mut conn)
            .await
            .map_err(|e| redis_error("SCAN", e))?;
        keys.extend(page);
        cursor = next;
        if cursor == 0 {
            return Ok(keys);
        }
    }
}

/// The Redis-backed repository: generic aggregates via [`RedisEntityStore`],
/// plus leases, outbox, migration manifests and accounts.
pub struct RedisRepository {
    store: RedisEntityStore,
    conn: ConnectionManager,
    /// Original URL (with credentials) — only ever surfaced through the
    /// redacting [`Debug` implementation](Self).
    url: String,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for RedisRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRepository")
            .field("url", &redact_url(&self.url))
            .finish_non_exhaustive()
    }
}

impl RedisRepository {
    /// Connects to `url` (e.g. `redis://127.0.0.1:6379/0`) using the system
    /// clock. The connection is a reconnecting [`ConnectionManager`] that is
    /// cloned for every operation instead of being rebuilt.
    pub async fn connect(url: impl AsRef<str>) -> Result<Self> {
        Self::with_clock(url, Arc::new(SystemClock)).await
    }

    /// Connects to `url` with an injected clock (lease expiry and outbox
    /// retry scheduling are judged against it, enabling virtual time).
    pub async fn with_clock(url: impl AsRef<str>, clock: Arc<dyn Clock>) -> Result<Self> {
        let url = url.as_ref().to_string();
        let client = redis::Client::open(url.as_str())
            .map_err(|e| AcmeError::Storage(format!("failed to open redis client: {e}")))?;
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| AcmeError::Storage(format!("failed to connect to redis: {e}")))?;
        // Prove connectivity now rather than on the first operation.
        let mut ping = conn.clone();
        let _: String = redis::cmd("PING")
            .query_async(&mut ping)
            .await
            .map_err(|e| AcmeError::Storage(format!("redis PING failed: {e}")))?;
        tracing::debug!(url = %redact_url(&url), "connected to redis repository");
        Ok(Self {
            store: RedisEntityStore::new(conn.clone()),
            conn,
            url,
            clock,
        })
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
            backend: "redis",
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

    async fn next_outbox_sequence(&self) -> Result<u64> {
        let mut conn = self.conn.clone();
        let sequence: i64 = conn
            .incr(format!("{KEY_PREFIX}counters:outbox"), 1)
            .await
            .map_err(|e| redis_error("INCR outbox", e))?;
        u64::try_from(sequence)
            .map_err(|_| corrupt(format!("outbox sequence counter went negative: {sequence}")))
    }

    async fn next_manifest_sequence(&self) -> Result<u64> {
        let mut conn = self.conn.clone();
        let sequence: i64 = conn
            .incr(format!("{KEY_PREFIX}counters:manifest"), 1)
            .await
            .map_err(|e| redis_error("INCR manifest", e))?;
        u64::try_from(sequence).map_err(|_| {
            corrupt(format!(
                "manifest sequence counter went negative: {sequence}"
            ))
        })
    }
}

fn epoch_ms(timestamp: Timestamp) -> i64 {
    timestamp.as_millisecond()
}

#[async_trait]
impl LeaseManager for RedisRepository {
    async fn acquire(&self, key: &str, owner: &str, ttl: Duration) -> Result<LeaseOutcome> {
        let now = self.clock.now();
        let mut conn = self.conn.clone();
        let reply: Vec<redis::Value> = LEASE_ACQUIRE_SCRIPT
            .key(lease_lock_key(key))
            .key(lease_token_counter_key(key))
            .arg(epoch_ms(now))
            .arg(ttl.as_millis() as i64)
            .arg(owner)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| redis_error("EVAL lease acquire", e))?;
        interpret_acquire_reply(&reply, key, owner)
    }

    async fn renew(
        &self,
        key: &str,
        owner: &str,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<Option<LeaseGrant>> {
        let now = self.clock.now();
        let mut conn = self.conn.clone();
        let reply: redis::Value = LEASE_RENEW_SCRIPT
            .key(lease_lock_key(key))
            .arg(epoch_ms(now))
            .arg(ttl.as_millis() as i64)
            .arg(owner)
            .arg(fencing_token.to_string())
            .invoke_async(&mut conn)
            .await
            .map_err(|e| redis_error("EVAL lease renew", e))?;
        match &reply {
            redis::Value::Array(elements) => match elements.as_slice() {
                [redis::Value::Int(1), expires] => Ok(Some(LeaseGrant {
                    key: key.to_string(),
                    owner: owner.to_string(),
                    fencing_token,
                    expires_at: timestamp_from_ms(
                        redis_value_u64(expires).ok_or_else(|| corrupt("bad renew reply"))?,
                    )?,
                })),
                _ => Err(corrupt("unexpected lease renew reply")),
            },
            // Lua `return 0`: the lease was lost (expired or taken over).
            _ => Ok(None),
        }
    }

    async fn release(&self, key: &str, owner: &str, fencing_token: FencingToken) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: i64 = LEASE_RELEASE_SCRIPT
            .key(lease_lock_key(key))
            .arg(owner)
            .arg(fencing_token.to_string())
            .invoke_async(&mut conn)
            .await
            .map_err(|e| redis_error("EVAL lease release", e))?;
        Ok(())
    }
}

#[async_trait]
impl OutboxRepository for RedisRepository {
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
        let json = serde_json::to_string_pretty(&event)?;
        let mut conn = self.conn.clone();
        // Event JSON and delivery-state hash land in one MULTI/EXEC block.
        let _: () = redis::pipe()
            .atomic()
            .set(outbox_event_key(sequence), json)
            .hset_multiple(
                outbox_state_key(sequence),
                &[
                    ("attempts", 0i64),
                    ("processed", 0i64),
                    ("dead_lettered", 0i64),
                ],
            )
            .query_async(&mut conn)
            .await
            .map_err(|e| redis_error("MULTI outbox append", e))?;
        Ok(sequence)
    }

    async fn list_pending(&self, limit: usize) -> Result<Vec<OutboxEvent>> {
        let keys = scan_keys(&self.conn, &aggregate_pattern("outbox")).await?;
        let mut sequences = Vec::with_capacity(keys.len());
        for key in &keys {
            let id = id_from_key("outbox", key)?;
            let sequence = id
                .parse::<u64>()
                .map_err(|_| corrupt(format!("outbox key {key:?} has a non-numeric id")))?;
            sequences.push(sequence);
        }
        sequences.sort_unstable();

        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        for sequence in &sequences {
            pipe.get(outbox_event_key(*sequence))
                .hgetall(outbox_state_key(*sequence));
        }
        let pairs: Vec<(Option<String>, HashMap<String, String>)> = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| redis_error("MULTI outbox scan", e))?;

        let now = self.clock.now();
        let mut events = Vec::new();
        for (sequence, (raw, state)) in sequences.into_iter().zip(pairs) {
            let Some(json) = raw else {
                return Err(corrupt(format!("outbox entry {sequence} missing")));
            };
            let event: OutboxEvent = serde_json::from_str(&json)
                .map_err(|e| corrupt(format!("outbox entry {sequence}: {e}")))?;
            let event = compose_outbox_event(event, &state);
            if !event.processed
                && !event.dead_lettered
                && event.next_attempt_at.is_none_or(|retry_at| retry_at <= now)
            {
                events.push(event);
            }
        }
        events.truncate(limit);
        Ok(events)
    }

    async fn mark_processed(&self, sequence: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .hset(outbox_state_key(sequence), "processed", 1)
            .await
            .map_err(|e| redis_error("HSET outbox", e))?;
        Ok(())
    }

    async fn mark_failed(
        &self,
        sequence: u64,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: i64 = OUTBOX_MARK_FAILED_SCRIPT
            .key(outbox_state_key(sequence))
            .arg(error)
            .arg(
                next_attempt_at
                    .map(epoch_ms)
                    .unwrap_or_default()
                    .to_string(),
            )
            .invoke_async(&mut conn)
            .await
            .map_err(|e| redis_error("EVAL outbox mark_failed", e))?;
        Ok(())
    }

    async fn dead_letter(&self, sequence: u64, reason: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: i64 = OUTBOX_DEAD_LETTER_SCRIPT
            .key(outbox_state_key(sequence))
            .arg(reason)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| redis_error("EVAL outbox dead_letter", e))?;
        Ok(())
    }

    async fn requeue(&self, sequence: u64) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: i64 = OUTBOX_REQUEUE_SCRIPT
            .key(outbox_state_key(sequence))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| redis_error("EVAL outbox requeue", e))?;
        Ok(())
    }
}

#[async_trait]
impl MigrationManifestStore for RedisRepository {
    async fn save_entry(&self, entry: MigrationManifestEntry) -> Result<()> {
        // Idempotent per source_key: scan existing manifests first (same
        // semantics as the file backend).
        for existing in self.entries().await? {
            if existing.source_key == entry.source_key {
                return Ok(());
            }
        }
        let sequence = self.next_manifest_sequence().await?;
        let json = serde_json::to_string_pretty(&entry)?;
        let mut conn = self.conn.clone();
        let _: () = conn
            .set(manifest_key(sequence), json)
            .await
            .map_err(|e| redis_error("SET manifest", e))?;
        Ok(())
    }

    async fn entries(&self) -> Result<Vec<MigrationManifestEntry>> {
        let keys = scan_keys(&self.conn, &format!("{KEY_PREFIX}migration:manifest-*")).await?;
        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        for key in &keys {
            pipe.get(key);
        }
        let values: Vec<Option<String>> = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| redis_error("MGET manifests", e))?;

        let mut out = Vec::with_capacity(keys.len());
        for (key, value) in keys.into_iter().zip(values) {
            let Some(json) = value else {
                return Err(corrupt(format!("manifest {key} vanished")));
            };
            let parsed: MigrationManifestEntry =
                serde_json::from_str(&json).map_err(|e| corrupt(format!("manifest {key}: {e}")))?;
            out.push(parsed);
        }
        out.sort_by(|a, b| a.source_key.cmp(&b.source_key));
        Ok(out)
    }
}

/// Accounts use upsert semantics; implemented directly over the store
/// (identical flow to the memory and file backends).
#[async_trait]
impl AccountRepository for RedisRepository {
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
                let revision = super::envelope_revision(&existing)?;
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
    use crate::repository::decode_versioned;
    use std::str::FromStr;

    #[test]
    fn key_component_encoding_round_trips_hostile_ids() {
        assert_eq!(encode_key_component("int_abc123"), "int_abc123");
        assert_eq!(encode_key_component("a/b"), "a%2Fb");
        assert_eq!(encode_key_component(""), "%00");
        // `%` itself must be encoded or decoding would be ambiguous.
        assert_eq!(encode_key_component("a%b"), "a%25b");
        for hostile in [
            "ten_default:lets-encrypt",
            "../../etc/passwd",
            "..",
            "cert:a,b",
            "证书编号",
            "with space",
        ] {
            let encoded = encode_key_component(hostile);
            assert!(!encoded.contains(':'), "{hostile:?} → {encoded:?}");
            assert!(!encoded.contains('/'), "{hostile:?} → {encoded:?}");
            assert_eq!(decode_key_component(&encoded).as_deref(), Some(hostile));
        }
        assert!(decode_key_component("a%2").is_none());
        assert!(decode_key_component("a%ZZ").is_none());
    }

    #[test]
    fn entity_keys_are_namespaced_and_decodable() {
        assert_eq!(entity_key("intents", "int_x"), "acmex:v1:intents:int_x");
        // A hostile id may not introduce extra namespace separators (`_`
        // and `-` are safe, `:` and `/` are percent-encoded).
        let key = entity_key("accounts", "ten_default:lets-encrypt");
        assert_eq!(key, "acmex:v1:accounts:ten_default%3Alets-encrypt");
        assert_eq!(
            id_from_key("accounts", &key).unwrap(),
            "ten_default:lets-encrypt"
        );
        assert!(id_from_key("intents", &key).is_err());
        assert_eq!(
            aggregate_pattern("challenge-leases"),
            "acmex:v1:challenge-leases:*"
        );
    }

    #[test]
    fn outbox_state_keys_stay_outside_the_entity_scan_pattern() {
        let pattern = aggregate_pattern("outbox");
        assert_eq!(pattern, "acmex:v1:outbox:*");
        let event_key = outbox_event_key(1);
        let state_key = outbox_state_key(1);
        assert_eq!(event_key, "acmex:v1:outbox:000000000001");
        assert_eq!(state_key, "acmex:v1:outbox-state:000000000001");
        assert!(event_key.starts_with(pattern.trim_end_matches('*')));
        assert!(!state_key.starts_with(pattern.trim_end_matches('*')));
        assert_eq!(manifest_key(7), "acmex:v1:migration:manifest-000007");
        assert_eq!(lease_lock_key("op/1"), "acmex:v1:locks:op%2F1");
        assert_eq!(
            lease_token_counter_key("op/1"),
            "acmex:v1:lease-tokens:op%2F1"
        );
    }

    #[test]
    fn redact_url_hides_only_the_password() {
        assert_eq!(
            redact_url("redis://:hunter2@localhost:6379/0"),
            "redis://:****@localhost:6379/0"
        );
        assert_eq!(
            redact_url("redis://alice:hunter2@example.com:6380"),
            "redis://alice:****@example.com:6380"
        );
        assert_eq!(
            redact_url("rediss://hunter2@example.com"),
            "rediss://hunter2@example.com"
        );
        assert_eq!(
            redact_url("redis://localhost:6379"),
            "redis://localhost:6379"
        );
        assert_eq!(
            redact_url("redis://alice:hunter2@[::1]:6379/15"),
            "redis://alice:****@[::1]:6379/15"
        );
        assert_eq!(redact_url("not-a-url"), "not-a-url");
    }

    #[test]
    fn envelope_serialization_matches_the_file_backend_format() {
        let created = Timestamp::from_str("2026-01-01T00:00:00Z").unwrap();
        let data = serde_json::json!({ "id": "int_1", "generation": 2 });
        let envelope = make_envelope(&data, created);
        assert_eq!(envelope["revision"], 1);
        assert_eq!(envelope["schema_version"], 1);
        assert_eq!(envelope["created_at"], created.to_string());

        let updated = created.checked_add(jiff::Span::new().seconds(30)).unwrap();
        let bumped = bump_envelope(&envelope, &data, updated).unwrap();
        assert_eq!(bumped["revision"], 2);
        assert_eq!(bumped["created_at"], created.to_string());
        assert_eq!(bumped["updated_at"], updated.to_string());

        // The stored bytes survive a JSON round trip with metadata intact.
        let json = serde_json::to_string_pretty(&bumped).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let versioned: crate::repository::Versioned<serde_json::Value> =
            decode_versioned(&parsed).unwrap();
        assert_eq!(versioned.revision, 2);
        assert_eq!(versioned.schema_version, 1);
        assert_eq!(versioned.created_at, created);
        assert_eq!(versioned.updated_at, updated);
        assert_eq!(versioned.value, data);
    }

    #[test]
    fn outbox_event_serialization_round_trips() {
        let created = Timestamp::from_str("2026-02-03T04:05:06Z").unwrap();
        let event = OutboxEvent {
            sequence: 42,
            event_id: "evt_000000000042".to_string(),
            event_type: "operation.succeeded".to_string(),
            payload: serde_json::json!({ "id": 1, "nested": ["a", "b"] }),
            created_at: created,
            attempts: 3,
            last_error: Some("boom".to_string()),
            next_attempt_at: Some(created),
            processed: false,
            dead_lettered: true,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: OutboxEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
        // Optional fields are omitted when absent (same as the file layout).
        let minimal = OutboxEvent {
            last_error: None,
            next_attempt_at: None,
            ..event.clone()
        };
        let json = serde_json::to_value(&minimal).unwrap();
        assert!(json.get("last_error").is_none());
        assert!(json.get("next_attempt_at").is_none());
    }

    #[test]
    fn cas_reply_interpretation_covers_every_script_outcome() {
        use redis::Value;
        assert!(matches!(
            interpret_cas_reply(
                &[Value::Int(1), Value::BulkString(b"2".to_vec())],
                "intents",
                "i"
            )
            .unwrap(),
            CasOutcome::Updated(2)
        ));
        assert!(matches!(
            interpret_cas_reply(
                &[Value::Int(0), Value::BulkString(b"5".to_vec())],
                "intents",
                "i"
            )
            .unwrap(),
            CasOutcome::Conflict { current: 5 }
        ));
        assert!(
            interpret_cas_reply(
                &[Value::Int(-1), Value::BulkString(Vec::new())],
                "intents",
                "i"
            )
            .is_err()
        );
        assert!(
            interpret_cas_reply(
                &[Value::Int(-2), Value::BulkString(Vec::new())],
                "intents",
                "i"
            )
            .is_err()
        );
        assert!(interpret_cas_reply(&[Value::Int(7)], "intents", "i").is_err());
    }

    #[test]
    fn acquire_reply_interpretation_covers_grant_and_held() {
        use redis::Value;
        let granted = interpret_acquire_reply(
            &[
                Value::BulkString(b"granted".to_vec()),
                Value::BulkString(b"3".to_vec()),
                Value::BulkString(b"1767225600000".to_vec()),
            ],
            "lineage/x",
            "worker-b",
        )
        .unwrap();
        match granted {
            LeaseOutcome::Granted(grant) => {
                assert_eq!(grant.key, "lineage/x");
                assert_eq!(grant.owner, "worker-b");
                assert_eq!(grant.fencing_token, 3);
                assert_eq!(grant.expires_at.to_string(), "2026-01-01T00:00:00Z");
            }
            other => panic!("expected grant, got {other:?}"),
        }
        let held = interpret_acquire_reply(
            &[
                Value::BulkString(b"held".to_vec()),
                Value::BulkString(b"worker-a".to_vec()),
                Value::BulkString(b"1767225600000".to_vec()),
            ],
            "lineage/x",
            "worker-b",
        )
        .unwrap();
        match held {
            LeaseOutcome::HeldByOther { owner, expires_at } => {
                assert_eq!(owner, "worker-a");
                assert_eq!(expires_at.to_string(), "2026-01-01T00:00:00Z");
            }
            other => panic!("expected held-by-other, got {other:?}"),
        }
        assert!(interpret_acquire_reply(&[Value::Int(0)], "k", "o").is_err());
    }

    #[test]
    fn outbox_composition_prefers_the_delivery_state_hash() {
        let created = Timestamp::from_str("2026-02-03T04:05:06Z").unwrap();
        let event = OutboxEvent {
            sequence: 9,
            event_id: "evt_000000000009".to_string(),
            event_type: "deployment.scheduled".to_string(),
            payload: serde_json::json!({ "id": 1 }),
            created_at: created,
            attempts: 0,
            last_error: None,
            next_attempt_at: None,
            processed: false,
            dead_lettered: false,
        };
        let state: HashMap<String, String> = [
            ("attempts".to_string(), "2".to_string()),
            ("processed".to_string(), "0".to_string()),
            ("dead_lettered".to_string(), "0".to_string()),
            ("last_error".to_string(), "webhook 500".to_string()),
            (
                "next_attempt_at_ms".to_string(),
                created.as_millisecond().to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let composed = compose_outbox_event(event.clone(), &state);
        assert_eq!(composed.attempts, 2);
        assert_eq!(composed.last_error.as_deref(), Some("webhook 500"));
        assert_eq!(composed.next_attempt_at, Some(created));
        assert!(!composed.processed);
        assert!(!composed.dead_lettered);

        // Flags are stored as "0"/"1" strings, not "true"/"false".
        let processed_state: HashMap<String, String> = [("processed".to_string(), "1".to_string())]
            .into_iter()
            .collect();
        let composed = compose_outbox_event(event.clone(), &processed_state);
        assert!(composed.processed);
        assert!(!composed.dead_lettered);

        // An empty (or partially written) hash falls back to event defaults.
        let composed = compose_outbox_event(event, &HashMap::new());
        assert_eq!(composed.attempts, 0);
        assert!(composed.last_error.is_none());
        assert!(composed.next_attempt_at.is_none());
    }

    #[test]
    fn debug_output_never_contains_credentials() {
        let url = "redis://:hunter2@localhost:6379/0";
        assert!(redact_url(url).contains("****"));
        assert!(!redact_url(url).contains("hunter2"));
        // The repository type itself is only constructible with a live
        // server, so the contract is pinned on the redaction helper; a
        // derived Debug (which would embed the raw URL) is deliberately
        // not implemented.
    }
}
