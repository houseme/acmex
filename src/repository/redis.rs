//! Redis-backed aggregate repository.
//!
//! The implementation reuses the same generic aggregate layer as memory/file,
//! but maps envelopes to Redis keys with per-aggregate ID indexes. Create and
//! compare-and-set are Lua scripts so callers get real atomic repository
//! semantics instead of a read-modify-write race.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde_json::Value;

use super::{
    AccountRepository, CasOutcome, Clock, CreateOutcome, EntityStore, Envelope, FencingToken,
    GenericRepository, LeaseGrant, LeaseManager, LeaseOutcome, MigrationManifestEntry,
    MigrationManifestStore, OutboxEvent, OutboxRepository, RepositorySet, Revision, Versioned,
    bump_envelope, corrupt, envelope_revision, make_envelope,
};
use crate::domain::AccountRecord;
use crate::error::{AcmeError, Result};

const DEFAULT_KEY_PREFIX: &str = "acmex:v1:repo";

#[derive(Clone)]
struct RedisEntityStore {
    manager: ::redis::aio::ConnectionManager,
    key_prefix: Arc<str>,
}

impl RedisEntityStore {
    async fn new(redis_url: &str, key_prefix: Arc<str>) -> Result<Self> {
        let client =
            ::redis::Client::open(redis_url).map_err(|error| redis_error("open client", error))?;
        let manager = client
            .get_connection_manager()
            .await
            .map_err(|error| redis_error("connect", error))?;
        Ok(Self {
            manager,
            key_prefix,
        })
    }

    fn value_key(&self, aggregate: &str, id: &str) -> String {
        format!(
            "{}:entity:{aggregate}:{}",
            self.key_prefix,
            encode_component(id)
        )
    }

    fn index_key(&self, aggregate: &str) -> String {
        format!("{}:index:{aggregate}", self.key_prefix)
    }

    async fn get_raw(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.manager.clone();
        ::redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("get entity", error))
    }
}

#[async_trait]
impl EntityStore for RedisEntityStore {
    async fn env_get(&self, aggregate: &str, id: &str) -> Result<Option<Value>> {
        let Some(raw) = self.get_raw(&self.value_key(aggregate, id)).await? else {
            return Ok(None);
        };
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|error| corrupt(format!("redis {aggregate} `{id}`: {error}")))
    }

    async fn env_create(
        &self,
        aggregate: &str,
        id: &str,
        data: &Value,
        now: Timestamp,
    ) -> Result<CreateOutcome> {
        let envelope = make_envelope(data, now);
        let bytes = serde_json::to_string(&envelope)?;
        let mut conn = self.manager.clone();
        let created: i64 = ::redis::Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) == 1 then
              return 0
            end
            redis.call('SET', KEYS[1], ARGV[1])
            redis.call('SADD', KEYS[2], ARGV[2])
            return 1
            "#,
        )
        .key(self.value_key(aggregate, id))
        .key(self.index_key(aggregate))
        .arg(bytes)
        .arg(id)
        .invoke_async(&mut conn)
        .await
        .map_err(|error| redis_error("create entity", error))?;
        Ok(if created == 1 {
            CreateOutcome::Created
        } else {
            CreateOutcome::AlreadyExists
        })
    }

    async fn env_cas(
        &self,
        aggregate: &str,
        id: &str,
        expected: Revision,
        data: &Value,
        now: Timestamp,
    ) -> Result<CasOutcome> {
        let key = self.value_key(aggregate, id);
        let Some(existing) = self.env_get(aggregate, id).await? else {
            return Err(corrupt(format!("{aggregate} `{id}` missing for update")));
        };
        let envelope = bump_envelope(&existing, data, now)?;
        let bytes = serde_json::to_string(&envelope)?;
        let mut conn = self.manager.clone();
        let result: Vec<i64> = ::redis::Script::new(
            r#"
            local existing = redis.call('GET', KEYS[1])
            if not existing then
              return {-1, 0}
            end
            local ok, decoded = pcall(cjson.decode, existing)
            if not ok or decoded['revision'] == nil then
              return {-2, 0}
            end
            local current = tonumber(decoded['revision'])
            if current ~= tonumber(ARGV[1]) then
              return {0, current}
            end
            redis.call('SET', KEYS[1], ARGV[2])
            return {1, current + 1}
            "#,
        )
        .key(key)
        .arg(expected)
        .arg(bytes)
        .invoke_async(&mut conn)
        .await
        .map_err(|error| redis_error("cas entity", error))?;
        match result.as_slice() {
            [1, revision] => Ok(CasOutcome::Updated(*revision as Revision)),
            [0, current] => Ok(CasOutcome::Conflict {
                current: *current as Revision,
            }),
            [-1, _] => Err(corrupt(format!("{aggregate} `{id}` missing for update"))),
            [-2, _] => Err(corrupt(format!("{aggregate} `{id}` has invalid envelope"))),
            other => Err(corrupt(format!("unexpected redis cas response: {other:?}"))),
        }
    }

    async fn env_list(&self, aggregate: &str) -> Result<Vec<Envelope>> {
        let mut conn = self.manager.clone();
        let mut ids: Vec<String> = ::redis::cmd("SMEMBERS")
            .arg(self.index_key(aggregate))
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("list entity index", error))?;
        ids.sort();

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(value) = self.env_get(aggregate, &id).await? {
                out.push(Envelope { id, value });
            }
        }
        Ok(out)
    }

    async fn env_delete(&self, aggregate: &str, id: &str) -> Result<()> {
        let mut conn = self.manager.clone();
        let _: () = ::redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(self.value_key(aggregate, id))
            .ignore()
            .cmd("SREM")
            .arg(self.index_key(aggregate))
            .arg(id)
            .ignore()
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("delete entity", error))?;
        Ok(())
    }
}

/// Complete Redis repository set.
pub struct RedisRepository {
    store: RedisEntityStore,
    clock: Arc<dyn Clock>,
    key_prefix: Arc<str>,
}

impl RedisRepository {
    /// Opens a Redis repository using the system clock.
    pub async fn new(redis_url: &str) -> Result<Self> {
        Self::with_clock(redis_url, Arc::new(super::SystemClock)).await
    }

    /// Opens a Redis repository with an injectable clock.
    pub async fn with_clock(redis_url: &str, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::with_key_prefix(redis_url, DEFAULT_KEY_PREFIX, clock).await
    }

    /// Opens a Redis repository with a custom key prefix.
    ///
    /// The default prefix is stable for production (`acmex:v1:repo`), while
    /// tests can use a unique prefix per run to avoid cross-run contamination
    /// without flushing the Redis database.
    pub async fn with_key_prefix(
        redis_url: &str,
        key_prefix: impl Into<Arc<str>>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let key_prefix = key_prefix.into();
        Ok(Self {
            store: RedisEntityStore::new(redis_url, key_prefix.clone()).await?,
            clock,
            key_prefix,
        })
    }

    /// Assembles the trait-object set backed by this instance.
    pub fn into_set(self) -> RepositorySet {
        let arc = Arc::new(self);
        let mk = || Arc::new(GenericRepository::new(arc.store.clone(), arc.clock.clone()));
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

    fn lease_key(&self, key: &str) -> String {
        format!("{}:lease:{}", self.key_prefix, encode_component(key))
    }

    fn lease_counter_key(&self, key: &str) -> String {
        format!("{}:lease-token:{}", self.key_prefix, encode_component(key))
    }

    fn outbox_sequence_key(&self) -> String {
        format!("{}:outbox:sequence", self.key_prefix)
    }

    fn outbox_index_key(&self) -> String {
        format!("{}:outbox:index", self.key_prefix)
    }

    fn outbox_event_key(&self, sequence: u64) -> String {
        format!("{}:outbox:event:{sequence:012}", self.key_prefix)
    }

    async fn outbox_event(&self, sequence: u64) -> Result<Option<OutboxEvent>> {
        let mut conn = self.store.manager.clone();
        let raw: Option<String> = ::redis::cmd("GET")
            .arg(self.outbox_event_key(sequence))
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("get outbox event", error))?;
        raw.map(|raw| {
            serde_json::from_str(&raw)
                .map_err(|error| corrupt(format!("outbox event {sequence}: {error}")))
        })
        .transpose()
    }

    async fn update_outbox(
        &self,
        sequence: u64,
        mutate: impl FnOnce(&mut OutboxEvent),
    ) -> Result<()> {
        let Some(mut event) = self.outbox_event(sequence).await? else {
            return Ok(());
        };
        mutate(&mut event);
        let bytes = serde_json::to_string(&event)?;
        let mut conn = self.store.manager.clone();
        let _: () = ::redis::cmd("SET")
            .arg(self.outbox_event_key(sequence))
            .arg(bytes)
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("update outbox event", error))?;
        Ok(())
    }
}

#[async_trait]
impl LeaseManager for RedisRepository {
    async fn acquire(&self, key: &str, owner: &str, ttl: Duration) -> Result<LeaseOutcome> {
        let now = self.clock.now();
        let expires = now
            .checked_add(jiff::Span::new().milliseconds(ttl.as_millis() as i64))
            .expect("lease ttl overflow");
        let mut conn = self.store.manager.clone();
        let result: Vec<String> = ::redis::Script::new(
            r#"
            local owner = redis.call('HGET', KEYS[1], 'owner')
            local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at') or '0')
            if owner and expires_at > tonumber(ARGV[1]) and owner ~= ARGV[2] then
              return {'held', owner, tostring(expires_at), '0'}
            end
            local token = redis.call('INCR', KEYS[2])
            redis.call('HSET', KEYS[1],
              'owner', ARGV[2],
              'fencing_token', token,
              'expires_at', ARGV[3])
            redis.call('PEXPIREAT', KEYS[1], ARGV[3])
            return {'granted', ARGV[2], ARGV[3], tostring(token)}
            "#,
        )
        .key(self.lease_key(key))
        .key(self.lease_counter_key(key))
        .arg(now.as_millisecond())
        .arg(owner)
        .arg(expires.as_millisecond())
        .invoke_async(&mut conn)
        .await
        .map_err(|error| redis_error("acquire lease", error))?;
        match result.as_slice() {
            [status, holder, expires_at, _] if status == "held" => Ok(LeaseOutcome::HeldByOther {
                owner: holder.clone(),
                expires_at: timestamp_from_millis(expires_at, "lease expires_at")?,
            }),
            [status, holder, expires_at, token] if status == "granted" => {
                Ok(LeaseOutcome::Granted(LeaseGrant {
                    key: key.to_string(),
                    owner: holder.clone(),
                    fencing_token: parse_u64(token, "lease token")?,
                    expires_at: timestamp_from_millis(expires_at, "lease expires_at")?,
                }))
            }
            other => Err(corrupt(format!(
                "unexpected redis lease response: {other:?}"
            ))),
        }
    }

    async fn renew(
        &self,
        key: &str,
        owner: &str,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<Option<LeaseGrant>> {
        let now = self.clock.now();
        let expires = now
            .checked_add(jiff::Span::new().milliseconds(ttl.as_millis() as i64))
            .expect("lease ttl overflow");
        let mut conn = self.store.manager.clone();
        let renewed: i64 = ::redis::Script::new(
            r#"
            local owner = redis.call('HGET', KEYS[1], 'owner')
            local token = tonumber(redis.call('HGET', KEYS[1], 'fencing_token') or '0')
            local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at') or '0')
            if owner ~= ARGV[2] or token ~= tonumber(ARGV[3]) or expires_at <= tonumber(ARGV[1]) then
              return 0
            end
            redis.call('HSET', KEYS[1], 'expires_at', ARGV[4])
            redis.call('PEXPIREAT', KEYS[1], ARGV[4])
            return 1
            "#,
        )
        .key(self.lease_key(key))
        .arg(now.as_millisecond())
        .arg(owner)
        .arg(fencing_token)
        .arg(expires.as_millisecond())
        .invoke_async(&mut conn)
        .await
        .map_err(|error| redis_error("renew lease", error))?;
        if renewed == 1 {
            Ok(Some(LeaseGrant {
                key: key.to_string(),
                owner: owner.to_string(),
                fencing_token,
                expires_at: expires,
            }))
        } else {
            Ok(None)
        }
    }

    async fn release(&self, key: &str, owner: &str, fencing_token: FencingToken) -> Result<()> {
        let mut conn = self.store.manager.clone();
        let _: i64 = ::redis::Script::new(
            r#"
            local owner = redis.call('HGET', KEYS[1], 'owner')
            local token = tonumber(redis.call('HGET', KEYS[1], 'fencing_token') or '0')
            if owner == ARGV[1] and token == tonumber(ARGV[2]) then
              return redis.call('DEL', KEYS[1])
            end
            return 0
            "#,
        )
        .key(self.lease_key(key))
        .arg(owner)
        .arg(fencing_token)
        .invoke_async(&mut conn)
        .await
        .map_err(|error| redis_error("release lease", error))?;
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
        let mut conn = self.store.manager.clone();
        let sequence: u64 = ::redis::cmd("INCR")
            .arg(self.outbox_sequence_key())
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("append outbox sequence", error))?;
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
        let bytes = serde_json::to_string(&event)?;
        let _: () = ::redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(self.outbox_event_key(sequence))
            .arg(bytes)
            .ignore()
            .cmd("ZADD")
            .arg(self.outbox_index_key())
            .arg(sequence)
            .arg(sequence)
            .ignore()
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("append outbox event", error))?;
        Ok(sequence)
    }

    async fn list_pending(&self, limit: usize) -> Result<Vec<OutboxEvent>> {
        let mut conn = self.store.manager.clone();
        let sequences: Vec<u64> = ::redis::cmd("ZRANGE")
            .arg(self.outbox_index_key())
            .arg(0)
            .arg(-1_i64)
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_error("list outbox index", error))?;
        let now = self.clock.now();
        let mut events = Vec::new();
        for sequence in sequences {
            let Some(event) = self.outbox_event(sequence).await? else {
                continue;
            };
            if !event.processed
                && !event.dead_lettered
                && event.next_attempt_at.is_none_or(|retry_at| retry_at <= now)
            {
                events.push(event);
                if events.len() == limit {
                    break;
                }
            }
        }
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
        next_attempt_at: Option<Timestamp>,
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
            event.attempts = 0;
            event.last_error = None;
            event.next_attempt_at = None;
        })
        .await
    }
}

#[async_trait]
impl MigrationManifestStore for RedisRepository {
    async fn save_entry(&self, entry: MigrationManifestEntry) -> Result<()> {
        let data = serde_json::to_value(&entry)?;
        self.store
            .env_create("migration", &entry.source_key, &data, self.clock.now())
            .await?;
        Ok(())
    }

    async fn entries(&self) -> Result<Vec<MigrationManifestEntry>> {
        Ok(
            GenericRepository::new(self.store.clone(), self.clock.clone())
                .list_as("migration")
                .await?
                .into_iter()
                .map(|entry: Versioned<MigrationManifestEntry>| entry.value)
                .collect(),
        )
    }
}

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
                let revision = envelope_revision(&existing)?;
                self.store
                    .env_cas("accounts", &account.id, revision, &data, self.clock.now())
                    .await?;
                Ok(())
            }
        }
    }

    async fn get(&self, id: &str) -> Result<Option<Versioned<AccountRecord>>> {
        GenericRepository::new(self.store.clone(), self.clock.clone())
            .get_as("accounts", id)
            .await
    }

    async fn list(&self) -> Result<Vec<Versioned<AccountRecord>>> {
        GenericRepository::new(self.store.clone(), self.clock.clone())
            .list_as("accounts")
            .await
    }
}

fn redis_error(context: &str, error: ::redis::RedisError) -> AcmeError {
    AcmeError::storage(format!("Redis repository {context} error: {error}"))
}

fn timestamp_from_millis(value: &str, field: &str) -> Result<Timestamp> {
    let ms = value
        .parse::<i64>()
        .map_err(|error| corrupt(format!("{field} is not an integer: {error}")))?;
    Timestamp::from_millisecond(ms).map_err(|error| corrupt(format!("{field}: {error}")))
}

fn parse_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|error| corrupt(format!("{field} is not an integer: {error}")))
}

fn encode_component(id: &str) -> String {
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
