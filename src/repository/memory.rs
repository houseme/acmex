//! In-memory repository — the contract-test reference implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use jiff::Timestamp;

use super::{
    CasOutcome, Clock, CreateOutcome, EntityStore, Envelope, LeaseGrant, LeaseManager,
    LeaseOutcome, MigrationManifestEntry, MigrationManifestStore, OutboxEvent, OutboxRepository,
    RepositorySet, Versioned, bump_envelope, corrupt, envelope_revision, make_envelope,
};
use crate::error::Result;

#[async_trait]
impl EntityStore for MemoryEntityStore {
    async fn env_get(&self, aggregate: &str, id: &str) -> Result<Option<Value>> {
        let maps = self.maps.read().expect("memory repo lock poisoned");
        Ok(maps.get(aggregate).and_then(|m| m.get(id)).cloned())
    }

    async fn env_create(
        &self,
        aggregate: &str,
        id: &str,
        data: &Value,
        now: Timestamp,
    ) -> Result<CreateOutcome> {
        let mut maps = self.maps.write().expect("memory repo lock poisoned");
        let map = maps.entry(aggregate.to_string()).or_default();
        if map.contains_key(id) {
            return Ok(CreateOutcome::AlreadyExists);
        }
        map.insert(id.to_string(), make_envelope(data, now));
        Ok(CreateOutcome::Created)
    }

    async fn env_cas(
        &self,
        aggregate: &str,
        id: &str,
        expected: super::Revision,
        data: &Value,
        now: Timestamp,
    ) -> Result<CasOutcome> {
        let mut maps = self.maps.write().expect("memory repo lock poisoned");
        let map = maps.entry(aggregate.to_string()).or_default();
        let Some(existing) = map.get(id) else {
            return Err(corrupt(format!("{aggregate} `{id}` not found for update")));
        };
        let current = envelope_revision(existing)?;
        if current != expected {
            return Ok(CasOutcome::Conflict { current });
        }
        map.insert(id.to_string(), bump_envelope(existing, data, now)?);
        Ok(CasOutcome::Updated(current + 1))
    }

    async fn env_list(&self, aggregate: &str) -> Result<Vec<Envelope>> {
        let maps = self.maps.read().expect("memory repo lock poisoned");
        let mut out: Vec<Envelope> = maps
            .get(aggregate)
            .map(|m| {
                m.iter()
                    .map(|(id, value)| Envelope {
                        id: id.clone(),
                        value: value.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn env_delete(&self, aggregate: &str, id: &str) -> Result<()> {
        let mut maps = self.maps.write().expect("memory repo lock poisoned");
        if let Some(map) = maps.get_mut(aggregate) {
            map.remove(id);
        }
        Ok(())
    }
}

/// Shared state of the in-memory backend. Clones share the same data.
#[derive(Clone, Default)]
pub struct MemoryEntityStore {
    maps: Arc<RwLock<HashMap<String, HashMap<String, Value>>>>,
}

struct MemoryLeaseState {
    owner: String,
    fencing_token: super::FencingToken,
    expires_at: Timestamp,
}

#[derive(Default)]
struct MemoryOutbox {
    sequence: u64,
    events: Vec<OutboxEvent>,
}

/// The complete in-memory repository.
pub struct MemoryRepository {
    store: MemoryEntityStore,
    leases: Mutex<HashMap<String, MemoryLeaseState>>,
    outbox: Mutex<MemoryOutbox>,
    lease_counter: Mutex<super::FencingToken>,
    manifests: Mutex<Vec<MigrationManifestEntry>>,
    clock: Arc<dyn Clock>,
}

impl MemoryRepository {
    /// Creates an empty in-memory repository with the given clock.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            store: MemoryEntityStore::default(),
            leases: Mutex::new(HashMap::new()),
            outbox: Mutex::new(MemoryOutbox::default()),
            lease_counter: Mutex::new(0),
            manifests: Mutex::new(Vec::new()),
            clock,
        }
    }

    /// Creates an empty in-memory repository using the system clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(super::SystemClock))
    }

    /// Assembles the trait-object set backed by this instance.
    ///
    /// The aggregate repositories share the same underlying store through
    /// `Arc`; the `MemoryRepository` itself backs leases, outbox, manifests
    /// and accounts.
    pub fn into_set(self) -> RepositorySet {
        let arc = Arc::new(self);
        let mk = || {
            Arc::new(super::GenericRepository::new(
                arc.store.clone(),
                arc.clock.clone(),
            ))
        };
        RepositorySet {
            intents: mk(),
            lineages: mk(),
            versions: mk(),
            operations: mk(),
            challenge_leases: mk(),
            deployments: mk(),
            accounts: arc.clone(),
            outbox: arc.clone(),
            leases: arc.clone(),
            manifests: arc.clone(),
            clock: arc.clock.clone(),
        }
    }
}

#[async_trait]
impl LeaseManager for MemoryRepository {
    async fn acquire(&self, key: &str, owner: &str, ttl: Duration) -> Result<LeaseOutcome> {
        let now = self.clock.now();
        let expires = now
            .checked_add(jiff::Span::new().milliseconds(ttl.as_millis() as i64))
            .expect("lease ttl overflow");
        let mut leases = self.leases.lock().expect("lease lock poisoned");
        match leases.get(key) {
            Some(state) if state.expires_at > now && state.owner != owner => {
                Ok(LeaseOutcome::HeldByOther {
                    owner: state.owner.clone(),
                    expires_at: state.expires_at,
                })
            }
            Some(_) | None => {
                let token = {
                    let mut counter = self.lease_counter.lock().expect("counter poisoned");
                    *counter += 1;
                    *counter
                };
                leases.insert(
                    key.to_string(),
                    MemoryLeaseState {
                        owner: owner.to_string(),
                        fencing_token: token,
                        expires_at: expires,
                    },
                );
                Ok(LeaseOutcome::Granted(LeaseGrant {
                    key: key.to_string(),
                    owner: owner.to_string(),
                    fencing_token: token,
                    expires_at: expires,
                }))
            }
        }
    }

    async fn renew(
        &self,
        key: &str,
        owner: &str,
        fencing_token: super::FencingToken,
        ttl: Duration,
    ) -> Result<Option<LeaseGrant>> {
        let now = self.clock.now();
        let expires = now
            .checked_add(jiff::Span::new().milliseconds(ttl.as_millis() as i64))
            .expect("lease ttl overflow");
        let mut leases = self.leases.lock().expect("lease lock poisoned");
        match leases.get_mut(key) {
            Some(state)
                if state.owner == owner
                    && state.fencing_token == fencing_token
                    && state.expires_at > now =>
            {
                state.expires_at = expires;
                Ok(Some(LeaseGrant {
                    key: key.to_string(),
                    owner: owner.to_string(),
                    fencing_token: state.fencing_token,
                    expires_at: expires,
                }))
            }
            _ => Ok(None),
        }
    }

    async fn release(
        &self,
        key: &str,
        owner: &str,
        fencing_token: super::FencingToken,
    ) -> Result<()> {
        let mut leases = self.leases.lock().expect("lease lock poisoned");
        if let Some(state) = leases.get(key)
            && state.owner == owner
            && state.fencing_token == fencing_token
        {
            leases.remove(key);
        }
        Ok(())
    }
}

#[async_trait]
impl OutboxRepository for MemoryRepository {
    async fn append(
        &self,
        event_type: &str,
        payload: Value,
        event_id: Option<String>,
    ) -> Result<u64> {
        let mut outbox = self.outbox.lock().expect("outbox lock poisoned");
        outbox.sequence += 1;
        let sequence = outbox.sequence;
        outbox.events.push(OutboxEvent {
            sequence,
            event_id: event_id.unwrap_or_else(|| format!("evt_{sequence:012}")),
            event_type: event_type.to_string(),
            payload,
            created_at: self.clock.now(),
            attempts: 0,
            last_error: None,
            processed: false,
        });
        Ok(sequence)
    }

    async fn list_pending(&self, limit: usize) -> Result<Vec<OutboxEvent>> {
        let outbox = self.outbox.lock().expect("outbox lock poisoned");
        Ok(outbox
            .events
            .iter()
            .filter(|e| !e.processed)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn mark_processed(&self, sequence: u64) -> Result<()> {
        let mut outbox = self.outbox.lock().expect("outbox lock poisoned");
        if let Some(event) = outbox.events.iter_mut().find(|e| e.sequence == sequence) {
            event.processed = true;
        }
        Ok(())
    }

    async fn mark_failed(&self, sequence: u64, error: &str) -> Result<()> {
        let mut outbox = self.outbox.lock().expect("outbox lock poisoned");
        if let Some(event) = outbox.events.iter_mut().find(|e| e.sequence == sequence) {
            event.attempts += 1;
            event.last_error = Some(error.to_string());
        }
        Ok(())
    }

    async fn dead_letter(&self, sequence: u64, reason: &str) -> Result<()> {
        let mut outbox = self.outbox.lock().expect("outbox lock poisoned");
        if let Some(event) = outbox.events.iter_mut().find(|e| e.sequence == sequence) {
            event.processed = true;
            event.last_error = Some(format!("dead-letter: {reason}"));
        }
        Ok(())
    }
}

#[async_trait]
impl MigrationManifestStore for MemoryRepository {
    async fn save_entry(&self, entry: MigrationManifestEntry) -> Result<()> {
        let mut manifests = self.manifests.lock().expect("manifest lock poisoned");
        if !manifests.iter().any(|e| e.source_key == entry.source_key) {
            manifests.push(entry);
            manifests.sort_by(|a, b| a.source_key.cmp(&b.source_key));
        }
        Ok(())
    }

    async fn entries(&self) -> Result<Vec<MigrationManifestEntry>> {
        let manifests = self.manifests.lock().expect("manifest lock poisoned");
        Ok(manifests.clone())
    }
}

/// Accounts use upsert semantics; implemented directly over the store.
#[async_trait]
impl super::AccountRepository for MemoryRepository {
    async fn upsert(&self, account: crate::domain::AccountRecord) -> Result<()> {
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

    async fn get(&self, id: &str) -> Result<Option<Versioned<crate::domain::AccountRecord>>> {
        super::GenericRepository::new(self.store.clone(), self.clock.clone())
            .get_as("accounts", id)
            .await
    }

    async fn list(&self) -> Result<Vec<Versioned<crate::domain::AccountRecord>>> {
        super::GenericRepository::new(self.store.clone(), self.clock.clone())
            .list_as("accounts")
            .await
    }
}
