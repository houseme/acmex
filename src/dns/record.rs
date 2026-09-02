//! The DNS record provider port: present / get / cleanup TXT records.
//!
//! Providers do **not** judge public propagation — that is the observer's
//! job (see `propagation.rs`). `present_txt` must be safe under retries
//! (same value → same resource) and must never clobber other TXT values on
//! the same name; `cleanup_txt` removes exactly the record the locator
//! describes and treats absence as success.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// A TXT record creation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentTxt {
    /// Zone apex the record belongs to.
    pub zone: String,
    /// Full record name (`_acme-challenge.example.com`).
    pub record_name: String,
    /// The TXT value to publish.
    pub value: String,
    /// Idempotency key (session id): a retry with the same key must find or
    /// re-create the same resource, never duplicate it.
    pub idempotency_key: String,
}

/// Locator describing exactly one TXT resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DnsRecordLocator {
    /// Provider instance that created the record.
    pub provider_id: String,
    /// Zone apex.
    pub zone: String,
    /// Full record name.
    pub record_name: String,
    /// Provider record id, when the API exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    /// SHA-256 of the TXT value this locator was created for — the precise
    /// deletion target when multiple TXT values coexist.
    pub value_hash: String,
}

/// An observed TXT record (values themselves, for propagation matching).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    /// Full record name.
    pub record_name: String,
    /// All TXT values at the name.
    pub values: Vec<String>,
}

/// Idempotent cleanup outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordCleanupOutcome {
    /// The record was removed by this call.
    Removed,
    /// The record was already gone.
    AlreadyAbsent,
}

/// Present/get/cleanup port for DNS-01 TXT records.
#[async_trait]
pub trait DnsRecordProvider: Send + Sync {
    /// Which provider instance this is.
    fn provider_id(&self) -> &str;

    /// Creates (or idempotently finds) a TXT record and returns its locator.
    async fn present_txt(&self, request: PresentTxt) -> Result<DnsRecordLocator>;

    /// Reads the TXT values at a locator's name (best effort; used for
    /// verification and merge-on-CAS flows).
    async fn get_txt(&self, locator: &DnsRecordLocator) -> Result<Option<TxtRecord>>;

    /// Removes exactly the record the locator describes. Absence is success.
    async fn cleanup_txt(&self, locator: &DnsRecordLocator) -> Result<RecordCleanupOutcome>;
}

/// SHA-256 hex of a TXT value.
pub fn txt_value_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// An in-memory TXT provider for tests, contract tests and examples.
///
/// Models RRSet semantics faithfully: a name holds a *set* of values;
/// presenting an existing (name, value) is idempotent; cleanup removes one
/// value and leaves siblings alone.
#[derive(Default)]
pub struct FakeDnsRecordProvider {
    provider_id: String,
    zones: tokio::sync::RwLock<std::collections::HashMap<String, Vec<String>>>,
    failures: std::sync::atomic::AtomicUsize,
    create_calls: std::sync::atomic::AtomicUsize,
}

impl FakeDnsRecordProvider {
    /// A fake provider with the given instance id.
    pub fn new(provider_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            zones: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            failures: std::sync::atomic::AtomicUsize::new(0),
            create_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Scripts the next `n` provider calls (any operation) to fail with an
    /// auth error, exercising error classification paths.
    pub fn fail_next(&self, n: usize) {
        self.failures.store(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many present_txt calls happened.
    pub fn create_calls(&self) -> usize {
        self.create_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// All live records as (name, values).
    pub async fn snapshot(&self) -> Vec<(String, Vec<String>)> {
        self.zones
            .read()
            .await
            .iter()
            .map(|(name, values)| (name.clone(), values.clone()))
            .collect()
    }
}

#[async_trait]
impl DnsRecordProvider for FakeDnsRecordProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    async fn present_txt(&self, request: PresentTxt) -> Result<DnsRecordLocator> {
        self.create_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.failures.swap(0, std::sync::atomic::Ordering::SeqCst) > 0 {
            return Err(crate::error::AcmeError::protocol(
                "[PROVIDER_AUTH_FAILED] operator-action-required: 401 invalid credentials"
                    .to_string(),
            ));
        }
        let mut zones = self.zones.write().await;
        let values = zones.entry(request.record_name.clone()).or_default();
        if !values.contains(&request.value) {
            values.push(request.value.clone());
        }
        Ok(DnsRecordLocator {
            provider_id: self.provider_id.clone(),
            zone: request.zone,
            record_name: request.record_name,
            record_id: Some(format!("fake-{}", txt_value_hash(&request.value))),
            value_hash: txt_value_hash(&request.value),
        })
    }

    async fn get_txt(&self, locator: &DnsRecordLocator) -> Result<Option<TxtRecord>> {
        if self.failures.swap(0, std::sync::atomic::Ordering::SeqCst) > 0 {
            return Err(crate::error::AcmeError::protocol(
                "[PROVIDER_AUTH_FAILED] operator-action-required: 401".to_string(),
            ));
        }
        let zones = self.zones.read().await;
        Ok(zones.get(&locator.record_name).map(|values| TxtRecord {
            record_name: locator.record_name.clone(),
            values: values.clone(),
        }))
    }

    async fn cleanup_txt(&self, locator: &DnsRecordLocator) -> Result<RecordCleanupOutcome> {
        if self.failures.swap(0, std::sync::atomic::Ordering::SeqCst) > 0 {
            return Err(crate::error::AcmeError::protocol(
                "[PROVIDER_AUTH_FAILED] operator-action-required: 403".to_string(),
            ));
        }
        let mut zones = self.zones.write().await;
        // Remove by value hash: sibling TXT values on the same name survive.
        let Some(values) = zones.get_mut(&locator.record_name) else {
            return Ok(RecordCleanupOutcome::AlreadyAbsent);
        };
        let before = values.len();
        values.retain(|value| txt_value_hash(value) != locator.value_hash);
        if values.len() == before {
            return Ok(RecordCleanupOutcome::AlreadyAbsent);
        }
        if values.is_empty() {
            zones.remove(&locator.record_name);
        }
        Ok(RecordCleanupOutcome::Removed)
    }
}
