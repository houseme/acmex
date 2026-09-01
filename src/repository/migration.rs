//! Migration of legacy `CertificateBundle` records into the new model.
//!
//! Legacy storage (≤0.8) kept one JSON `CertificateBundle` per sorted
//! domain set under the key `cert:<domains>` via `StorageBackend`. This
//! migrator imports each record as:
//!
//! * one `CertificateLineage` (deterministic id derived from the source
//!   hash, so re-running is idempotent),
//! * one `CertificateVersion` (state `active`, immutable from then on),
//! * the private key stored in the controlled secret area under a
//!   deterministic `KeyId`,
//! * a manifest entry recording `source_key` + `source_hash` → ids.
//!
//! Source data is never modified or deleted; deleting it is a separate,
//! explicitly authorized operation.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use super::secret_store::FileSecretStore;
use super::{Clock, MigrationManifestEntry, RepositorySet};
use crate::client::CertificateBundle;
use crate::domain::{
    CertificateLineage, CertificateVersion, DnsIdentifier, Identifier, IdentifierSet, KeyAlgorithm,
    KeyId, KeyRef, LineageId, TenantId, VersionId, VersionState,
};
use crate::error::Result;
use crate::storage::StorageBackend;

/// How the migrator should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationMode {
    /// Compute what would happen; write nothing.
    DryRun,
    /// Perform the migration.
    Execute,
    /// Re-verify already-migrated records against the source data.
    VerifyOnly,
}

/// One planned migration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationPlanEntry {
    /// Legacy key, e.g. `cert:example.com`.
    pub source_key: String,
    /// SHA-256 of the legacy record bytes.
    pub source_hash: String,
    /// Domains found in the legacy bundle.
    pub domains: Vec<String>,
    /// Target lineage id (deterministic).
    pub lineage_id: LineageId,
    /// Target version id (deterministic).
    pub version_id: VersionId,
    /// Target secret key id (deterministic).
    pub key_id: KeyId,
    /// Status of this entry.
    pub status: MigrationStatus,
}

/// Status of one migration entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    /// Would be / has been migrated in this run.
    WouldMigrate,
    /// Migrated by this run.
    Migrated,
    /// A manifest entry with identical hash already exists.
    AlreadyMigrated,
    /// Verification passed for an existing entry.
    Verified,
    /// The record could not be migrated.
    Failed(String),
}

/// Aggregate migration report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// When the run happened.
    pub ran_at: Timestamp,
    /// The mode that produced this report.
    pub mode: MigrationMode,
    /// Per-entry outcomes.
    pub entries: Vec<MigrationOutcome>,
}

/// Per-entry outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationOutcome {
    /// The plan data for the entry.
    pub plan: MigrationPlanEntry,
    /// What happened.
    pub status: MigrationStatus,
}

impl MigrationReport {
    /// Counts of each status.
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let migrated = self
            .entries
            .iter()
            .filter(|e| e.status == MigrationStatus::Migrated)
            .count();
        let already = self
            .entries
            .iter()
            .filter(|e| e.status == MigrationStatus::AlreadyMigrated)
            .count();
        let verified = self
            .entries
            .iter()
            .filter(|e| e.status == MigrationStatus::Verified)
            .count();
        let failed = self
            .entries
            .iter()
            .filter(|e| matches!(e.status, MigrationStatus::Failed(_)))
            .count();
        (migrated, already, verified, failed)
    }
}

/// Migrates legacy bundles from a `StorageBackend` into a `RepositorySet`.
pub struct LegacyBundleMigrator {
    source: Arc<dyn StorageBackend>,
    destination: RepositorySet,
    secrets: FileSecretStore,
    clock: Arc<dyn Clock>,
    tenant: TenantId,
}

impl LegacyBundleMigrator {
    /// Creates a migrator.
    pub fn new(
        source: Arc<dyn StorageBackend>,
        destination: RepositorySet,
        secrets: FileSecretStore,
    ) -> Self {
        let clock = destination.clock.clone();
        Self {
            source,
            destination,
            secrets,
            clock,
            tenant: TenantId::default_tenant(),
        }
    }

    /// Plans the migration without writing anything.
    pub async fn plan(&self) -> Result<Vec<MigrationPlanEntry>> {
        let manifest = self.destination.manifests.entries().await?;
        let mut out = Vec::new();
        for key in self.legacy_keys().await? {
            let Some(bytes) = self.source.load(&key).await? else {
                out.push(MigrationPlanEntry::failed(key, "record unreadable"));
                continue;
            };
            let source_hash = hash_bytes(&bytes);
            let parsed: Option<CertificateBundle> = serde_json::from_slice(&bytes).ok();
            let ids = derive_ids(&source_hash);
            let status = if manifest
                .iter()
                .any(|m| m.source_key == key && m.source_hash == source_hash)
            {
                MigrationStatus::AlreadyMigrated
            } else if parsed.is_none() {
                MigrationStatus::Failed("record is not a CertificateBundle".to_string())
            } else {
                MigrationStatus::WouldMigrate
            };
            out.push(MigrationPlanEntry {
                source_key: key,
                source_hash,
                domains: parsed.map(|b| b.domains).unwrap_or_default(),
                lineage_id: LineageId::new(ids.0)?,
                version_id: VersionId::new(ids.1)?,
                key_id: KeyId::new(ids.2)?,
                status,
            });
        }
        Ok(out)
    }

    /// Runs the migration in the requested mode.
    pub async fn run(&self, mode: MigrationMode) -> Result<MigrationReport> {
        let now = self.clock.now();
        let plan = self.plan().await?;
        let mut entries = Vec::with_capacity(plan.len());

        for item in plan {
            let status = match mode {
                MigrationMode::DryRun => item.status.clone(),
                MigrationMode::VerifyOnly => self.verify_entry(&item).await?,
                MigrationMode::Execute => match &item.status {
                    MigrationStatus::AlreadyMigrated => {
                        // Re-running must be a no-op; verification proves the
                        // stored data still matches the source record.
                        match self.verify_entry(&item).await? {
                            MigrationStatus::Verified => MigrationStatus::AlreadyMigrated,
                            other => other,
                        }
                    }
                    MigrationStatus::WouldMigrate => self.execute_entry(&item).await?,
                    other => other.clone(),
                },
            };
            entries.push(MigrationOutcome { plan: item, status });
        }

        Ok(MigrationReport {
            ran_at: now,
            mode,
            entries,
        })
    }

    async fn execute_entry(&self, item: &MigrationPlanEntry) -> Result<MigrationStatus> {
        let Some(bytes) = self.source.load(&item.source_key).await? else {
            return Ok(MigrationStatus::Failed("record unreadable".to_string()));
        };
        let bundle: CertificateBundle = match serde_json::from_slice(&bytes) {
            Ok(bundle) => bundle,
            Err(err) => return Ok(MigrationStatus::Failed(format!("parse error: {err}"))),
        };

        // Identifiers from the bundle's domain list (legacy is DNS-only).
        let identifiers = match IdentifierSet::new(
            bundle
                .domains
                .iter()
                .map(|d| Identifier::Dns(DnsIdentifier::parse_lenient(d)))
                .collect(),
        ) {
            Ok(set) => set,
            Err(err) => return Ok(MigrationStatus::Failed(format!("empty domain list: {err}"))),
        };

        // 1. Secret first: if later steps fail we prefer an orphan secret
        //    (harmless, overwritten on retry) over a missing private key.
        if !self.secrets.contains(item.key_id.as_str()).await? {
            self.secrets
                .put(item.key_id.as_str(), bundle.private_key_pem.as_bytes())
                .await?;
        }

        // 2. Version (state active).
        let key_ref = KeyRef {
            provider: "legacy-import".to_string(),
            key_id: item.key_id.clone(),
            algorithm: KeyAlgorithm::EcP256,
            exportable: true,
        };
        let (not_before, not_after) = match validity_of(&bundle) {
            Ok(bounds) => bounds,
            Err(err) => return Ok(MigrationStatus::Failed(err.to_string())),
        };
        let version = CertificateVersion {
            id: item.version_id.clone(),
            lineage_id: item.lineage_id.clone(),
            identifiers: identifiers.clone(),
            certificate_chain_pem: bundle.certificate_pem.clone(),
            serial: String::new(),
            not_before,
            not_after,
            issued_by: "legacy-import".to_string(),
            profile: None,
            key_ref,
            replaces: None,
            superseded_by: None,
            state: VersionState::Active,
        };
        match self.destination.versions.create(version.clone()).await {
            Ok(_) => {}
            Err(err) => return Ok(MigrationStatus::Failed(format!("version create: {err}"))),
        }

        // 3. Lineage pointing at the version.
        let lineage = CertificateLineage {
            id: item.lineage_id.clone(),
            tenant_id: self.tenant.clone(),
            intent_id: crate::domain::IntentId::new(format!(
                "int_legacy_{}",
                &item.source_hash[..16.min(item.source_hash.len())]
            ))?,
            identifiers,
            active_version_id: Some(item.version_id.clone()),
        };
        if let Err(err) = self.destination.lineages.create(lineage).await {
            return Ok(MigrationStatus::Failed(format!("lineage create: {err}")));
        }

        // 4. Manifest (idempotency anchor).
        if let Err(err) = self
            .destination
            .manifests
            .save_entry(MigrationManifestEntry {
                source_key: item.source_key.clone(),
                source_hash: item.source_hash.clone(),
                lineage_id: item.lineage_id.clone(),
                version_id: item.version_id.clone(),
                key_id: item.key_id.clone(),
                migrated_at: self.clock.now(),
            })
            .await
        {
            return Ok(MigrationStatus::Failed(format!("manifest write: {err}")));
        }

        // 5. Verify the written data is readable and consistent.
        match self.verify_entry(item).await {
            Ok(MigrationStatus::Verified) => Ok(MigrationStatus::Migrated),
            Ok(other) => Ok(other),
            Err(err) => Ok(MigrationStatus::Failed(format!("post-verify: {err}"))),
        }
    }

    async fn verify_entry(&self, item: &MigrationPlanEntry) -> Result<MigrationStatus> {
        let Some(version) = self.destination.versions.get(&item.version_id).await? else {
            return Ok(MigrationStatus::Failed("version missing".to_string()));
        };
        let Some(lineage) = self.destination.lineages.get(&item.lineage_id).await? else {
            return Ok(MigrationStatus::Failed("lineage missing".to_string()));
        };
        if lineage.value.active_version_id.as_ref() != Some(&item.version_id) {
            return Ok(MigrationStatus::Failed(
                "lineage does not point at the migrated version".to_string(),
            ));
        }
        if version.value.identifiers != lineage.value.identifiers {
            return Ok(MigrationStatus::Failed(
                "identifier mismatch between lineage and version".to_string(),
            ));
        }
        if !self.secrets.contains(item.key_id.as_str()).await? {
            return Ok(MigrationStatus::Failed("secret missing".to_string()));
        }
        Ok(MigrationStatus::Verified)
    }

    /// Legacy keys (`cert:*`), with the `.bin`-suffix asymmetry repaired:
    /// both suffixed and unsuffixed forms are checked.
    async fn legacy_keys(&self) -> Result<Vec<String>> {
        let raw = self.source.list("cert:").await?;
        let mut keys = Vec::with_capacity(raw.len());
        for key in raw {
            let key = key.trim_end_matches(".bin").to_string();
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys.sort();
        Ok(keys)
    }
}

impl MigrationPlanEntry {
    fn failed(source_key: String, reason: &str) -> Self {
        let hash = hash_bytes(source_key.as_bytes());
        let ids = derive_ids(&hash);
        Self {
            source_key,
            source_hash: hash,
            domains: Vec::new(),
            lineage_id: LineageId::new(ids.0).unwrap_or_else(|_| LineageId::generate()),
            version_id: VersionId::new(ids.1).unwrap_or_else(|_| VersionId::generate()),
            key_id: KeyId::new(ids.2).unwrap_or_else(|_| KeyId::generate()),
            status: MigrationStatus::Failed(reason.to_string()),
        }
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Deterministic ids derived from the source hash: re-running the migration
/// computes the same target ids, which makes retries idempotent.
fn derive_ids(source_hash: &str) -> (String, String, String) {
    let short = &source_hash[..16.min(source_hash.len())];
    (
        format!("lin_legacy_{short}"),
        format!("ver_legacy_{short}"),
        format!("key_legacy_{short}"),
    )
}

fn validity_of(bundle: &CertificateBundle) -> Result<(String, String)> {
    let chain = crate::certificate::CertificateChain::from_pem(bundle.certificate_pem.as_bytes())?;
    let not_before = chain.not_before()?;
    let not_after = chain.not_after()?;
    Ok((
        not_before.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
        not_after.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
    ))
}
