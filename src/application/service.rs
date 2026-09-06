use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::domain::{
    CertificateIntent, CertificateLineage, ChallengeLease, ChallengeLeaseState, ChallengeSet,
    IdentifierSet, IntentId, LineageId, OperationId, OperationKind, OperationRecord, OperationRef,
    OperationStatus, OperationSubject, TenantId, VersionId, validate_order_policy,
};
use crate::error::{AcmeError, Result};
use crate::metrics::{AuditEvent, EventAuditor};
use crate::repository::{
    CasOutcome, CreateOutcome, FileRepository, MemoryRepository, RepositorySet,
};
#[cfg(test)]
use crate::types::ChallengeType;

use super::types::{
    CancelOperation, CertificateApplication, CertificateQuery, ChallengeLeaseView,
    ChallengeSessionView, CreateCertificateIntent, DeployCertificate, IntentView, IssueCertificate,
    OperationView, RenewCertificate, RevokeCertificate, UpdateCertificateIntent, VersionView,
    command_hash, ensure_idempotency_key, op_ref,
};

/// Builder for the default embedded Application Service.
pub struct ApplicationServiceBuilder {
    repositories: Option<RepositorySet>,
    offered_challenges: ChallengeSet,
}

impl ApplicationServiceBuilder {
    /// Starts with an in-memory repository and all built-in challenges offered.
    pub fn new() -> Self {
        Self {
            repositories: None,
            offered_challenges: ChallengeSet::all(),
        }
    }

    /// Uses an already assembled repository set.
    pub fn with_repositories(mut self, repositories: RepositorySet) -> Self {
        self.repositories = Some(repositories);
        self
    }

    /// Restricts challenges offered by the configured CA/backend.
    pub fn with_offered_challenges(mut self, offered: ChallengeSet) -> Self {
        self.offered_challenges = offered;
        self
    }

    /// Builds a repository-backed service from configuration.
    pub async fn from_config(config: &crate::config::Config) -> Result<Self> {
        let repositories = match config.repository.backend.as_str() {
            "memory" => MemoryRepository::new().into_set(),
            "file" => {
                let Some(file) = &config.repository.file else {
                    return Err(AcmeError::configuration(
                        "repository.file.path is required when repository.backend = \"file\"",
                    ));
                };
                FileRepository::new(&file.path).await?.into_set()
            }
            #[cfg(feature = "redis")]
            "redis" => {
                let Some(redis) = &config.repository.redis else {
                    return Err(AcmeError::configuration(
                        "repository.redis.url is required when repository.backend = \"redis\"",
                    ));
                };
                crate::repository::RedisRepository::connect(&redis.url)
                    .await?
                    .into_set()
            }
            #[cfg(not(feature = "redis"))]
            "redis" => {
                let _ = &config.repository.redis;
                return Err(AcmeError::configuration(
                    "repository backend `redis` requires the `redis` feature",
                ));
            }
            other => {
                return Err(AcmeError::configuration(format!(
                    "unsupported repository backend `{other}`"
                )));
            }
        };
        Ok(Self::new().with_repositories(repositories))
    }

    /// Returns both the service and its repository set.
    pub fn build(self) -> Result<(Arc<RepositoryCertificateApplication>, RepositorySet)> {
        let repositories = self
            .repositories
            .unwrap_or_else(|| MemoryRepository::new().into_set());
        let service = Arc::new(RepositoryCertificateApplication {
            repositories: repositories.clone(),
            offered_challenges: self.offered_challenges,
        });
        Ok((service, repositories))
    }
}

impl Default for ApplicationServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Repository-backed implementation of the certificate lifecycle use cases.
pub struct RepositoryCertificateApplication {
    repositories: RepositorySet,
    offered_challenges: ChallengeSet,
}

impl RepositoryCertificateApplication {
    /// Creates a service using repository defaults.
    pub fn new(repositories: RepositorySet) -> Self {
        Self {
            repositories,
            offered_challenges: ChallengeSet::all(),
        }
    }

    /// The repositories used by this service.
    pub fn repositories(&self) -> &RepositorySet {
        &self.repositories
    }

    async fn find_intent_by_idempotency(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<crate::repository::Versioned<CertificateIntent>>> {
        Ok(self
            .repositories
            .intents
            .list()
            .await?
            .into_iter()
            .find(|stored| stored.value.idempotency_key == idempotency_key))
    }

    fn intent_payload_hash(intent: &CertificateIntent) -> Result<String> {
        command_hash(&(
            intent
                .identifiers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            &intent.ca_policy,
            &intent.validation_policy,
            &intent.key_policy,
            &intent.renewal_policy,
            &intent.delivery_targets,
        ))
    }

    async fn existing_operation(
        &self,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<Option<OperationRef>> {
        let existing = self
            .repositories
            .operations
            .find_by_idempotency_key(idempotency_key)
            .await?;
        if let Some(stored) = existing {
            if stored.value.request_hash.as_deref() == Some(request_hash) {
                return Ok(Some(op_ref(&stored.value)));
            }
            return Err(AcmeError::conflict(
                "Idempotency-Key was already used with a different request payload",
            ));
        }
        Ok(None)
    }

    async fn lineage_for_intent(&self, intent: &CertificateIntent) -> Result<CertificateLineage> {
        if let Some(stored) = self
            .repositories
            .lineages
            .list()
            .await?
            .into_iter()
            .find(|stored| stored.value.intent_id == intent.id)
        {
            return Ok(stored.value);
        }

        let lineage = CertificateLineage::new(
            LineageId::generate(),
            intent.tenant_id.clone(),
            intent.id.clone(),
            intent.identifiers.clone(),
        );
        match self.repositories.lineages.create(lineage.clone()).await? {
            CreateOutcome::Created | CreateOutcome::AlreadyExists => Ok(lineage),
        }
    }

    async fn resolve_lineage_for_renew(
        &self,
        command: &RenewCertificate,
    ) -> Result<CertificateLineage> {
        if let Some(id) = &command.lineage_id {
            let lineage = self
                .repositories
                .lineages
                .get(id)
                .await?
                .map(|stored| stored.value)
                .ok_or_else(|| AcmeError::not_found(format!("lineage `{id}` not found")))?;
            ensure_tenant(&command.context.tenant_id, &lineage.tenant_id, "lineage")?;
            return Ok(lineage);
        }

        let identifiers = IdentifierSet::parse(&command.identifiers)
            .map_err(|e| AcmeError::invalid_input(e.to_string()))?;
        self.repositories
            .lineages
            .list()
            .await?
            .into_iter()
            .find(|stored| {
                stored.value.identifiers == identifiers
                    && stored.value.tenant_id == command.context.tenant_id
            })
            .map(|stored| stored.value)
            .ok_or_else(|| {
                AcmeError::not_found(
                    "no certificate lineage matches the supplied renewal identifiers",
                )
            })
    }

    async fn submit_operation(
        &self,
        context: &super::types::ActorContext,
        kind: OperationKind,
        subject: OperationSubject,
        idempotency_key: String,
        request_hash: String,
        step_init: Option<(crate::domain::WorkflowStepKind, String)>,
    ) -> Result<OperationRef> {
        if let Some(existing) = self
            .existing_operation(&idempotency_key, &request_hash)
            .await?
        {
            return Ok(existing);
        }
        let now = self.repositories.clock.now();
        let mut record = OperationRecord::new(
            OperationId::generate(),
            kind,
            subject,
            Some(idempotency_key),
            Some(request_hash),
            now,
        );
        // Initialization payload for a step (external CSR material): consumed
        // and replaced by the owning step's own output on first success, so
        // the material survives restarts without ever being duplicated.
        if let Some((step_kind, payload)) = step_init
            && let Some(step) = record.steps.iter_mut().find(|s| s.kind == step_kind)
        {
            step.output_ref = Some(payload);
        }
        match self.repositories.operations.create(record.clone()).await? {
            CreateOutcome::Created => {
                self.repositories
                    .outbox
                    .append(
                        "operation.created",
                        serde_json::json!({
                            "operation_id": record.id.as_str(),
                            "kind": record.kind.as_str(),
                            "subject": record.subject,
                            "tenant_id": context.tenant_id.as_str(),
                            "actor": &context.subject,
                            "request_id": context.request_id.clone(),
                        }),
                        None,
                    )
                    .await?;
                EventAuditor::track_audit(
                    &self.repositories,
                    AuditEvent::success(
                        context,
                        format!("operation.{}", record.kind.as_str()),
                        record.id.as_str(),
                        Some(record.id.as_str().to_string()),
                        None,
                        self.repositories.clock.now(),
                    ),
                )
                .await?;
                Ok(op_ref(&record))
            }
            CreateOutcome::AlreadyExists => Ok(op_ref(&record)),
        }
    }

    /// Restores the external-CSR initialization payload for a renewal.
    ///
    /// External-CSR lineages can never fall back to managed key generation,
    /// so a renewal is only executable when the CSR material can be
    /// re-supplied. The original CSR is durable: the issuing operation's
    /// `CreateCsr` step keeps it in its output payload — as the issue
    /// request's initialization PEM until the step first succeeds, then as
    /// the completed CSR payload (base64 DER) — and `PersistVersion` derives
    /// the version id deterministically from the operation id
    /// (`ver_<operation id>`), so the active version leads back to it.
    ///
    /// When the lineage's active version carries an external key, the CSR is
    /// recovered from there, re-encoded as a PEM `CERTIFICATE REQUEST` and
    /// seeded onto the Renew operation exactly like `issue` seeds it.
    ///
    /// `None` means "not an external lineage" or "material not recoverable":
    /// the operation is still created and then fails at `CreateCsr` with the
    /// stable operator-action-required error instead of silently switching to
    /// managed keys. Recoverable-history corruption is logged and degrades to
    /// `None`; repository errors propagate.
    async fn external_csr_renewal_init(
        &self,
        lineage: &CertificateLineage,
    ) -> Result<Option<String>> {
        let Some(active) = &lineage.active_version_id else {
            return Ok(None);
        };
        let version = self
            .repositories
            .versions
            .get(active)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| {
                AcmeError::storage(format!(
                    "lineage `{}` references missing active version `{}`",
                    lineage.id, active
                ))
            })?;
        if version.key_ref.provider != crate::key::EXTERNAL_CSR_KEY_PROVIDER {
            return Ok(None);
        }
        let Some(stored) = self.issuing_operation_of_version(&version).await? else {
            tracing::warn!(
                lineage_id = %lineage.id,
                version_id = %version.id,
                "external renewal cannot recover the issuing operation's CSR payload"
            );
            return Ok(None);
        };
        let Some(step) = stored
            .steps
            .iter()
            .find(|s| s.kind == crate::domain::WorkflowStepKind::CreateCsr)
        else {
            tracing::warn!(
                lineage_id = %lineage.id,
                operation_id = %stored.id,
                "issuing operation has no CreateCsr step"
            );
            return Ok(None);
        };
        let Some(raw) = step.output_ref.as_deref() else {
            tracing::warn!(
                lineage_id = %lineage.id,
                operation_id = %stored.id,
                "issuing operation's CreateCsr step has no output yet"
            );
            return Ok(None);
        };
        let payload = match serde_json::from_str::<PersistedCsrOutput>(raw) {
            Ok(payload) => payload,
            Err(err) => {
                tracing::warn!(
                    lineage_id = %lineage.id,
                    operation_id = %stored.id,
                    error = %err,
                    "issuing operation's CreateCsr payload is unreadable"
                );
                return Ok(None);
            }
        };
        let pem = if let Some(pem) = payload.external_csr_pem {
            pem
        } else if let Some(csr_der) = payload.csr_der {
            let csr_der = match BASE64.decode(csr_der.as_bytes()) {
                Ok(der) => der,
                Err(err) => {
                    tracing::warn!(
                        lineage_id = %lineage.id,
                        operation_id = %stored.id,
                        error = %err,
                        "persisted external CSR DER is not valid base64"
                    );
                    return Ok(None);
                }
            };
            // Re-encoded as PEM so the Renew operation consumes exactly the
            // same initialization payload shape the issue path produces.
            pem::Pem::new("CERTIFICATE REQUEST", csr_der).to_string()
        } else {
            tracing::warn!(
                lineage_id = %lineage.id,
                operation_id = %stored.id,
                "persisted CreateCsr payload carries no CSR material"
            );
            return Ok(None);
        };
        Ok(Some(
            serde_json::json!({ "external_csr_pem": pem }).to_string(),
        ))
    }

    /// Resolves the Issue operation that produced `version` via the
    /// deterministic `ver_<operation id>` version id. `None` when the id
    /// shape, the record or its kind does not match.
    async fn issuing_operation_of_version(
        &self,
        version: &crate::domain::CertificateVersion,
    ) -> Result<Option<OperationRecord>> {
        let Some(operation_id) = version.id.as_str().strip_prefix("ver_") else {
            return Ok(None);
        };
        let Ok(operation_id) = OperationId::new(operation_id.to_string()) else {
            return Ok(None);
        };
        let Some(stored) = self.repositories.operations.get(&operation_id).await? else {
            return Ok(None);
        };
        if stored.value.kind != OperationKind::Issue {
            return Ok(None);
        }
        Ok(Some(stored.value))
    }

    async fn version_and_lineage(
        &self,
        version_id: &VersionId,
    ) -> Result<(crate::domain::CertificateVersion, CertificateLineage)> {
        let version = self
            .repositories
            .versions
            .get(version_id)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| AcmeError::not_found(format!("version `{version_id}` not found")))?;
        let lineage = self
            .repositories
            .lineages
            .get(&version.lineage_id)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| {
                AcmeError::storage(format!(
                    "version `{version_id}` references missing lineage `{}`",
                    version.lineage_id
                ))
            })?;
        Ok((version, lineage))
    }

    async fn operation_visible_to_tenant(
        &self,
        operation: &OperationRecord,
        tenant_id: &TenantId,
    ) -> Result<bool> {
        if let Some(intent_id) = &operation.subject.intent_id {
            return Ok(self
                .repositories
                .intents
                .get(intent_id)
                .await?
                .is_some_and(|stored| stored.value.tenant_id == *tenant_id));
        }
        if let Some(lineage_id) = &operation.subject.lineage_id {
            return Ok(self
                .repositories
                .lineages
                .get(lineage_id)
                .await?
                .is_some_and(|stored| stored.value.tenant_id == *tenant_id));
        }
        if let Some(version_id) = &operation.subject.version_id {
            let Some(version) = self.repositories.versions.get(version_id).await? else {
                return Ok(false);
            };
            return Ok(self
                .repositories
                .lineages
                .get(&version.value.lineage_id)
                .await?
                .is_some_and(|stored| stored.value.tenant_id == *tenant_id));
        }
        Ok(false)
    }

    /// Every stored operation id, bounded per status by the repository's
    /// page cap. Used to enumerate challenge sessions, which are only
    /// reachable per-operation.
    async fn all_operation_ids(&self) -> Result<Vec<OperationId>> {
        let mut ids = Vec::new();
        for status in [
            OperationStatus::Queued,
            OperationStatus::Running,
            OperationStatus::Waiting,
            OperationStatus::Succeeded,
            OperationStatus::Failed,
            OperationStatus::CancelRequested,
            OperationStatus::Cancelled,
            OperationStatus::Compensating,
            OperationStatus::CompensationFailed,
        ] {
            ids.extend(
                self.repositories
                    .operations
                    .list_by_status(status, 500)
                    .await?
                    .into_iter()
                    .map(|stored| stored.value.id),
            );
        }
        Ok(ids)
    }
}

#[async_trait]
impl CertificateApplication for RepositoryCertificateApplication {
    async fn create_intent(&self, command: CreateCertificateIntent) -> Result<IntentView> {
        let idempotency_key = ensure_idempotency_key(&command.idempotency_key)?;
        let identifiers = IdentifierSet::parse(&command.identifiers)
            .map_err(|e| AcmeError::invalid_input(e.to_string()))?;
        let normalized_identifiers: Vec<String> =
            identifiers.iter().map(ToString::to_string).collect();
        let request_hash = command_hash(&(
            &normalized_identifiers,
            &command.ca_policy,
            &command.validation_policy,
            &command.key_policy,
            &command.renewal_policy,
            &command.delivery_targets,
        ))?;

        if let Some(existing) = self.find_intent_by_idempotency(&idempotency_key).await? {
            if Self::intent_payload_hash(&existing.value)? == request_hash {
                return Ok(existing.into());
            }
            return Err(AcmeError::conflict(
                "Idempotency-Key was already used with a different request payload",
            ));
        }

        validate_order_policy(
            identifiers.as_slice(),
            &self.offered_challenges,
            &command.validation_policy,
        )
        .map_err(|e| AcmeError::invalid_input(e.to_string()))?;

        validate_external_csr_mode(&command.key_policy, command.external_csr.as_deref())?;
        command
            .key_policy
            .validate()
            .map_err(|e| AcmeError::invalid_input(e.to_string()))?;

        let intent = CertificateIntent {
            id: IntentId::generate(),
            tenant_id: command.context.tenant_id.clone(),
            identifiers,
            ca_policy: command.ca_policy,
            validation_policy: command.validation_policy,
            key_policy: command.key_policy,
            renewal_policy: command.renewal_policy,
            delivery_targets: command.delivery_targets,
            idempotency_key,
            generation: 1,
        };
        intent.validate()?;

        match self.repositories.intents.create(intent.clone()).await? {
            CreateOutcome::Created => {
                self.repositories
                    .outbox
                    .append(
                        "intent.created",
                        serde_json::json!({
                            "intent_id": intent.id.as_str(),
                            "tenant_id": intent.tenant_id.as_str(),
                            "actor": &command.context.actor,
                        }),
                        None,
                    )
                    .await?;
                EventAuditor::track_audit(
                    &self.repositories,
                    AuditEvent::success(
                        &command.context,
                        "intent.create",
                        intent.id.as_str(),
                        None,
                        None,
                        self.repositories.clock.now(),
                    ),
                )
                .await?;
                Ok(IntentView::from_intent(&intent))
            }
            CreateOutcome::AlreadyExists => self
                .repositories
                .intents
                .get(&intent.id)
                .await?
                .map(IntentView::from)
                .ok_or_else(|| AcmeError::storage("intent create raced but entity is missing")),
        }
    }

    async fn update_intent(&self, command: UpdateCertificateIntent) -> Result<IntentView> {
        // The key is validated for presence (transport contract) but never
        // persisted: v1 keeps no per-intent idempotency ledger, replay
        // safety comes from the value-comparison no-op below.
        ensure_idempotency_key(&command.idempotency_key)?;
        loop {
            let stored = self
                .repositories
                .intents
                .get(&command.intent_id)
                .await?
                .ok_or_else(|| {
                    AcmeError::not_found(format!("intent `{}` not found", command.intent_id))
                })?;
            ensure_tenant(
                &command.context.tenant_id,
                &stored.value.tenant_id,
                "intent",
            )?;

            if let Some(expected) = command.expected_generation
                && expected != stored.value.generation
            {
                return Err(AcmeError::conflict(format!(
                    "intent `{}` is at generation {}, If-Match expected {expected}",
                    command.intent_id, stored.value.generation
                )));
            }

            // Apply only the mutable fields; each provided field fully
            // replaces the stored value, omitted fields keep theirs.
            let mut next = stored.value.clone();
            let mut fields_changed: Vec<&'static str> = Vec::new();
            if let Some(renewal_policy) = &command.renewal_policy
                && &next.renewal_policy != renewal_policy
            {
                next.renewal_policy = renewal_policy.clone();
                fields_changed.push("renewal_policy");
            }
            if let Some(delivery_targets) = &command.delivery_targets
                && &next.delivery_targets != delivery_targets
            {
                next.delivery_targets = delivery_targets.clone();
                fields_changed.push("delivery_targets");
            }

            // Identical replay: nothing differs from the stored values, so
            // the current view is returned without a second generation
            // bump (documented idempotency behavior).
            if fields_changed.is_empty() {
                return Ok(stored.into());
            }

            next.generation += 1;
            next.validate()?;

            match self
                .repositories
                .intents
                .update(stored.revision, next.clone())
                .await?
            {
                CasOutcome::Updated(_) => {
                    // Outbox + audit trail follow the intent.created
                    // pattern; only field names are recorded, never policy
                    // contents.
                    self.repositories
                        .outbox
                        .append(
                            "intent.updated",
                            serde_json::json!({
                                "intent_id": next.id.as_str(),
                                "tenant_id": next.tenant_id.as_str(),
                                "generation": next.generation,
                                "fields_changed": fields_changed,
                                "actor": &command.context.actor,
                            }),
                            None,
                        )
                        .await?;
                    EventAuditor::track_audit(
                        &self.repositories,
                        AuditEvent::success(
                            &command.context,
                            "intent.update",
                            next.id.as_str(),
                            None,
                            Some(next.generation),
                            self.repositories.clock.now(),
                        ),
                    )
                    .await?;
                    return Ok(IntentView::from_intent(&next));
                }
                // Another writer advanced the intent between read and
                // write; re-validate against fresh state (including the
                // If-Match generation guard).
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }

    async fn issue(&self, command: IssueCertificate) -> Result<OperationRef> {
        let idempotency_key = ensure_idempotency_key(&command.idempotency_key)?;
        let intent = self
            .repositories
            .intents
            .get(&command.intent_id)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| {
                AcmeError::not_found(format!("intent `{}` not found", command.intent_id))
            })?;
        ensure_tenant(&command.context.tenant_id, &intent.tenant_id, "intent")?;
        // External-CSR material: mode exclusivity is validated here (HTTP 400
        // semantics) and the PEM is forwarded verbatim as the CreateCsr
        // step's initialization payload. Signature and identifier matching
        // run in the workflow step where the KeyProvider lives. The material
        // is part of the idempotency hash so replays with different CSRs are
        // rejected instead of silently reusing the first operation.
        let step_init = external_csr_init_payload(&intent, command.external_csr.as_deref())?
            .map(|payload| (crate::domain::WorkflowStepKind::CreateCsr, payload));
        let lineage = self.lineage_for_intent(&intent).await?;
        let request_hash = command_hash(&(
            OperationKind::Issue,
            &command.intent_id,
            &command.external_csr,
        ))?;
        self.submit_operation(
            &command.context,
            OperationKind::Issue,
            OperationSubject {
                intent_id: Some(intent.id),
                lineage_id: Some(lineage.id),
                version_id: None,
            },
            idempotency_key,
            request_hash,
            step_init,
        )
        .await
    }

    async fn renew(&self, command: RenewCertificate) -> Result<OperationRef> {
        let idempotency_key = ensure_idempotency_key(&command.idempotency_key)?;
        let lineage = self.resolve_lineage_for_renew(&command).await?;
        // External-CSR lineages renew from their recorded material: the
        // active version's issuing operation still holds the original CSR,
        // which is recovered and seeded like the issue path does. Without a
        // recoverable CSR the operation is created anyway and fails at
        // CreateCsr with the stable operator-action-required error — the
        // material can only come from the external key holder.
        let step_init = self
            .external_csr_renewal_init(&lineage)
            .await?
            .map(|payload| (crate::domain::WorkflowStepKind::CreateCsr, payload));
        let request_hash = command_hash(&(
            OperationKind::Renew,
            &lineage.id,
            command.force,
            &command.identifiers,
        ))?;
        self.submit_operation(
            &command.context,
            OperationKind::Renew,
            OperationSubject {
                intent_id: Some(lineage.intent_id),
                lineage_id: Some(lineage.id),
                version_id: None,
            },
            idempotency_key,
            request_hash,
            step_init,
        )
        .await
    }

    async fn revoke(&self, command: RevokeCertificate) -> Result<OperationRef> {
        let idempotency_key = ensure_idempotency_key(&command.idempotency_key)?;
        let (version, lineage) = self.version_and_lineage(&command.version_id).await?;
        ensure_tenant(&command.context.tenant_id, &lineage.tenant_id, "version")?;
        let request_hash =
            command_hash(&(OperationKind::Revoke, &command.version_id, &command.reason))?;
        self.submit_operation(
            &command.context,
            OperationKind::Revoke,
            OperationSubject {
                intent_id: None,
                lineage_id: Some(version.lineage_id),
                version_id: Some(command.version_id),
            },
            idempotency_key,
            request_hash,
            None,
        )
        .await
    }

    async fn deploy(&self, command: DeployCertificate) -> Result<OperationRef> {
        let idempotency_key = ensure_idempotency_key(&command.idempotency_key)?;
        let (version, lineage) = self.version_and_lineage(&command.version_id).await?;
        ensure_tenant(&command.context.tenant_id, &lineage.tenant_id, "version")?;
        let request_hash = command_hash(&(
            OperationKind::Deploy,
            &command.version_id,
            &command.target_ids,
        ))?;
        self.submit_operation(
            &command.context,
            OperationKind::Deploy,
            OperationSubject {
                intent_id: None,
                lineage_id: Some(version.lineage_id),
                version_id: Some(command.version_id),
            },
            idempotency_key,
            request_hash,
            None,
        )
        .await
    }

    async fn cancel_operation(&self, command: CancelOperation) -> Result<OperationView> {
        loop {
            let stored = self
                .repositories
                .operations
                .get(&command.operation_id)
                .await?
                .ok_or_else(|| {
                    AcmeError::not_found(format!("operation `{}` not found", command.operation_id))
                })?;
            if !self
                .operation_visible_to_tenant(&stored.value, &command.context.tenant_id)
                .await?
            {
                return Err(AcmeError::not_found(format!(
                    "operation `{}` not found",
                    command.operation_id
                )));
            }
            if stored.value.status.is_terminal() {
                return Ok(stored.value.into());
            }
            let mut next = stored
                .value
                .transition(OperationStatus::CancelRequested)
                .map_err(AcmeError::storage)?;
            next.updated_at = self.repositories.clock.now();
            match self
                .repositories
                .operations
                .update(stored.revision, next.clone())
                .await?
            {
                CasOutcome::Updated(_) => return Ok(next.into()),
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }

    async fn retry_challenge_cleanup(
        &self,
        context: super::types::ActorContext,
        lease_id: crate::domain::ChallengeLeaseId,
    ) -> Result<ChallengeLeaseView> {
        loop {
            let stored = self
                .repositories
                .challenge_leases
                .get(&lease_id)
                .await?
                .ok_or_else(|| {
                    AcmeError::not_found(format!("challenge lease `{lease_id}` not found"))
                })?;
            // Leases carry no tenant of their own: authorize through the
            // owning operation's subject lineage, like cancellation does.
            let operation = self
                .repositories
                .operations
                .get(&stored.value.operation_id)
                .await?
                .ok_or_else(|| {
                    AcmeError::not_found(format!(
                        "operation `{}` behind challenge lease `{lease_id}` not found",
                        stored.value.operation_id
                    ))
                })?;
            if !self
                .operation_visible_to_tenant(&operation.value, &context.tenant_id)
                .await?
            {
                // Cross-tenant probes must not reveal existence.
                return Err(AcmeError::not_found(format!(
                    "challenge lease `{lease_id}` not found"
                )));
            }
            if stored.value.state != ChallengeLeaseState::CleanupFailed {
                return Err(AcmeError::conflict(format!(
                    "challenge lease `{lease_id}` is `{}`, only `cleanup_failed` leases can be requeued",
                    stored.value.state.as_str()
                )));
            }
            let mut next = stored.value.clone();
            // Only the state flips: `cleanup_attempts` and
            // `last_cleanup_error` stay untouched so the audit trail of the
            // failed attempts survives. The lease is now back in the
            // scanner queue and the background ChallengeCleanupScanner
            // picks it up on its next pass.
            next.state = ChallengeLeaseState::CleanupPending;
            match self
                .repositories
                .challenge_leases
                .update(stored.revision, next.clone())
                .await?
            {
                CasOutcome::Updated(_) => return Ok(next.into()),
                // The scanner raced us; re-validate against fresh state.
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }
}

fn ensure_tenant(
    request_tenant: &TenantId,
    resource_tenant: &TenantId,
    resource: &str,
) -> Result<()> {
    if request_tenant == resource_tenant {
        Ok(())
    } else {
        Err(AcmeError::not_found(format!("{resource} not found")))
    }
}

/// The persisted `CreateCsr` step output of an issuing operation, in either
/// of its two shapes (mirrors `workflow::issuance::{ExternalCsrInitPayload,
/// CsrPayload}`; only the fields the external-renewal restore needs):
///
/// * initialization form until the step first succeeds: `external_csr_pem`;
/// * completed form afterwards: `csr_der` (base64, standard alphabet).
#[derive(serde::Deserialize)]
struct PersistedCsrOutput {
    /// PEM `CERTIFICATE REQUEST` (issue seeding form).
    #[serde(default)]
    external_csr_pem: Option<String>,
    /// Base64 (standard) encoded CSR DER (completed step form).
    #[serde(default)]
    csr_der: Option<String>,
}

/// Validates external-CSR mode exclusivity for one command.
///
/// * `key_policy.mode = external_csr` requires CSR material (missing
///   material would silently fall back to managed key generation — exactly
///   the behavior this mode exists to prevent);
/// * `key_policy.mode = managed` forbids CSR material (AcmeX would generate
///   and hold the key, making the supplied CSR dead weight at best);
/// * supplied material must parse as a PEM `CERTIFICATE REQUEST`.
///
/// Signature and SAN/identifier matching run later in the `CreateCsr`
/// workflow step, where the KeyProvider lives.
fn validate_external_csr_mode(
    policy: &crate::domain::KeyPolicy,
    external_csr: Option<&str>,
) -> Result<()> {
    use crate::domain::KeyManagementMode;
    match (policy.mode, external_csr) {
        (KeyManagementMode::ExternalCsr, Some(pem)) => {
            crate::key::ExternalCsr::from_pem(pem)?;
            Ok(())
        }
        (KeyManagementMode::ExternalCsr, None) => Err(AcmeError::invalid_input(
            "key_policy.mode external_csr requires external_csr material (a PEM CSR); \
             AcmeX must never generate the private key for this intent",
        )),
        (KeyManagementMode::Managed, Some(_)) => Err(AcmeError::invalid_input(
            "external_csr material requires key_policy.mode external_csr; managed keys \
             are generated by AcmeX",
        )),
        (KeyManagementMode::Managed, None) => Ok(()),
    }
}

/// Builds the `CreateCsr` step initialization payload for an issue request.
///
/// Returns `Some(json)` only for external-CSR intents; the JSON field name
/// is the contract shared with `workflow::issuance::ExternalCsrInitPayload`.
fn external_csr_init_payload(
    intent: &CertificateIntent,
    external_csr: Option<&str>,
) -> Result<Option<String>> {
    if intent.key_policy.mode != crate::domain::KeyManagementMode::ExternalCsr {
        // Same exclusivity rule as intent creation: material on a managed
        // intent is a configuration error, not dead weight.
        validate_external_csr_mode(&intent.key_policy, external_csr)?;
        return Ok(None);
    }
    let pem = external_csr.ok_or_else(|| {
        AcmeError::invalid_input(
            "intent key_policy.mode is external_csr; the issue request must carry \
             external_csr material (a PEM CSR)",
        )
    })?;
    validate_external_csr_mode(&intent.key_policy, Some(pem))?;
    Ok(Some(
        serde_json::json!({ "external_csr_pem": pem }).to_string(),
    ))
}

#[async_trait]
impl CertificateQuery for RepositoryCertificateApplication {
    async fn get_intent(&self, id: &IntentId) -> Result<Option<IntentView>> {
        Ok(self
            .repositories
            .intents
            .get(id)
            .await?
            .map(IntentView::from))
    }

    async fn list_intents(&self, limit: usize) -> Result<Vec<IntentView>> {
        let limit = limit.clamp(1, 500);
        let mut views: Vec<IntentView> = self
            .repositories
            .intents
            .list()
            .await?
            .into_iter()
            .map(IntentView::from)
            .collect();
        views.sort_by(|a, b| b.id.as_str().cmp(a.id.as_str()));
        views.truncate(limit);
        Ok(views)
    }

    async fn get_operation(&self, id: &OperationId) -> Result<Option<OperationView>> {
        Ok(self
            .repositories
            .operations
            .get(id)
            .await?
            .map(|stored| stored.value.into()))
    }

    async fn list_operations(&self, limit: usize) -> Result<Vec<OperationView>> {
        let mut out: Vec<OperationView> = Vec::new();
        for status in [
            OperationStatus::Queued,
            OperationStatus::Running,
            OperationStatus::Waiting,
            OperationStatus::Succeeded,
            OperationStatus::Failed,
            OperationStatus::CancelRequested,
            OperationStatus::Cancelled,
            OperationStatus::Compensating,
            OperationStatus::CompensationFailed,
        ] {
            out.extend(
                self.repositories
                    .operations
                    .list_by_status(status, limit)
                    .await?
                    .into_iter()
                    .map(|stored| stored.value.into()),
            );
        }
        out.sort_by_key(|op| op.created_at);
        out.truncate(limit);
        Ok(out)
    }

    async fn get_lineage(&self, id: &LineageId) -> Result<Option<CertificateLineage>> {
        Ok(self
            .repositories
            .lineages
            .get(id)
            .await?
            .map(|stored| stored.value))
    }

    async fn list_versions(&self, lineage_id: &LineageId) -> Result<Vec<VersionView>> {
        Ok(self
            .repositories
            .versions
            .list_by_lineage(lineage_id)
            .await?
            .into_iter()
            .map(|stored| stored.value.into())
            .collect())
    }

    async fn get_version(&self, id: &VersionId) -> Result<Option<VersionView>> {
        Ok(self
            .repositories
            .versions
            .get(id)
            .await?
            .map(|stored| stored.value.into()))
    }

    async fn list_challenge_sessions(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<ChallengeSessionView>> {
        // Sessions reference only `operation_id` (no tenant of their own).
        // For v1 reads are scoped by operation and tenancy is inherited from
        // the operation's subject lineage, mirroring how operation lookups
        // are addressed today.
        Ok(self
            .repositories
            .challenge_sessions
            .list_by_operation(operation_id)
            .await?
            .into_iter()
            .map(|stored| stored.value.into())
            .collect())
    }

    async fn list_cleanup_pending(&self) -> Result<Vec<ChallengeLeaseView>> {
        // The scanner queue (`active` + `cleanup_pending`) comes straight
        // from the repository.
        let mut leases: Vec<ChallengeLease> = self
            .repositories
            .challenge_leases
            .list_needing_cleanup()
            .await?
            .into_iter()
            .map(|stored| stored.value)
            .collect();
        let mut known: HashSet<String> = leases
            .iter()
            .map(|lease| lease.id.as_str().to_string())
            .collect();
        // Leases that exhausted their automatic budget (`cleanup_failed`)
        // leave the scanner queue even though their external resource still
        // exists — and they are exactly what operators must see and retry
        // (T05 manual retry entry). Every lease is referenced by its
        // session's `lease_id`, so they are recovered by walking the
        // sessions and merging in any referenced lease that is not yet
        // `cleaned` and not already listed.
        for operation_id in self.all_operation_ids().await? {
            for session in self
                .repositories
                .challenge_sessions
                .list_by_operation(&operation_id)
                .await?
            {
                let Some(lease_id) = &session.value.lease_id else {
                    continue;
                };
                if known.contains(lease_id.as_str()) {
                    continue;
                }
                let Some(stored) = self.repositories.challenge_leases.get(lease_id).await? else {
                    continue;
                };
                if stored.value.state != ChallengeLeaseState::Cleaned {
                    known.insert(stored.value.id.as_str().to_string());
                    leases.push(stored.value);
                }
            }
        }
        leases.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        Ok(leases.into_iter().map(Into::into).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{ActorContext, CertificateApplication, CertificateQuery};

    fn create_command(key: &str, identifiers: Vec<&str>) -> CreateCertificateIntent {
        CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: identifiers.into_iter().map(str::to_string).collect(),
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: Default::default(),
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            external_csr: None,
            idempotency_key: key.to_string(),
        }
    }

    fn external_csr_command(key: &str, domain: &str) -> CreateCertificateIntent {
        let mut command = create_command(key, vec![domain]);
        command.key_policy.mode = crate::domain::KeyManagementMode::ExternalCsr;
        command.external_csr = Some(test_csr_pem(domain));
        command
    }

    /// A well-formed PEM CSR for `domain`, generated outside AcmeX exactly
    /// like an external key holder would.
    fn test_csr_pem(domain: &str) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    async fn service() -> Arc<RepositoryCertificateApplication> {
        let (service, _) = ApplicationServiceBuilder::new().build().unwrap();
        service
    }

    #[tokio::test]
    async fn application_create_intent_is_idempotent_for_same_payload() {
        let service = service().await;
        let first = service
            .create_intent(create_command("idem-1", vec!["Example.COM"]))
            .await
            .unwrap();
        let second = service
            .create_intent(create_command("idem-1", vec!["example.com"]))
            .await
            .unwrap();
        assert_eq!(first.id, second.id);
    }

    #[tokio::test]
    async fn application_create_intent_rejects_idempotency_payload_conflict() {
        let service = service().await;
        service
            .create_intent(create_command("idem-1", vec!["example.com"]))
            .await
            .unwrap();
        let err = service
            .create_intent(create_command("idem-1", vec!["example.org"]))
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::Conflict(_)));
    }

    #[tokio::test]
    async fn application_issue_creates_operation_and_lineage() {
        let service = service().await;
        let intent = service
            .create_intent(create_command("intent-key", vec!["example.com"]))
            .await
            .unwrap();
        let op = service
            .issue(IssueCertificate {
                context: ActorContext::default(),
                intent_id: intent.id.clone(),
                external_csr: None,
                idempotency_key: "issue-key".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(op.kind, OperationKind::Issue);
        assert!(op.subject.lineage_id.is_some());
        assert!(service.get_operation(&op.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn application_renew_by_identifier_requires_existing_lineage() {
        let service = service().await;
        let err = service
            .renew(RenewCertificate {
                context: ActorContext::default(),
                lineage_id: None,
                identifiers: vec!["missing.example".to_string()],
                force: true,
                idempotency_key: "renew-key".to_string(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::NotFound(_)));
    }

    #[tokio::test]
    async fn application_cancel_updates_operation_status() {
        let service = service().await;
        let intent = service
            .create_intent(create_command("intent-cancel", vec!["example.com"]))
            .await
            .unwrap();
        let op = service
            .issue(IssueCertificate {
                context: ActorContext::default(),
                intent_id: intent.id,
                external_csr: None,
                idempotency_key: "issue-cancel".to_string(),
            })
            .await
            .unwrap();
        let cancelled = service
            .cancel_operation(CancelOperation {
                context: ActorContext::default(),
                operation_id: op.id,
            })
            .await
            .unwrap();
        assert_eq!(cancelled.status, "cancel_requested");
    }

    #[tokio::test]
    async fn external_csr_intent_requires_csr_material() {
        let service = service().await;
        let mut command = create_command("extcsr-missing", vec!["example.com"]);
        command.key_policy.mode = crate::domain::KeyManagementMode::ExternalCsr;
        let err = service.create_intent(command).await.unwrap_err();
        assert!(matches!(err, AcmeError::InvalidInput(_)));
        assert!(
            err.to_string().contains("requires external_csr material"),
            "error must name the missing material: {err}"
        );
    }

    #[tokio::test]
    async fn managed_intent_rejects_external_csr_material() {
        let service = service().await;
        let mut command = create_command("extcsr-managed", vec!["example.com"]);
        command.external_csr = Some(test_csr_pem("example.com"));
        let err = service.create_intent(command).await.unwrap_err();
        assert!(matches!(err, AcmeError::InvalidInput(_)));
        assert!(
            err.to_string().contains("requires key_policy.mode"),
            "error must name the mode exclusivity: {err}"
        );
    }

    #[tokio::test]
    async fn external_csr_intent_rejects_malformed_pem() {
        let service = service().await;
        let mut command = create_command("extcsr-bad-pem", vec!["example.com"]);
        command.key_policy.mode = crate::domain::KeyManagementMode::ExternalCsr;
        command.external_csr = Some("not a pem".to_string());
        let err = service.create_intent(command).await.unwrap_err();
        assert!(
            matches!(err, AcmeError::Pem(_)),
            "malformed CSR PEM must be a pem error: {err}"
        );
    }

    #[tokio::test]
    async fn external_csr_intent_is_accepted_and_replayed_idempotently() {
        let service = service().await;
        let intent = service
            .create_intent(external_csr_command("extcsr-ok", "example.com"))
            .await
            .unwrap();
        // Same key + same material replays to the same intent.
        let replay = service
            .create_intent(external_csr_command("extcsr-ok", "example.com"))
            .await
            .unwrap();
        assert_eq!(intent.id, replay.id);
    }

    #[tokio::test]
    async fn issue_requires_csr_material_for_external_csr_intent() {
        let service = service().await;
        let intent = service
            .create_intent(external_csr_command("extcsr-issue", "example.com"))
            .await
            .unwrap();
        let err = service
            .issue(IssueCertificate {
                context: ActorContext::default(),
                intent_id: intent.id,
                external_csr: None,
                idempotency_key: "issue-extcsr-missing".to_string(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::InvalidInput(_)));
        assert!(
            err.to_string().contains("must carry external_csr"),
            "error must demand the material: {err}"
        );
    }

    #[tokio::test]
    async fn issue_rejects_csr_material_for_managed_intent() {
        let service = service().await;
        let intent = service
            .create_intent(create_command("managed-issue", vec!["example.com"]))
            .await
            .unwrap();
        let err = service
            .issue(IssueCertificate {
                context: ActorContext::default(),
                intent_id: intent.id,
                external_csr: Some(test_csr_pem("example.com")),
                idempotency_key: "issue-managed-csr".to_string(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn issue_seeds_external_csr_into_create_csr_step_payload() {
        let service = service().await;
        let intent = service
            .create_intent(external_csr_command("extcsr-seed", "example.com"))
            .await
            .unwrap();
        let op = service
            .issue(IssueCertificate {
                context: ActorContext::default(),
                intent_id: intent.id,
                external_csr: Some(test_csr_pem("example.com")),
                idempotency_key: "issue-extcsr-seed".to_string(),
            })
            .await
            .unwrap();
        let record = service
            .repositories
            .operations
            .get(&op.id)
            .await
            .unwrap()
            .unwrap();
        let step = record
            .value
            .steps
            .iter()
            .find(|s| s.kind == crate::domain::WorkflowStepKind::CreateCsr)
            .unwrap();
        let payload: serde_json::Value =
            serde_json::from_str(step.output_ref.as_deref().unwrap()).unwrap();
        assert!(
            payload["external_csr_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE REQUEST"),
            "the CreateCsr step must carry the external CSR init payload"
        );
    }

    fn renew_command(key: &str, lineage_id: Option<LineageId>) -> RenewCertificate {
        RenewCertificate {
            context: ActorContext::default(),
            lineage_id,
            identifiers: Vec::new(),
            force: false,
            idempotency_key: key.to_string(),
        }
    }

    /// A renewal of an external-CSR lineage re-seeds the original CSR onto
    /// the Renew operation's CreateCsr step, recovered from the issuing
    /// operation's persisted payload — the deterministic dead end where a
    /// renewal previously failed forever is now executable.
    #[tokio::test]
    async fn renew_recovers_external_csr_from_the_issuing_operation() {
        let service = service().await;
        let csr_pem = test_csr_pem("example.com");
        let intent = service
            .create_intent(external_csr_command("extcsr-renew", "example.com"))
            .await
            .unwrap();
        let issued = service
            .issue(IssueCertificate {
                context: ActorContext::default(),
                intent_id: intent.id.clone(),
                external_csr: Some(csr_pem.clone()),
                idempotency_key: "issue-extcsr-renew".to_string(),
            })
            .await
            .unwrap();
        // Simulate the completed first issuance: the version exists and the
        // lineage points at it (the engine does this in production).
        let lineage_stored = service
            .repositories
            .lineages
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|stored| stored.value.intent_id == intent.id)
            .expect("issue creates the lineage");
        let version_id = VersionId::new(format!("ver_{}", issued.id)).unwrap();
        let external_key_ref = crate::domain::KeyRef {
            provider: "external".to_string(),
            key_id: crate::domain::KeyId::new("key_external_renewed").unwrap(),
            algorithm: crate::domain::KeyAlgorithm::EcP256,
            exportable: false,
        };
        let version = crate::domain::CertificateVersion {
            id: version_id.clone(),
            lineage_id: lineage_stored.value.id.clone(),
            identifiers: crate::domain::IdentifierSet::parse(["example.com"]).unwrap(),
            certificate_chain_pem: "-----BEGIN CERTIFICATE-----".to_string(),
            serial: "01".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2026-04-01T00:00:00Z".to_string(),
            issued_by: "test-ca".to_string(),
            profile: None,
            key_ref: external_key_ref,
            replaces: None,
            superseded_by: None,
            verification_report: None,
            state: crate::domain::VersionState::Issued,
        };
        service.repositories.versions.create(version).await.unwrap();
        let mut lineage = lineage_stored.value.clone();
        lineage.active_version_id = Some(version_id);
        service
            .repositories
            .lineages
            .update(lineage_stored.revision, lineage)
            .await
            .unwrap();

        let op = service
            .renew(renew_command(
                "renew-extcsr-renew",
                Some(lineage_stored.value.id),
            ))
            .await
            .unwrap();
        let record = service
            .repositories
            .operations
            .get(&op.id)
            .await
            .unwrap()
            .unwrap();
        let step = record
            .value
            .steps
            .iter()
            .find(|s| s.kind == crate::domain::WorkflowStepKind::CreateCsr)
            .unwrap();
        let payload: serde_json::Value =
            serde_json::from_str(step.output_ref.as_deref().unwrap()).unwrap();
        assert_eq!(
            payload["external_csr_pem"].as_str().unwrap(),
            csr_pem,
            "the Renew operation must carry the recovered external CSR"
        );
    }

    /// Managed lineages keep the renewal behavior unchanged: no CSR
    /// initialization payload is seeded (the CreateCsr step generates or
    /// reuses managed keys).
    #[tokio::test]
    async fn renew_of_managed_lineage_seeds_no_csr_payload() {
        let service = service().await;
        let intent = service
            .create_intent(create_command("managed-renew", vec!["example.com"]))
            .await
            .unwrap();
        service
            .issue(IssueCertificate {
                context: ActorContext::default(),
                intent_id: intent.id.clone(),
                external_csr: None,
                idempotency_key: "issue-managed-renew".to_string(),
            })
            .await
            .unwrap();
        let lineage_id = service
            .repositories
            .lineages
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|stored| stored.value.intent_id == intent.id)
            .map(|stored| stored.value.id)
            .expect("issue creates the lineage");
        let op = service
            .renew(renew_command("renew-managed", Some(lineage_id)))
            .await
            .unwrap();
        let record = service
            .repositories
            .operations
            .get(&op.id)
            .await
            .unwrap()
            .unwrap();
        let step = record
            .value
            .steps
            .iter()
            .find(|s| s.kind == crate::domain::WorkflowStepKind::CreateCsr)
            .unwrap();
        assert!(
            step.output_ref.is_none(),
            "managed renewals must not carry external CSR material"
        );
    }

    #[test]
    fn application_only_serializes_public_version_view() {
        let json = serde_json::to_string(&VersionView {
            id: VersionId::generate(),
            lineage_id: LineageId::generate(),
            identifiers: vec!["example.com".to_string()],
            serial: "01".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2026-02-01T00:00:00Z".to_string(),
            issued_by: "test-ca".to_string(),
            state: "active".to_string(),
            key_provider: "software".to_string(),
            key_id: "key_public".to_string(),
            verification_report: None,
        })
        .unwrap();
        assert!(!json.to_lowercase().contains("private"));
        assert!(!json.contains("BEGIN"));
    }

    #[test]
    fn application_accepts_all_builtin_challenges_by_default() {
        let builder =
            ApplicationServiceBuilder::new().with_offered_challenges(ChallengeSet::new([
                ChallengeType::Http01,
                ChallengeType::Dns01,
                ChallengeType::TlsAlpn01,
            ]));
        assert!(builder.build().is_ok());
    }
}
