use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

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
    ) -> Result<OperationRef> {
        if let Some(existing) = self
            .existing_operation(&idempotency_key, &request_hash)
            .await?
        {
            return Ok(existing);
        }
        let now = self.repositories.clock.now();
        let record = OperationRecord::new(
            OperationId::generate(),
            kind,
            subject,
            Some(idempotency_key),
            Some(request_hash),
            now,
        );
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
        let lineage = self.lineage_for_intent(&intent).await?;
        let request_hash = command_hash(&(OperationKind::Issue, &command.intent_id))?;
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
        )
        .await
    }

    async fn renew(&self, command: RenewCertificate) -> Result<OperationRef> {
        let idempotency_key = ensure_idempotency_key(&command.idempotency_key)?;
        let lineage = self.resolve_lineage_for_renew(&command).await?;
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
            idempotency_key: key.to_string(),
        }
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
