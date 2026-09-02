#![allow(deprecated)]

/// Automatic certificate renewal logic.
/// This module provides the `SimpleRenewalScheduler` and `RenewalHook` trait
/// to automate the process of checking and renewing certificates before they expire.
use crate::client::{AcmeClient, CertificateBundle};
use crate::error::{AcmeError, Result};
use crate::storage::{CertificateStore, StorageBackend};
use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument;
use x509_parser::prelude::FromDer;

use crate::application::{ActorContext, CertificateApplication, RenewCertificate};
use crate::ca_backend::RenewalWindow;
use crate::domain::{
    CertificateIntent, CertificateLineage, CertificateVersion, DeliveryRequirement, LineageId,
    OperationKind, OperationStatus, TargetId, VersionId, VersionState,
};
use crate::repository::{CasOutcome, LeaseOutcome, RepositorySet};

const ACTIVE_RENEWAL_STATUSES: &[OperationStatus] = &[
    OperationStatus::Queued,
    OperationStatus::Running,
    OperationStatus::Waiting,
    OperationStatus::CancelRequested,
    OperationStatus::Compensating,
];

/// A trait for defining custom hooks that are triggered during the renewal process.
pub trait RenewalHook: Send + Sync {
    /// Called immediately before a renewal attempt starts.
    fn before_renewal(&self, _domains: &[String]) {}

    /// Called after a certificate has been successfully renewed.
    fn after_renewal(&self, _domains: &[String], _bundle: &CertificateBundle) {}

    /// Called if a renewal attempt fails.
    fn on_error(&self, _domains: &[String], _error: &AcmeError) {}
}

/// A simple scheduler that periodically checks certificates and renews them if they are close to expiry.
#[deprecated(
    since = "0.9.0",
    note = "use RenewalController through ControllerRenewalScheduler instead"
)]
pub struct SimpleRenewalScheduler<B: StorageBackend> {
    /// The ACME client used for issuance.
    client: AcmeClient,
    /// The store where certificates are persisted.
    store: CertificateStore<B>,
    /// Optional hooks for custom logic.
    hook: Option<Arc<dyn RenewalHook>>,
    /// How often to check the certificates.
    check_interval: Duration,
    /// The time window before expiry during which a certificate should be renewed.
    renew_before: Duration,
}

impl<B: StorageBackend> SimpleRenewalScheduler<B> {
    /// Creates a new `SimpleRenewalScheduler` with default settings.
    /// Default check interval: 1 hour. Default renew-before window: 30 days.
    pub fn new(client: AcmeClient, store: CertificateStore<B>) -> Self {
        Self {
            client,
            store,
            hook: None,
            check_interval: Duration::from_secs(3600),
            renew_before: Duration::from_secs(30 * 24 * 3600),
        }
    }

    /// Sets a custom `RenewalHook`.
    pub fn with_hook(mut self, hook: Arc<dyn RenewalHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Sets the interval at which certificates are checked for expiry.
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Sets the time window before expiry to trigger renewal.
    pub fn with_renew_before(mut self, renew_before: Duration) -> Self {
        self.renew_before = renew_before;
        self
    }

    /// Starts the renewal scheduler loop. This method runs indefinitely.
    pub async fn run(mut self, domains_list: Vec<Vec<String>>) -> Result<()> {
        tracing::info!(
            "Starting SimpleRenewalScheduler loop with {} domain sets",
            domains_list.len()
        );
        loop {
            for domains in &domains_list {
                tracing::debug!("Checking renewal status for domains: {:?}", domains);
                match self.needs_renewal(domains).await {
                    Ok(true) => {
                        tracing::info!("Renewal required for domains: {:?}", domains);
                        if let Some(hook) = &self.hook {
                            hook.before_renewal(domains);
                        }

                        match self.renew(domains.clone()).await {
                            Ok(bundle) => {
                                tracing::info!(
                                    "Successfully renewed certificate for domains: {:?}",
                                    domains
                                );
                                if let Some(hook) = &self.hook {
                                    hook.after_renewal(domains, &bundle);
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to renew certificate for {:?}: {}",
                                    domains,
                                    e
                                );
                                if let Some(hook) = &self.hook {
                                    hook.on_error(domains, &e);
                                }
                            }
                        }
                    }
                    Ok(false) => {
                        tracing::debug!(
                            "Certificate for {:?} is still valid and not within renewal window",
                            domains
                        );
                    }
                    Err(e) => {
                        tracing::error!("Error checking renewal status for {:?}: {}", domains, e);
                    }
                }
            }

            tracing::debug!("Renewal scheduler sleeping for {:?}", self.check_interval);
            tokio::time::sleep(self.check_interval).await;
        }
    }

    /// Determines if a certificate for the given domains needs renewal.
    pub async fn needs_renewal(&self, domains: &[String]) -> Result<bool> {
        let bundle = self.store.load(domains).await?;
        let Some(bundle) = bundle else {
            tracing::info!(
                "No existing certificate found for {:?}, triggering initial issuance",
                domains
            );
            return Ok(true);
        };

        let expiry = certificate_expiry_timestamp(&bundle)?;
        let now = now_timestamp()?;

        // If expired or expiring soon
        if now >= expiry {
            tracing::warn!(
                "Certificate for {:?} has already expired (Expiry: {})",
                domains,
                expiry
            );
            return Ok(true);
        }

        let renew_before_secs = self.renew_before.as_secs() as i64;
        let threshold_secs = expiry.as_second() - renew_before_secs;
        let threshold = Timestamp::from_second(threshold_secs)
            .map_err(|e| AcmeError::certificate(format!("Invalid threshold timestamp: {}", e)))?;

        let needs_renew = now >= threshold;
        if needs_renew {
            tracing::info!(
                "Certificate for {:?} is within the renewal window (Threshold: {}, Expiry: {})",
                domains,
                threshold,
                expiry
            );
        }

        Ok(needs_renew)
    }

    /// Performs the actual certificate renewal by requesting a new one from the ACME server.
    pub async fn renew(&mut self, domains: Vec<String>) -> Result<CertificateBundle> {
        tracing::info!("Initiating renewal process for domains: {:?}", domains);
        let mut registry = crate::challenge::ChallengeSolverRegistry::new();
        // Default to HTTP-01 for simple scheduler; advanced scheduler can be more flexible
        registry.register(crate::challenge::Http01Solver::default());

        let bundle = self
            .client
            .issue_certificate(domains.clone(), &mut registry)
            .await?;

        tracing::debug!("Saving renewed certificate bundle to storage");
        self.store.save(&bundle).await?;
        Ok(bundle)
    }
}

/// Extracts the expiration timestamp from a `CertificateBundle`.
pub fn certificate_expiry_timestamp(bundle: &CertificateBundle) -> Result<Timestamp> {
    let chain = crate::order::parse_certificate_chain(&bundle.certificate_pem)?;
    let cert_der = chain.first().ok_or_else(|| {
        tracing::error!("Certificate bundle contains an empty chain");
        AcmeError::certificate("Empty certificate chain".to_string())
    })?;

    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(cert_der).map_err(|e| {
        tracing::error!("Failed to parse X.509 certificate DER: {}", e);
        AcmeError::certificate(format!("Failed to parse certificate: {}", e))
    })?;

    let not_after = cert.validity().not_after.timestamp();
    let ts = Timestamp::from_second(not_after)
        .map_err(|e| AcmeError::certificate(format!("Invalid expiry timestamp: {}", e)))?;

    Ok(ts)
}

/// Returns the current system time as a `jiff::Timestamp`.
pub fn now_timestamp() -> Result<Timestamp> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AcmeError::certificate(format!("System time error: {}", e)))?;

    let secs = now.as_secs() as i64;
    Timestamp::from_second(secs)
        .map_err(|e| AcmeError::certificate(format!("Invalid current timestamp: {}", e)))
}

/// Where a renewal window came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalWindowSource {
    /// RFC 9773 ARI suggested window.
    Ari,
    /// Intent-level fixed renew-before compatibility window.
    IntentPolicy,
    /// Fraction of the observed certificate lifetime.
    LifetimeFraction,
}

/// Controller priority for scheduler ordering and alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalPriority {
    /// Before the selected renewal instant.
    Low,
    /// Reached the stable selected instant.
    Normal,
    /// Past the later half of the renewal window.
    High,
    /// Inside the minimum operator safety margin.
    Urgent,
    /// Past the safety deadline or no active healthy version exists.
    Critical,
}

/// Why the controller made its current decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalReason {
    /// Renewal is not due yet.
    NotYetDue,
    /// The stable selected instant has arrived.
    SelectedAtReached,
    /// The safety deadline has passed.
    SafetyDeadlineReached,
    /// The lineage has no active version.
    NoActiveVersion,
}

/// Lineage-level renewal decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalDecision {
    /// Lineage being evaluated.
    pub lineage_id: LineageId,
    /// Active version used for the decision.
    pub active_version_id: VersionId,
    /// Window source.
    pub source: RenewalWindowSource,
    /// First sensible renewal instant.
    pub window_start: Timestamp,
    /// Last sensible renewal instant.
    pub window_end: Timestamp,
    /// Stable jittered instant chosen inside the window.
    pub selected_at: Timestamp,
    /// Latest instant that still preserves the operator safety margin.
    pub safety_deadline: Timestamp,
    /// Priority derived from time, window source and safety margin.
    pub priority: RenewalPriority,
    /// Human/audit reason for the current decision.
    pub reason: RenewalReason,
}

impl RenewalDecision {
    /// Whether a renewal operation should be created now.
    pub fn should_create_operation(&self) -> bool {
        self.priority >= RenewalPriority::Normal
    }
}

/// Output from one scanner pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalScanReport {
    /// Number of lineages examined in this page.
    pub scanned: usize,
    /// Decisions produced by the pass.
    pub decisions: Vec<RenewalDecision>,
    /// Newly-created renewal operations.
    pub operations_created: usize,
    /// Lineages skipped because another owner held the lease.
    pub leases_skipped: usize,
    /// Due lineages intentionally not enqueued in shadow mode.
    pub shadowed: usize,
    /// Cursor for a follow-up page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Result of trying to promote a renewed certificate version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum RenewalActivationOutcome {
    /// The version was already the lineage's active version.
    AlreadyActive {
        /// Lineage that already points at the version.
        lineage_id: LineageId,
        /// Active version.
        version_id: VersionId,
    },
    /// Required deployment gates are not healthy yet; keep the old active version.
    WaitingForDeployments {
        /// Lineage still serving its previous version.
        lineage_id: LineageId,
        /// Version waiting to be activated.
        version_id: VersionId,
        /// Required targets that have not succeeded.
        missing_targets: Vec<TargetId>,
    },
    /// The lineage active pointer switched successfully.
    Activated {
        /// Lineage updated through CAS.
        lineage_id: LineageId,
        /// Newly active version.
        version_id: VersionId,
        /// Previous active version, now superseded when it existed.
        superseded_version_id: Option<VersionId>,
    },
}

/// Renewal controller runtime settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalControllerConfig {
    /// Maximum lineages examined per pass.
    pub page_size: usize,
    /// Lease owner identity for this process.
    pub owner: String,
    /// Lineage lease TTL.
    pub lease_ttl: Duration,
    /// Compute decisions but do not create operations.
    pub shadow_mode: bool,
}

impl Default for RenewalControllerConfig {
    fn default() -> Self {
        Self {
            page_size: 100,
            owner: "renewal-controller".to_string(),
            lease_ttl: Duration::from_secs(10 * 60),
            shadow_mode: false,
        }
    }
}

/// Minimal ARI provider boundary used by the controller.
#[async_trait]
pub trait RenewalInfoProvider: Send + Sync {
    /// Returns the RFC 9773 suggested renewal window, when available.
    async fn renewal_window(&self, chain_pem: &str) -> Result<Option<RenewalWindow>>;
}

/// The CA metric label for an intent: pinned `ca_id`, else the first
/// allowed CA, else `any` — always sanitized to label-safe characters.
fn ca_metric_label(intent: &CertificateIntent) -> String {
    let raw = intent
        .ca_policy
        .ca_id
        .clone()
        .or_else(|| intent.ca_policy.allowed_cas.first().cloned())
        .unwrap_or_else(|| "any".to_string());
    sanitize_metric_label(&raw)
}

fn sanitize_metric_label(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "any".to_string()
    } else {
        cleaned
    }
}

/// Low-cardinality priority label.
fn priority_label(priority: RenewalPriority) -> &'static str {
    match priority {
        RenewalPriority::Low => "low",
        RenewalPriority::Normal => "normal",
        RenewalPriority::High => "high",
        RenewalPriority::Urgent => "urgent",
        RenewalPriority::Critical => "critical",
    }
}

/// Coarse error-class label for an [`AcmeError`] (metrics convention).
fn acme_error_class_label(err: &AcmeError) -> &'static str {
    match err {
        AcmeError::RateLimited(_) => "rate_limited",
        AcmeError::Timeout(_) | AcmeError::Transport(_) => "retryable",
        AcmeError::NotFound(_) => "not_found",
        AcmeError::Conflict(_) => "conflict",
        AcmeError::Configuration(_) => "configuration",
        AcmeError::InvalidInput(_) => "invalid_input",
        _ => "internal",
    }
}

#[async_trait]
impl<T> RenewalInfoProvider for T
where
    T: crate::ca_backend::CaBackend + ?Sized,
{
    async fn renewal_window(&self, chain_pem: &str) -> Result<Option<RenewalWindow>> {
        crate::ca_backend::CaBackend::renewal_window(self, chain_pem).await
    }
}

/// Repository-backed Renewal Controller.
pub struct RenewalController {
    repositories: RepositorySet,
    application: Arc<dyn CertificateApplication>,
    ari: Option<Arc<dyn RenewalInfoProvider>>,
    config: RenewalControllerConfig,
    metrics: Option<crate::metrics::SharedMetrics>,
}

impl RenewalController {
    /// Creates a controller without ARI support.
    pub fn new(
        repositories: RepositorySet,
        application: Arc<dyn CertificateApplication>,
        config: RenewalControllerConfig,
    ) -> Self {
        Self {
            repositories,
            application,
            ari: None,
            config,
            metrics: None,
        }
    }

    /// Attaches an RFC 9773 ARI provider.
    pub fn with_ari_provider(mut self, provider: Arc<dyn RenewalInfoProvider>) -> Self {
        self.ari = Some(provider);
        self
    }

    /// Attaches the shared metrics registry (T11): due renewals, failures
    /// and active-version expiry are recorded with low-cardinality labels.
    pub fn with_metrics(mut self, metrics: crate::metrics::SharedMetrics) -> Self {
        self.repositories = self.repositories.clone().observe_errors(metrics.clone());
        self.metrics = Some(metrics);
        self
    }

    /// Records expiry and due-renewal gauges for one scanned lineage.
    fn record_decision_metrics(
        &self,
        intent: &CertificateIntent,
        version: &CertificateVersion,
        decision: &RenewalDecision,
        due_counts: &mut std::collections::HashMap<(String, &'static str), i64>,
    ) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        let ca = ca_metric_label(intent);
        if let Ok(not_after) = jiff::Timestamp::from_str(&version.not_after) {
            let seconds = self
                .repositories
                .clock
                .now()
                .until(not_after)
                .ok()
                .and_then(|span| span.total(jiff::Unit::Second).ok())
                .map(|total| total as i64);
            if let Some(seconds) = seconds {
                metrics
                    .certificate_seconds_to_expiry
                    .with_label_values(&[&ca, version.state.as_str()])
                    .set(seconds);
            }
        }
        if decision.should_create_operation() {
            *due_counts
                .entry((ca, priority_label(decision.priority)))
                .or_default() += 1;
        }
    }

    /// Evaluates one lineage/version pair.
    pub async fn decision_for(
        &self,
        lineage: &CertificateLineage,
        version: &CertificateVersion,
        intent: &CertificateIntent,
    ) -> Result<RenewalDecision> {
        let ari_window = if intent.renewal_policy.prefer_ari {
            if let Some(provider) = &self.ari {
                match provider
                    .renewal_window(&version.certificate_chain_pem)
                    .await
                {
                    Ok(window) => window,
                    Err(err) => {
                        tracing::warn!(
                            lineage_id = %lineage.id,
                            version_id = %version.id,
                            error = %err,
                            "ARI renewal window lookup failed; falling back to policy window"
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        calculate_decision(
            lineage,
            version,
            intent,
            ari_window,
            self.repositories.clock.now(),
        )
    }

    /// Scans the first page of lineages.
    pub async fn scan_once(&self) -> Result<RenewalScanReport> {
        self.scan_page(None).await
    }

    /// Scans one stable page of lineages and creates renewal operations only
    /// for due decisions.
    pub async fn scan_page(&self, cursor: Option<String>) -> Result<RenewalScanReport> {
        let offset = cursor
            .as_deref()
            .unwrap_or("0")
            .parse::<usize>()
            .map_err(|_| AcmeError::invalid_input("renewal scan cursor must be numeric"))?;
        let mut lineages = self.repositories.lineages.list().await?;
        lineages.sort_by(|a, b| a.value.id.cmp(&b.value.id));
        let total = lineages.len();
        let page_size = self.config.page_size.max(1);
        let page = lineages.into_iter().skip(offset).take(page_size);
        let next_cursor = (offset + page_size < total).then(|| (offset + page_size).to_string());
        let active_renewal_lineages = self.active_renewal_lineages().await?;

        let mut report = RenewalScanReport {
            next_cursor,
            ..RenewalScanReport::default()
        };
        let mut due_counts: std::collections::HashMap<(String, &'static str), i64> =
            std::collections::HashMap::new();
        for stored_lineage in page {
            report.scanned += 1;
            let lineage = stored_lineage.value;
            let Some(active_version_id) = &lineage.active_version_id else {
                continue;
            };
            let Some(version) = self.repositories.versions.get(active_version_id).await? else {
                continue;
            };
            let Some(intent) = self.repositories.intents.get(&lineage.intent_id).await? else {
                continue;
            };

            let ca = ca_metric_label(&intent.value);
            let decision = self
                .decision_for(&lineage, &version.value, &intent.value)
                .instrument(tracing::debug_span!(
                    "renewal.lineage",
                    lineage_id = %lineage.id,
                    ca_id = %ca
                ))
                .await?;
            self.record_decision_metrics(&intent.value, &version.value, &decision, &mut due_counts);
            let should_create = decision.should_create_operation();
            report.decisions.push(decision);
            if !should_create {
                continue;
            }
            if active_renewal_lineages.contains(&lineage.id) {
                continue;
            }
            if self.config.shadow_mode {
                report.shadowed += 1;
                continue;
            }
            match self
                .create_renewal_operation_with_lease(&lineage, active_version_id)
                .await
            {
                Ok(true) => report.operations_created += 1,
                Ok(false) => report.leases_skipped += 1,
                Err(err) => {
                    if let Some(metrics) = &self.metrics {
                        metrics
                            .renewal_failures_total
                            .with_label_values(&[
                                &ca_metric_label(&intent.value),
                                acme_error_class_label(&err),
                            ])
                            .inc();
                    }
                    return Err(err);
                }
            }
        }
        if let Some(metrics) = &self.metrics {
            for ((ca, priority), count) in &due_counts {
                metrics
                    .renewal_due
                    .with_label_values(&[ca.as_str(), priority])
                    .set(*count);
            }
        }
        Ok(report)
    }

    async fn active_renewal_lineages(&self) -> Result<BTreeSet<LineageId>> {
        let mut lineages = BTreeSet::new();
        for status in ACTIVE_RENEWAL_STATUSES {
            lineages.extend(
                self.repositories
                    .operations
                    .list_by_status(*status, usize::MAX)
                    .await?
                    .into_iter()
                    .filter(|stored| stored.value.kind == OperationKind::Renew)
                    .filter_map(|stored| stored.value.subject.lineage_id),
            );
        }
        Ok(lineages)
    }

    async fn create_renewal_operation_with_lease(
        &self,
        lineage: &CertificateLineage,
        active_version_id: &VersionId,
    ) -> Result<bool> {
        let lease_key = format!("renewal/lineage/{}", lineage.id);
        let grant = match self
            .repositories
            .leases
            .acquire(&lease_key, &self.config.owner, self.config.lease_ttl)
            .await?
        {
            LeaseOutcome::Granted(grant) => grant,
            LeaseOutcome::HeldByOther { .. } => return Ok(false),
        };

        let operation_result = async {
            let operation = self
                .application
                .renew(RenewCertificate {
                    context: ActorContext {
                        tenant_id: lineage.tenant_id.clone(),
                        subject: self.config.owner.clone(),
                        actor: self.config.owner.clone(),
                        roles: vec!["scheduler".to_string()],
                        permissions: crate::application::Permission::admin_set(),
                        request_id: None,
                        source: Some("renewal-controller".to_string()),
                    },
                    lineage_id: Some(lineage.id.clone()),
                    identifiers: Vec::new(),
                    force: false,
                    idempotency_key: format!("renewal:{}:{}", lineage.id, active_version_id),
                })
                .await?;
            self.repositories
                .outbox
                .append(
                    "renewal.operation_created",
                    serde_json::json!({
                        "lineage_id": lineage.id.as_str(),
                        "active_version_id": active_version_id.as_str(),
                        "operation_id": operation.id.as_str(),
                        "owner": self.config.owner,
                        "fencing_token": grant.fencing_token,
                    }),
                    None,
                )
                .await?;
            Ok::<_, AcmeError>(())
        }
        .await;
        let release_result = self
            .repositories
            .leases
            .release(&lease_key, &grant.owner, grant.fencing_token)
            .await;

        match (operation_result, release_result) {
            (Ok(()), Ok(())) => Ok(true),
            (Ok(()), Err(err)) => Err(err),
            (Err(err), Ok(())) => Err(err),
            (Err(err), Err(release_err)) => {
                tracing::warn!(
                    lineage_id = %lineage.id,
                    owner = %grant.owner,
                    error = %release_err,
                    "failed to release renewal lease after operation creation failed"
                );
                Err(err)
            }
        }
    }

    /// Promotes a renewed version only after required deployments succeeded.
    pub async fn activate_renewed_version(
        &self,
        version_id: &VersionId,
    ) -> Result<RenewalActivationOutcome> {
        let stored_version = self
            .repositories
            .versions
            .get(version_id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("version `{version_id}` not found")))?;
        let lineage_id = stored_version.value.lineage_id.clone();
        let stored_lineage = self
            .repositories
            .lineages
            .get(&lineage_id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("lineage `{lineage_id}` not found")))?;
        if stored_lineage.value.active_version_id.as_ref() == Some(version_id) {
            return Ok(RenewalActivationOutcome::AlreadyActive {
                lineage_id,
                version_id: version_id.clone(),
            });
        }

        let intent = self
            .repositories
            .intents
            .get(&stored_lineage.value.intent_id)
            .await?
            .ok_or_else(|| {
                AcmeError::storage(format!(
                    "lineage `{lineage_id}` references missing intent `{}`",
                    stored_lineage.value.intent_id
                ))
            })?
            .value;
        let missing_targets = self.missing_activation_targets(version_id, &intent).await?;
        if !missing_targets.is_empty() {
            return Ok(RenewalActivationOutcome::WaitingForDeployments {
                lineage_id,
                version_id: version_id.clone(),
                missing_targets,
            });
        }

        let active_version = self.mark_version_active(version_id).await?;
        let previous_active = stored_lineage.value.active_version_id.clone();
        let lineage = self
            .activate_lineage_version(&stored_lineage.value, &active_version)
            .await?;
        if let Some(previous) = &previous_active {
            self.supersede_previous_version(previous, version_id)
                .await?;
        }
        self.repositories
            .outbox
            .append(
                "renewal.version_activated",
                serde_json::json!({
                    "lineage_id": lineage.id.as_str(),
                    "version_id": version_id.as_str(),
                    "superseded_version_id": previous_active.as_ref().map(|id| id.as_str()),
                }),
                None,
            )
            .await?;

        Ok(RenewalActivationOutcome::Activated {
            lineage_id: lineage.id,
            version_id: version_id.clone(),
            superseded_version_id: previous_active,
        })
    }

    async fn missing_activation_targets(
        &self,
        version_id: &VersionId,
        intent: &CertificateIntent,
    ) -> Result<Vec<TargetId>> {
        if intent.delivery_targets.is_empty() {
            return Ok(Vec::new());
        }
        let deployments = self
            .repositories
            .deployments
            .list_by_version(version_id)
            .await?;
        let successful_targets: std::collections::BTreeSet<TargetId> = deployments
            .into_iter()
            .filter(|stored| stored.value.state.is_success())
            .map(|stored| stored.value.target_id)
            .collect();
        let quorum_successes = intent
            .delivery_targets
            .iter()
            .filter(|target| matches!(target.requirement, DeliveryRequirement::Quorum(_)))
            .filter(|target| successful_targets.contains(&target.id))
            .count();
        let mut missing = Vec::new();
        for target in &intent.delivery_targets {
            match target.requirement {
                DeliveryRequirement::Required => {
                    if !successful_targets.contains(&target.id) {
                        missing.push(target.id.clone());
                    }
                }
                DeliveryRequirement::Quorum(required) => {
                    if quorum_successes < required {
                        missing.push(target.id.clone());
                    }
                }
                DeliveryRequirement::BestEffort => {}
            }
        }
        missing.sort();
        missing.dedup();
        Ok(missing)
    }

    async fn mark_version_active(&self, version_id: &VersionId) -> Result<CertificateVersion> {
        loop {
            let stored = self
                .repositories
                .versions
                .get(version_id)
                .await?
                .ok_or_else(|| AcmeError::not_found(format!("version `{version_id}` not found")))?;
            let next = stored.value.transition(VersionState::Active)?;
            match self
                .repositories
                .versions
                .update(stored.revision, next.clone())
                .await?
            {
                CasOutcome::Updated(_) => return Ok(next),
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }

    async fn activate_lineage_version(
        &self,
        lineage: &CertificateLineage,
        version: &CertificateVersion,
    ) -> Result<CertificateLineage> {
        loop {
            let stored = self
                .repositories
                .lineages
                .get(&lineage.id)
                .await?
                .ok_or_else(|| {
                    AcmeError::not_found(format!("lineage `{}` not found", lineage.id))
                })?;
            let next = stored.value.activate_version(version)?;
            match self
                .repositories
                .lineages
                .update(stored.revision, next.clone())
                .await?
            {
                CasOutcome::Updated(_) => return Ok(next),
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }

    async fn supersede_previous_version(
        &self,
        previous_version_id: &VersionId,
        successor_id: &VersionId,
    ) -> Result<()> {
        loop {
            let Some(stored) = self.repositories.versions.get(previous_version_id).await? else {
                return Ok(());
            };
            if stored.value.state == VersionState::Superseded
                && stored.value.superseded_by.as_ref() == Some(successor_id)
            {
                return Ok(());
            }
            let next = stored.value.superseded_by(successor_id.clone())?;
            match self
                .repositories
                .versions
                .update(stored.revision, next)
                .await?
            {
                CasOutcome::Updated(_) => return Ok(()),
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }
}

/// Compatibility facade so the server scheduler can call the new controller.
pub struct ControllerRenewalScheduler {
    controller: RenewalController,
}

impl ControllerRenewalScheduler {
    /// Wraps a renewal controller as a scheduler.
    pub fn new(controller: RenewalController) -> Self {
        Self { controller }
    }

    /// Returns the wrapped controller.
    pub fn controller(&self) -> &RenewalController {
        &self.controller
    }
}

#[async_trait]
impl crate::scheduler::RenewalScheduler for ControllerRenewalScheduler {
    async fn run_once(&self) -> Result<()> {
        self.controller.scan_once().await.map(|_| ())
    }
}

/// Pure decision calculator used by tests and dry-run tooling.
pub fn calculate_decision(
    lineage: &CertificateLineage,
    version: &CertificateVersion,
    intent: &CertificateIntent,
    ari_window: Option<RenewalWindow>,
    now: Timestamp,
) -> Result<RenewalDecision> {
    let not_before = Timestamp::from_str(&version.not_before)
        .map_err(|e| AcmeError::certificate(format!("invalid not_before: {e}")))?;
    let not_after = Timestamp::from_str(&version.not_after)
        .map_err(|e| AcmeError::certificate(format!("invalid not_after: {e}")))?;
    if not_after <= not_before {
        return Err(AcmeError::certificate(
            "certificate not_after must be after not_before",
        ));
    }

    let fallback = fallback_window(not_before, not_after, &intent.renewal_policy)?;
    let (source, window_start, window_end) = if let Some(window) = ari_window {
        (RenewalWindowSource::Ari, window.start, window.end)
    } else {
        fallback
    };
    let lifetime_secs = not_after.as_second() - not_before.as_second();
    let safety_deadline = timestamp_sub(
        not_after,
        effective_safety_margin(intent.renewal_policy.min_safety_margin, lifetime_secs),
    )?;
    let bounded_end = min_timestamp(window_end, safety_deadline);
    let selected_at = stable_selected_at(
        &lineage.id,
        &version.id,
        window_start,
        max_timestamp(window_start, bounded_end),
    )?;
    let priority = priority_for(
        now,
        not_after,
        window_start,
        bounded_end,
        selected_at,
        safety_deadline,
    );
    let reason = if now >= safety_deadline {
        RenewalReason::SafetyDeadlineReached
    } else if now >= selected_at {
        RenewalReason::SelectedAtReached
    } else {
        RenewalReason::NotYetDue
    };

    Ok(RenewalDecision {
        lineage_id: lineage.id.clone(),
        active_version_id: version.id.clone(),
        source,
        window_start,
        window_end,
        selected_at,
        safety_deadline,
        priority,
        reason,
    })
}

fn fallback_window(
    not_before: Timestamp,
    not_after: Timestamp,
    policy: &crate::domain::RenewalPolicy,
) -> Result<(RenewalWindowSource, Timestamp, Timestamp)> {
    let lifetime_secs = not_after.as_second() - not_before.as_second();
    let fraction = policy.fallback_lifetime_fraction.clamp(0.0, 0.95);
    let fraction_start =
        timestamp_add(not_before, (lifetime_secs as f64 * fraction).round() as i64)?;
    if let Some(fixed) = policy.fixed_renew_before {
        let fixed_start = timestamp_sub(not_after, fixed)?;
        if fixed_start < fraction_start {
            return Ok((RenewalWindowSource::IntentPolicy, fixed_start, not_after));
        }
    }
    Ok((
        RenewalWindowSource::LifetimeFraction,
        fraction_start,
        not_after,
    ))
}

fn effective_safety_margin(configured: Duration, lifetime_secs: i64) -> Duration {
    let lifetime_secs = lifetime_secs.max(1) as u64;
    let max_margin = (lifetime_secs / 4).max(3600);
    Duration::from_secs(configured.as_secs().min(max_margin))
}

fn priority_for(
    now: Timestamp,
    not_after: Timestamp,
    window_start: Timestamp,
    window_end: Timestamp,
    selected_at: Timestamp,
    safety_deadline: Timestamp,
) -> RenewalPriority {
    if now >= safety_deadline || now >= not_after {
        return RenewalPriority::Critical;
    }
    if now < selected_at {
        return RenewalPriority::Low;
    }
    if seconds_between(now, not_after) <= 24 * 60 * 60 {
        return RenewalPriority::Urgent;
    }
    if now >= midpoint(window_start, window_end) {
        return RenewalPriority::High;
    }
    RenewalPriority::Normal
}

fn stable_selected_at(
    lineage_id: &LineageId,
    version_id: &VersionId,
    window_start: Timestamp,
    window_end: Timestamp,
) -> Result<Timestamp> {
    let span = (window_end.as_second() - window_start.as_second()).max(0);
    if span == 0 {
        return Ok(window_start);
    }
    let mut hasher = Sha256::new();
    hasher.update(lineage_id.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(version_id.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let offset = (u64::from_be_bytes(bytes) % (span as u64 + 1)) as i64;
    timestamp_add(window_start, offset)
}

fn midpoint(start: Timestamp, end: Timestamp) -> Timestamp {
    timestamp_add(start, seconds_between(start, end) / 2).unwrap_or(start)
}

fn seconds_between(start: Timestamp, end: Timestamp) -> i64 {
    end.as_second() - start.as_second()
}

fn timestamp_add(timestamp: Timestamp, seconds: i64) -> Result<Timestamp> {
    timestamp
        .checked_add(jiff::Span::new().seconds(seconds))
        .map_err(|_| AcmeError::certificate("timestamp overflow"))
}

fn timestamp_sub(timestamp: Timestamp, duration: Duration) -> Result<Timestamp> {
    timestamp_add(timestamp, -(duration.as_secs() as i64))
}

fn min_timestamp(a: Timestamp, b: Timestamp) -> Timestamp {
    if a <= b { a } else { b }
}

fn max_timestamp(a: Timestamp, b: Timestamp) -> Timestamp {
    if a >= b { a } else { b }
}
