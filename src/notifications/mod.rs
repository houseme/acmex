//! Webhook and email notification system for AcmeX
//!
//! This module provides event-driven notifications for certificate events:
//! multiple webhook endpoints with retry logic and event filtering, plus
//! SMTP email delivery (`email`). The durable outbox consumer fans every
//! event out to both channels; each channel reports errors independently.

pub mod email;

pub use email::{EmailBodyFormat, EmailNotifier, SmtpErrorClass, SmtpTlsMode};

use crate::config::OutboxSettings;
use crate::dns::spec::{EnvFileSecretResolver, SecretRef, SecretResolver};
use crate::error::{AcmeError, Result};
use crate::repository::{LeaseOutcome, OutboxEvent, RepositorySet};
use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use jiff::Zoned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Webhook event types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Renewal events
    RenewalStarted,
    RenewalSuccess,
    RenewalFailed,
    RenewalSkipped,

    // Account events
    AccountRegistered,
    AccountUpdated,

    // Challenge events
    ChallengeCreated,
    ChallengeValidated,
    ChallengeFailed,

    // Certificate events
    CertificateObtained,
    CertificateDeployed,
    CertificateExpired,

    // Error events
    DeploymentFailed,
}

/// Webhook event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub event_type: EventType,
    pub timestamp: String,
    pub domains: Vec<String>,
    pub subject: String,
    pub message: String,
    pub error: Option<String>,
    pub duration_secs: Option<u64>,
}

impl WebhookEvent {
    /// Create a new webhook event
    pub fn new(
        event_type: EventType,
        domains: Vec<String>,
        subject: String,
        message: String,
    ) -> Self {
        Self {
            event_type,
            timestamp: Zoned::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            domains,
            subject,
            message,
            error: None,
            duration_secs: None,
        }
    }

    /// Add error information
    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    /// Add duration information
    pub fn with_duration(mut self, secs: u64) -> Self {
        self.duration_secs = Some(secs);
        self
    }
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    /// Event types the push path ([`WebhookClient::send`] /
    /// [`WebhookManager::send_event`]) delivers. Endpoints assembled from
    /// `[notifications.webhooks]` keep this **empty** — they deliver through
    /// the durable outbox path (`send_outbox`), filtered by
    /// `event_type_filter` — and must not be routed through the push path;
    /// see [`WebhookClient::should_handle`].
    pub events: Vec<EventType>,
    pub format: WebhookFormat,
    pub auth_token: Option<SecretRef>,
    pub signing_secret: Option<SecretRef>,
    pub timeout_secs: u64,
    pub max_retries: u32,
    /// Outbox event-type filter for the durable delivery path (for example
    /// `"operation.created"`). An empty list delivers every outbox event.
    #[serde(default)]
    pub event_type_filter: Vec<String>,
}

/// Webhook response format
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    Json,
    Slack,
    Discord,
    Custom,
}

/// Webhook client
pub struct WebhookClient {
    config: WebhookConfig,
    client: reqwest::Client,
    secrets: Arc<dyn SecretResolver>,
}

impl WebhookClient {
    /// Create a new webhook client
    pub fn new(config: WebhookConfig) -> Self {
        Self::new_with_resolver(config, Arc::new(EnvFileSecretResolver))
    }

    /// Create a new webhook client with an explicit secret resolver.
    pub fn new_with_resolver(config: WebhookConfig, secrets: Arc<dyn SecretResolver>) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .user_agent(concat!("acmex/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("webhook http client"),
            secrets,
        }
    }

    /// Check if webhook should handle this event.
    ///
    /// # Panics (debug builds)
    ///
    /// Asserts the push-path precondition that `events` is non-empty.
    /// Clients assembled from `[notifications.webhooks]` leave `events`
    /// empty (they filter via `event_type_filter` on the outbox path);
    /// routing one of them through the push path (`send`/`send_event`)
    /// would otherwise silently skip every event.
    pub fn should_handle(&self, event_type: EventType) -> bool {
        debug_assert!(
            !self.config.events.is_empty(),
            "webhook `{}` has no `events` filter: the push path (send/send_event) would silently skip every event — from-config endpoints deliver via the outbox path (send_outbox) only",
            self.config.name
        );
        self.config.events.contains(&event_type)
    }

    /// Format event based on webhook format
    fn format_event(&self, event: &WebhookEvent) -> serde_json::Value {
        match self.config.format {
            WebhookFormat::Json => self.format_json(event),
            WebhookFormat::Slack => self.format_slack(event),
            WebhookFormat::Discord => self.format_discord(event),
            WebhookFormat::Custom => serde_json::to_value(event).unwrap_or(serde_json::json!({})),
        }
    }

    /// Format event as JSON
    fn format_json(&self, event: &WebhookEvent) -> serde_json::Value {
        serde_json::json!({
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "domains": event.domains,
            "subject": event.subject,
            "message": event.message,
            "error": event.error,
            "duration_secs": event.duration_secs,
        })
    }

    /// Format event for Slack
    fn format_slack(&self, event: &WebhookEvent) -> serde_json::Value {
        let color = match event.event_type {
            EventType::RenewalSuccess | EventType::CertificateObtained => "good",
            EventType::RenewalFailed | EventType::ChallengeFailed | EventType::DeploymentFailed => {
                "danger"
            }
            _ => "#0099cc",
        };

        serde_json::json!({
            "attachments": [{
                "color": color,
                "title": event.subject,
                "text": event.message,
                "fields": [
                    {
                        "title": "Event Type",
                        "value": format!("{:?}", event.event_type),
                        "short": true
                    },
                    {
                        "title": "Domains",
                        "value": event.domains.join(", "),
                        "short": false
                    },
                    {
                        "title": "Timestamp",
                        "value": event.timestamp,
                        "short": true
                    }
                ]
            }]
        })
    }

    /// Format event for Discord
    fn format_discord(&self, event: &WebhookEvent) -> serde_json::Value {
        let color = match event.event_type {
            EventType::RenewalSuccess | EventType::CertificateObtained => 0x28a745,
            EventType::RenewalFailed | EventType::ChallengeFailed | EventType::DeploymentFailed => {
                0xdc3545
            }
            _ => 0x0099cc,
        };

        serde_json::json!({
            "embeds": [{
                "title": event.subject,
                "description": event.message,
                "color": color,
                "fields": [
                    {
                        "name": "Event Type",
                        "value": format!("{:?}", event.event_type),
                        "inline": true
                    },
                    {
                        "name": "Domains",
                        "value": event.domains.join(", "),
                        "inline": false
                    },
                    {
                        "name": "Timestamp",
                        "value": event.timestamp,
                        "inline": true
                    }
                ]
            }]
        })
    }

    /// Send webhook with retry logic
    pub async fn send(&self, event: &WebhookEvent) -> Result<()> {
        if !self.should_handle(event.event_type) {
            debug!(
                "Webhook {} skipping event type: {:?}",
                self.config.name, event.event_type
            );
            return Ok(());
        }

        // Only the redacted endpoint (scheme + host + port) may reach logs:
        // the configured URL can embed credentials (`user:pass@host`).
        info!(
            webhook = %self.config.name,
            endpoint = %redact_url(&self.config.url),
            "sending webhook"
        );

        let body = self.format_event(event);
        let timeout = Duration::from_secs(self.config.timeout_secs);

        for attempt in 1..=self.config.max_retries {
            match self.send_once(&body, timeout, None).await {
                Ok(_) => {
                    info!("Webhook {} sent successfully", self.config.name);
                    return Ok(());
                }
                Err(e) => {
                    if attempt == self.config.max_retries {
                        error!(
                            "Webhook {} failed after {} retries: {}",
                            self.config.name, self.config.max_retries, e
                        );
                        return Err(e);
                    }
                    warn!(
                        "Webhook {} attempt {} failed: {}, retrying...",
                        self.config.name, attempt, e
                    );

                    // Exponential backoff: 1s, 2s, 4s, 8s...
                    let backoff = Duration::from_secs(2_u64.pow(attempt - 1));
                    tokio::time::sleep(backoff).await;
                }
            }
        }

        Ok(())
    }

    /// Send webhook once
    async fn send_once(
        &self,
        body: &serde_json::Value,
        timeout: Duration,
        outbox: Option<&OutboxEvent>,
    ) -> Result<()> {
        let body_bytes = serde_json::to_vec(body)?;
        let mut request = self
            .client
            .post(&self.config.url)
            .timeout(timeout)
            .header("content-type", "application/json")
            .body(body_bytes.clone());

        // Add authorization header if provided
        if let Some(ref token_ref) = self.config.auth_token {
            let token = self.secrets.resolve(token_ref).await?;
            let token = token.expose_utf8().ok_or_else(|| {
                AcmeError::configuration(format!(
                    "webhook {} auth token is not valid UTF-8",
                    self.config.name
                ))
            })?;
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        if let (Some(secret_ref), Some(event)) = (&self.config.signing_secret, outbox) {
            let timestamp = signing_timestamp();
            let secret = self.secrets.resolve(secret_ref).await?;
            let signature = webhook_signature(secret.expose(), &timestamp, &body_bytes)?;
            request = request
                .header(WEBHOOK_EVENT_ID_HEADER, &event.event_id)
                .header("X-AcmeX-Event-Type", &event.event_type)
                .header(WEBHOOK_SIGNATURE_TIMESTAMP_HEADER, timestamp)
                .header(WEBHOOK_SIGNATURE_HEADER, signature);
        }

        let response = request.send().await.map_err(|e| {
            // reqwest's error Display embeds the full request URL (which may
            // carry embedded credentials): keep the raw detail at debug level
            // only and hand the classified error a redacted endpoint.
            debug!(
                webhook = %self.config.name,
                endpoint = %redact_url(&self.config.url),
                error = %e,
                "webhook request failed"
            );
            AcmeError::Transport(format!(
                "webhook {} delivery to {} failed",
                self.config.name,
                redact_url(&self.config.url)
            ))
        })?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Transport(format!(
                "Webhook returned status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn send_outbox(&self, event: &OutboxEvent) -> Result<()> {
        if !self.config.event_type_filter.is_empty()
            && !self
                .config
                .event_type_filter
                .iter()
                .any(|allowed| allowed == &event.event_type)
        {
            debug!(
                webhook = %self.config.name,
                event_type = %event.event_type,
                "skipping outbox event not in webhook filter"
            );
            return Ok(());
        }
        let body = serde_json::json!({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "sequence": event.sequence,
            "created_at": event.created_at.to_string(),
            "payload": event.payload,
        });
        self.send_once(
            &body,
            Duration::from_secs(self.config.timeout_secs),
            Some(event),
        )
        .await
    }
}

/// Outbound notification manager: every configured webhook endpoint plus
/// every configured SMTP email target. Implements [`OutboxDelivery`] by
/// fanning each event out to all channels and aggregating their errors —
/// a failing channel never hides another channel's success, and a single
/// failing channel's classified error is returned unmodified.
pub struct WebhookManager {
    webhooks: Vec<WebhookClient>,
    emails: Vec<EmailNotifier>,
}

impl WebhookManager {
    /// Create a new webhook manager without email targets.
    pub fn new(configs: Vec<WebhookConfig>) -> Self {
        let webhooks = configs.into_iter().map(WebhookClient::new).collect();

        Self {
            webhooks,
            emails: Vec::new(),
        }
    }

    /// Builds the manager from `[notifications.webhooks]` and
    /// `[notifications.email]` settings.
    ///
    /// `events` entries filter the durable outbox delivery by event-type
    /// string (`operation.created`, `deployment.activated`, ...); an empty
    /// list delivers everything. Retries are owned by the outbox consumer,
    /// so each configured endpoint performs a single delivery attempt per
    /// consumer pass instead of its own backoff loop.
    pub fn from_config(config: &crate::config::Config) -> Result<Self> {
        let (webhook_settings, email_settings) = config
            .notifications
            .as_ref()
            .map(|notifications| {
                (
                    notifications.webhooks.as_slice(),
                    notifications.email.as_slice(),
                )
            })
            .unwrap_or_default();
        let webhooks = webhook_settings
            .iter()
            .enumerate()
            .map(|(index, entry)| webhook_config_from_settings(entry, index))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(WebhookClient::new)
            .collect();
        let emails = email_settings
            .iter()
            .enumerate()
            .map(|(index, entry)| email_notifier_from_settings(entry, index))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { webhooks, emails })
    }

    /// True when neither webhooks nor email targets are configured; the
    /// consumer then drains the outbox as a cheap no-op.
    pub fn is_empty(&self) -> bool {
        self.webhooks.is_empty() && self.emails.is_empty()
    }

    /// Send event to all matching webhooks
    pub async fn send_event(&self, event: &WebhookEvent) -> Result<()> {
        let mut errors = Vec::new();

        for webhook in &self.webhooks {
            if let Err(e) = webhook.send(event).await {
                errors.push(format!("{}: {}", webhook.config.name, e));
            }
        }

        if !errors.is_empty() {
            warn!("Some webhooks failed: {:?}", errors);
        }

        Ok(())
    }
}

#[async_trait]
impl OutboxDelivery for WebhookManager {
    /// Fans the event out to every webhook and every email target.
    ///
    /// Channels are attempted independently: one channel's failure never
    /// suppresses another channel's delivery attempt. With exactly one
    /// failure the classified error is returned unmodified (so a terminal
    /// SMTP 5xx stays `AcmeError::Protocol`); multiple failures are joined
    /// into one aggregated transport error.
    async fn deliver(&self, event: &OutboxEvent) -> Result<()> {
        let mut errors: Vec<AcmeError> = Vec::new();

        for webhook in &self.webhooks {
            if let Err(err) = webhook.send_outbox(event).await {
                warn!(webhook = %webhook.config.name, error = %err, "webhook delivery failed");
                errors.push(err);
            }
        }
        for notifier in &self.emails {
            if let Err(err) = notifier.deliver(event).await {
                warn!(endpoint = %notifier.name(), error = %err, "email delivery failed");
                errors.push(err);
            }
        }

        // Preserve the most permanent classification when joining: a
        // terminal SMTP 5xx must not be masked as retryable transport, or
        // the consumer would retry until the attempt budget runs out. The
        // individual failures were already logged above, so returning the
        // terminal error verbatim keeps its stable delivery code.
        let retryable = |err: &AcmeError| {
            matches!(
                err,
                AcmeError::Transport(_) | AcmeError::Timeout(_) | AcmeError::RateLimited(_)
            )
        };
        if let Some(idx) = errors.iter().position(|err| !retryable(err)) {
            return Err(errors.swap_remove(idx));
        }
        let mut aggregated = errors.into_iter();
        let Some(first) = aggregated.next() else {
            return Ok(());
        };
        // A single failure is returned verbatim: re-wrapping its Display in
        // another Transport would double the prefix and drop the original
        // classification. Only genuinely multi-channel failures are joined.
        match aggregated.next() {
            None => Err(first),
            Some(second) => {
                let mut rendered = vec![first.to_string(), second.to_string()];
                rendered.extend(aggregated.map(|err| err.to_string()));
                Err(AcmeError::Transport(rendered.join("; ")))
            }
        }
    }
}

/// Converts one `[notifications.email]` entry into an [`EmailNotifier`].
/// Indexes the endpoint into its name when none was configured.
fn email_notifier_from_settings(
    value: &crate::config::EmailConfig,
    index: usize,
) -> Result<EmailNotifier> {
    let mut settings = value.clone();
    if settings.name.is_none() {
        settings.name = Some(format!("email-{index}"));
    }
    EmailNotifier::new(settings)
}

/// Converts one `[notifications.webhooks]` entry into the delivery-side
/// configuration. `index` only names the endpoint when no explicit name was
/// configured.
fn webhook_config_from_settings(
    value: &crate::config::WebhookConfig,
    index: usize,
) -> Result<WebhookConfig> {
    let format = match value.format.as_str() {
        "json" => WebhookFormat::Json,
        "slack" => WebhookFormat::Slack,
        "discord" => WebhookFormat::Discord,
        "custom" => WebhookFormat::Custom,
        other => {
            return Err(AcmeError::configuration(format!(
                "notifications.webhooks[{index}].format `{other}` is not one of json|slack|discord|custom"
            )));
        }
    };
    Ok(WebhookConfig {
        name: value
            .name
            .clone()
            .unwrap_or_else(|| format!("webhook-{index}")),
        url: value.url.clone(),
        events: Vec::new(),
        format,
        auth_token: value.auth_token.clone(),
        signing_secret: value.signing_secret.clone(),
        timeout_secs: value.timeout_secs,
        max_retries: 1,
        event_type_filter: value.events.clone(),
    })
}

/// Delivery boundary used by the durable outbox consumer.
#[async_trait]
pub trait OutboxDelivery: Send + Sync {
    async fn deliver(&self, event: &OutboxEvent) -> Result<()>;
}

/// Durable outbox consumer settings.
#[derive(Debug, Clone)]
pub struct OutboxConsumerConfig {
    pub owner: String,
    pub lease_ttl: Duration,
    pub batch_size: usize,
    pub max_attempts: u32,
    pub retry_backoff_base: Duration,
    pub retry_backoff_max: Duration,
}

impl Default for OutboxConsumerConfig {
    fn default() -> Self {
        Self {
            owner: unique_outbox_owner(),
            lease_ttl: Duration::from_secs(30),
            batch_size: 32,
            max_attempts: 6,
            retry_backoff_base: Duration::from_secs(1),
            retry_backoff_max: Duration::from_secs(300),
        }
    }
}

/// Generates a process-unique outbox lease owner.
///
/// The default must be unique across processes *and* across replicas:
/// container runtimes hand every replica the same PID (a Kubernetes pod's
/// PID namespace typically starts at 1), and lease acquisition re-grants an
/// unexpired lease to a caller presenting the same owner — colliding owners
/// would silently break outbox mutual exclusion and every replica would
/// deliver the same batch. PID plus a random 64-bit hex suffix makes that
/// collision practically impossible. Operators who need a stable owner
/// across restarts set `[outbox].owner` explicitly (and take responsibility
/// for global uniqueness).
fn unique_outbox_owner() -> String {
    format!(
        "outbox-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    )
}

impl From<&OutboxSettings> for OutboxConsumerConfig {
    /// Maps the `[outbox]` configuration section onto the consumer config:
    /// `batch_size`, `owner`, `lease_ttl_secs` and `max_attempts` map onto
    /// the matching fields. When `owner` is unset a process-unique owner is
    /// generated per construction (see [`unique_outbox_owner`]); an
    /// explicitly configured owner must be globally unique across replicas.
    /// The retry backoff keeps its [`OutboxConsumerConfig::default`].
    fn from(settings: &OutboxSettings) -> Self {
        OutboxConsumerConfig {
            batch_size: settings.batch_size,
            owner: settings.owner.clone().unwrap_or_else(unique_outbox_owner),
            lease_ttl: Duration::from_secs(settings.lease_ttl_secs),
            max_attempts: settings.max_attempts,
            ..OutboxConsumerConfig::default()
        }
    }
}

/// Summary of one consumer pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboxConsumerReport {
    pub delivered: usize,
    pub failed: usize,
    pub dead_lettered: usize,
    pub leased_elsewhere: usize,
}

/// At-least-once durable outbox consumer guarded by repository leases.
pub struct OutboxConsumer<D> {
    repositories: RepositorySet,
    delivery: Arc<D>,
    config: OutboxConsumerConfig,
    metrics: Option<crate::metrics::SharedMetrics>,
}

impl<D> OutboxConsumer<D>
where
    D: OutboxDelivery + 'static,
{
    pub fn new(
        repositories: RepositorySet,
        delivery: Arc<D>,
        config: OutboxConsumerConfig,
    ) -> Self {
        Self {
            repositories,
            delivery,
            config,
            metrics: None,
        }
    }

    /// Attaches the shared metrics registry.
    ///
    /// `acmex_outbox_pending` reports, per event type, how many events of
    /// the most recent scan batch were still pending when the pass ended
    /// (delivered and dead-lettered events are excluded). It is a lower
    /// bound of the true backlog — a single `list_pending` batch cannot
    /// observe events beyond the batch size, and events waiting out a retry
    /// backoff only reappear in a later batch — and every label the pass
    /// touches is fully reset with `set`, so the value never accumulates
    /// stale increments across passes.
    pub fn with_metrics(mut self, metrics: crate::metrics::SharedMetrics) -> Self {
        self.repositories = self.repositories.clone().observe_errors(metrics.clone());
        self.metrics = Some(metrics);
        self
    }

    pub async fn run_once(&self) -> Result<OutboxConsumerReport> {
        self.run_once_inner().await
    }

    /// Drives [`OutboxConsumer::run_once`] in a loop until the surrounding
    /// task is aborted.
    ///
    /// The first pass starts immediately (draining the startup backlog), then
    /// one batch is attempted every `interval`. Missed ticks (a pass slower
    /// than, or suspended past, the interval) collapse into a single delay
    /// instead of firing back-to-back catching-up ticks. A failing pass is
    /// logged at warn level and retried on the next tick instead of
    /// terminating the loop — the same classify-and-continue policy the
    /// workflow worker uses. The wait between passes is the tokio timer, so
    /// aborting the spawned task exits promptly; there is no cleanup on the
    /// cancel path.
    pub async fn run_forever(&self, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // The first tick completes immediately, so the startup backlog
            // drains without waiting out the interval.
            ticker.tick().await;
            match self.run_once().await {
                Ok(report) => {
                    if report.delivered + report.failed + report.dead_lettered > 0 {
                        debug!(
                            delivered = report.delivered,
                            failed = report.failed,
                            dead_lettered = report.dead_lettered,
                            leased_elsewhere = report.leased_elsewhere,
                            "outbox consumer pass"
                        );
                    }
                }
                Err(err) => {
                    warn!(error = %err, "outbox consumer pass failed; retrying next interval");
                }
            }
        }
    }

    async fn run_once_inner(&self) -> Result<OutboxConsumerReport> {
        let pending = self
            .repositories
            .outbox
            .list_pending(self.config.batch_size)
            .await?;

        // Gauge bookkeeping (`acmex_outbox_pending`): the map starts out with
        // the batch composition and is decremented when an event reaches a
        // terminal state (delivered, or dead-lettered). It is flushed to the
        // gauge with `set` once per pass, so events that stay pending (retry
        // backoff, lease held elsewhere) or land in the dead letter can never
        // leak stale increments into the metric.
        let mut backlog: HashMap<String, i64> = HashMap::new();
        for event in &pending {
            *backlog.entry(event.event_type.clone()).or_insert(0) += 1;
        }

        let mut report = OutboxConsumerReport::default();
        for event in pending {
            let lease_key = format!("outbox/{}", event.sequence);
            let grant = match self
                .repositories
                .leases
                .acquire(&lease_key, &self.config.owner, self.config.lease_ttl)
                .await?
            {
                LeaseOutcome::Granted(grant) => grant,
                LeaseOutcome::HeldByOther { .. } => {
                    report.leased_elsewhere += 1;
                    continue;
                }
            };

            let settled = self
                .settle_leased_event(&event, &mut report, &mut backlog)
                .await;

            // Best-effort lease release: a failed release only means the
            // lease lapses via its TTL (delivery stays at-least-once), so it
            // must not mask the settlement outcome nor skip the release of
            // later events.
            if let Err(err) = self
                .repositories
                .leases
                .release(&lease_key, &grant.owner, grant.fencing_token)
                .await
            {
                debug!(
                    lease_key = %lease_key,
                    error = %err,
                    "outbox lease release failed; lease will expire via ttl"
                );
            }

            if let Err(err) = settled {
                // Repository bookkeeping failed mid-pass: publish what this
                // batch settled so far, then surface the failure.
                self.flush_backlog_gauge(&backlog);
                return Err(err);
            }
        }

        self.flush_backlog_gauge(&backlog);
        Ok(report)
    }

    /// Delivers one leased event and records its terminal state. Returns
    /// `Err` only for repository bookkeeping failures (`mark_processed`,
    /// `mark_failed`, `dead_letter`) — delivery errors are folded into the
    /// retry / dead-letter paths — so the caller can release the lease
    /// before surfacing them.
    async fn settle_leased_event(
        &self,
        event: &OutboxEvent,
        report: &mut OutboxConsumerReport,
        backlog: &mut HashMap<String, i64>,
    ) -> Result<()> {
        let result = self.delivery.deliver(event).await;
        match result {
            Ok(()) => {
                self.repositories
                    .outbox
                    .mark_processed(event.sequence)
                    .await?;
                // Delivered: no longer pending.
                if let Some(remaining) = backlog.get_mut(&event.event_type) {
                    *remaining -= 1;
                }
                report.delivered += 1;
            }
            Err(err) => {
                let next_attempt = event.attempts + 1;
                let error = stable_delivery_error(&err);
                if next_attempt >= self.config.max_attempts {
                    self.repositories
                        .outbox
                        .mark_failed(event.sequence, &error, None)
                        .await?;
                    self.repositories
                        .outbox
                        .dead_letter(event.sequence, &error)
                        .await?;
                    // Dead-lettered: terminal, no longer pending.
                    if let Some(remaining) = backlog.get_mut(&event.event_type) {
                        *remaining -= 1;
                    }
                    report.dead_lettered += 1;
                } else {
                    // Retry scheduling that overflows the representable
                    // timestamp (clock at `Timestamp::MAX`) falls back to the
                    // farthest instant instead of panicking the pass.
                    let retry_at = self
                        .repositories
                        .clock
                        .now()
                        .checked_add(
                            jiff::Span::new()
                                .milliseconds(self.backoff(next_attempt).as_millis() as i64),
                        )
                        .unwrap_or(jiff::Timestamp::MAX);
                    self.repositories
                        .outbox
                        .mark_failed(event.sequence, &error, Some(retry_at))
                        .await?;
                    report.failed += 1;
                }
            }
        }
        Ok(())
    }

    /// Publishes this pass's per-type remaining counts to the
    /// `acmex_outbox_pending` gauge. Setting each label once per pass (as
    /// opposed to inc/dec per event) keeps the gauge drift-free even when
    /// events dead-letter, are leased elsewhere, or the pass aborts.
    fn flush_backlog_gauge(&self, backlog: &HashMap<String, i64>) {
        if let Some(metrics) = &self.metrics {
            for (event_type, remaining) in backlog {
                metrics
                    .outbox_pending
                    .with_label_values(&[event_type])
                    .set(*remaining);
            }
        }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(16);
        self.config
            .retry_backoff_base
            .saturating_mul(2_u32.saturating_pow(shift))
            .min(self.config.retry_backoff_max)
    }
}

/// Redacts a webhook URL to its `scheme://host[:port]` for logs and error
/// messages. The configured URL may carry embedded basic-auth credentials
/// (`https://user:pass@host/...`) and reqwest's error Display embeds the
/// full URL, so raw URLs must never reach logs. Unparsable input redacts to
/// a fixed placeholder (never panics, never echoes the input).
fn redact_url(url: &str) -> String {
    const OPAQUE: &str = "<unparsable webhook url>";
    let Some((scheme, rest)) = url.split_once("://") else {
        return OPAQUE.to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // `user:pass@host[:port]` — drop everything before the last `@`, which
    // is the userinfo separator (hosts cannot contain `@`).
    match authority.rsplit_once('@') {
        Some((_credentials, host)) if !host.is_empty() => format!("{scheme}://{host}"),
        Some(_) => OPAQUE.to_string(),
        None if authority.is_empty() => OPAQUE.to_string(),
        None => format!("{scheme}://{authority}"),
    }
}

fn stable_delivery_error(err: &AcmeError) -> String {
    match err {
        AcmeError::RateLimited(_) => "RATE_LIMITED".to_string(),
        AcmeError::Timeout(_) => "TIMEOUT".to_string(),
        AcmeError::Transport(_) => "WEBHOOK_TRANSPORT".to_string(),
        AcmeError::Configuration(_) => "WEBHOOK_CONFIGURATION".to_string(),
        // On this path `Protocol` is produced exclusively by the SMTP email
        // delivery for permanent failures (5xx, protocol violations); the
        // outbox records it so dead-letter triage can skip retries.
        AcmeError::Protocol(_) => "SMTP_TERMINAL".to_string(),
        _ => "WEBHOOK_DELIVERY_FAILED".to_string(),
    }
}

/// RFC 3339 UTC timestamp for webhook signing.
///
/// Must be true UTC: the `Z` suffix is a format literal, so formatting
/// `Zoned::now()` directly would stamp local time as UTC on non-UTC hosts
/// and shift every signature outside any sane replay window.
fn signing_timestamp() -> String {
    jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn webhook_signature(secret: &[u8], timestamp: &str, body: &[u8]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|err| AcmeError::crypto(format!("invalid webhook signing key: {err}")))?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

/// Header carrying the stable event id (consumer-side deduplication).
const WEBHOOK_EVENT_ID_HEADER: &str = "X-AcmeX-Event-Id";
/// Header carrying the signature timestamp (RFC 3339, part of the MAC input).
const WEBHOOK_SIGNATURE_TIMESTAMP_HEADER: &str = "X-AcmeX-Signature-Timestamp";
/// Header carrying the `sha256=<hex>` HMAC-SHA256 signature.
const WEBHOOK_SIGNATURE_HEADER: &str = "X-AcmeX-Signature";

/// Why a webhook signature check failed (see [`verify_webhook_signature`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebhookVerificationError {
    /// A required signing header was absent or not valid UTF-8. Carries the
    /// header name.
    #[error("missing or invalid webhook header `{0}`")]
    MissingHeader(&'static str),
    /// The signature timestamp is not a parsable RFC 3339 instant
    /// (`YYYY-MM-DDTHH:MM:SSZ` as sent by [`WebhookClient`]).
    #[error("webhook signature timestamp is not a valid RFC 3339 timestamp")]
    InvalidTimestamp,
    /// The signature timestamp lies outside the allowed replay window
    /// (`max_skew`), so the request is rejected even before HMAC checking.
    #[error("webhook signature timestamp is outside the allowed replay window")]
    StaleTimestamp,
    /// The HMAC did not match: wrong secret, or tampered body/timestamp.
    /// A malformed signature value (bad prefix, bad hex) is reported here
    /// as well.
    #[error("webhook signature mismatch")]
    BadSignature,
}

/// Reads a required header as UTF-8.
fn header_str<'a>(
    headers: &'a reqwest::header::HeaderMap,
    name: &'static str,
) -> std::result::Result<&'a str, WebhookVerificationError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(WebhookVerificationError::MissingHeader(name))
}

/// Verifies a signed AcmeX webhook on the consumer side (T11 replay-window
/// residual).
///
/// The sender ([`WebhookClient`]) adds `X-AcmeX-Event-Id`,
/// `X-AcmeX-Signature-Timestamp` and `X-AcmeX-Signature`, where the
/// signature is HMAC-SHA256 over `{timestamp}.{body}` with the shared
/// secret, hex-encoded with a `sha256=` prefix. This helper:
///
/// 1. requires all three headers ([`WebhookVerificationError::MissingHeader`]);
/// 2. rejects timestamps further than `max_skew` from the current system
///    time, bounding the replay window
///    ([`WebhookVerificationError::StaleTimestamp`]);
/// 3. recomputes the HMAC over the exact same signing input and compares it
///    in constant time via `hmac`'s `verify_slice`
///    ([`WebhookVerificationError::BadSignature`]).
///
/// The header map type is `http::HeaderMap` as re-exported by `reqwest`;
/// `axum` serves the identical type, so HTTP-server consumers can pass their
/// request headers directly.
///
/// Returns the event id on success so consumers can deduplicate the
/// at-least-once delivery.
pub fn verify_webhook_signature<'headers>(
    headers: &'headers reqwest::header::HeaderMap,
    body: &[u8],
    secret: &[u8],
    max_skew: Duration,
) -> std::result::Result<&'headers str, WebhookVerificationError> {
    let event_id = header_str(headers, WEBHOOK_EVENT_ID_HEADER)?;
    let timestamp = header_str(headers, WEBHOOK_SIGNATURE_TIMESTAMP_HEADER)?;
    let signature = header_str(headers, WEBHOOK_SIGNATURE_HEADER)?;

    // Replay window: parse RFC 3339 (the sender's strftime layout is a
    // subset) and bound |now - signed_at|, compared in nanoseconds so no
    // duration conversion can panic.
    let signed_at: jiff::Timestamp = timestamp
        .parse()
        .map_err(|_| WebhookVerificationError::InvalidTimestamp)?;
    let skew_ns = (jiff::Timestamp::now().as_nanosecond() - signed_at.as_nanosecond()).abs();
    let max_skew_ns = max_skew.as_nanos().min(i128::MAX as u128) as i128;
    if skew_ns > max_skew_ns {
        return Err(WebhookVerificationError::StaleTimestamp);
    }

    // Recompute the MAC over the same `{timestamp}.{body}` input the sender
    // signs; `verify_slice` performs the constant-time comparison.
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| WebhookVerificationError::BadSignature)?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = signature
        .strip_prefix("sha256=")
        .and_then(|hex_digest| hex::decode(hex_digest).ok())
        .ok_or(WebhookVerificationError::BadSignature)?;
    mac.verify_slice(&expected)
        .map_err(|_| WebhookVerificationError::BadSignature)?;
    Ok(event_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = WebhookEvent::new(
            EventType::RenewalSuccess,
            vec!["example.com".to_string()],
            "Certificate Renewal".to_string(),
            "Certificate successfully renewed".to_string(),
        );

        assert_eq!(event.event_type, EventType::RenewalSuccess);
        assert_eq!(event.domains, vec!["example.com"]);
        assert_eq!(event.subject, "Certificate Renewal");
    }

    #[test]
    fn test_event_with_error() {
        let event = WebhookEvent::new(
            EventType::RenewalFailed,
            vec!["example.com".to_string()],
            "Certificate Renewal".to_string(),
            "Certificate renewal failed".to_string(),
        )
        .with_error("DNS timeout".to_string());

        assert!(event.error.is_some());
        assert_eq!(event.error.unwrap(), "DNS timeout");
    }

    #[test]
    fn test_webhook_client_filtering() {
        let config = WebhookConfig {
            name: "test".to_string(),
            url: "https://example.com/webhook".to_string(),
            events: vec![EventType::RenewalSuccess],
            format: WebhookFormat::Json,
            auth_token: None,
            signing_secret: None,
            timeout_secs: 30,
            max_retries: 3,
            event_type_filter: Vec::new(),
        };

        let client = WebhookClient::new(config);
        assert!(client.should_handle(EventType::RenewalSuccess));
        assert!(!client.should_handle(EventType::RenewalFailed));
    }

    /// The `should_handle` debug assertion catches from-config clients
    /// (empty `events`) being routed through the push path — the trap that
    /// would silently skip every event. In release builds the assert
    /// compiles out and the check degrades to the old contains() semantics.
    #[test]
    fn should_handle_debug_asserts_on_empty_events() {
        let client = WebhookClient::new(WebhookConfig {
            name: "from-config".to_string(),
            url: "https://example.com/webhook".to_string(),
            events: Vec::new(),
            format: WebhookFormat::Json,
            auth_token: None,
            signing_secret: None,
            timeout_secs: 30,
            max_retries: 1,
            event_type_filter: Vec::new(),
        });
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = client.should_handle(EventType::RenewalSuccess);
        }))
        .is_err();
        assert_eq!(
            panicked,
            cfg!(debug_assertions),
            "empty `events` must trip the push-path debug assert in debug builds"
        );
    }

    /// Logs and classified errors must never carry the raw webhook URL:
    /// embedded basic-auth credentials (`user:pass@host`) are stripped, and
    /// only scheme + host + port survive.
    #[test]
    fn redact_url_strips_credentials_path_and_query() {
        assert_eq!(
            redact_url("https://user:pass@hooks.example.test:8443/path?token=secret"),
            "https://hooks.example.test:8443"
        );
        assert_eq!(
            redact_url("https://hooks.example.test/hook"),
            "https://hooks.example.test"
        );
        assert_eq!(redact_url("http://127.0.0.1:9/hook"), "http://127.0.0.1:9");
        // An `@` in the path must not confuse the userinfo split.
        assert_eq!(
            redact_url("https://hooks.example.test/u@ser"),
            "https://hooks.example.test"
        );
        // Unparsable input degrades to a fixed placeholder — no panic, and
        // the input is never echoed back.
        assert_eq!(redact_url("not a url"), "<unparsable webhook url>");
        assert_eq!(redact_url("https://"), "<unparsable webhook url>");

        let redacted = redact_url("https://alice:s3cret@hooks.example.test/hook");
        assert!(!redacted.contains("alice"), "{redacted}");
        assert!(!redacted.contains("s3cret"), "{redacted}");
    }

    /// `[notifications.webhooks]` maps to delivery endpoints: names default
    /// by index, formats parse strictly, and the configured `events` list
    /// becomes the outbox event-type filter.
    #[test]
    fn webhook_manager_from_config_maps_settings() {
        let config: crate::config::Config = "[[notifications.webhooks]]\nurl = \"https://hooks.example.test/acmex\"\nformat = \"slack\"\n\n[[notifications.webhooks]]\nname = \"ops\"\nurl = \"https://ops.example.test/hook\"\nevents = [\"operation.created\", \"deployment.activated\"]\n"
            .parse()
            .unwrap();

        let manager = WebhookManager::from_config(&config).unwrap();
        assert_eq!(manager.webhooks.len(), 2);
        assert_eq!(manager.webhooks[0].config.name, "webhook-0");
        assert!(matches!(
            manager.webhooks[0].config.format,
            WebhookFormat::Slack
        ));
        assert!(manager.webhooks[0].config.event_type_filter.is_empty());
        assert_eq!(manager.webhooks[1].config.name, "ops");
        assert_eq!(
            manager.webhooks[1].config.event_type_filter,
            vec![
                "operation.created".to_string(),
                "deployment.activated".to_string()
            ]
        );

        let err = WebhookManager::from_config(
            &"[[notifications.webhooks]]\nurl = \"https://hooks.example.test/acmex\"\nformat = \"carrier-pigeon\"\n"
                .parse::<crate::config::Config>()
                .unwrap(),
        )
        .map(|_| ())
        .unwrap_err()
        .to_string();
        assert!(err.contains("format `carrier-pigeon`"), "got: {err}");
    }

    /// `[notifications.email]` maps onto `EmailNotifier`s with the same
    /// event-type filter semantics as webhooks; a broken section fails
    /// assembly, and with no notifications at all the manager is empty.
    #[test]
    fn webhook_manager_from_config_maps_email_settings() {
        let config: crate::config::Config = r#"
[[notifications.email]]
smtp_host = "relay.example.test"
from = "acmex@example.test"
to = ["ops@example.test"]
events = ["operation.created"]

[[notifications.email]]
name = "ops-mail"
smtp_host = "relay2.example.test"
tls_mode = "implicit"
ca_pem_files = ["/etc/ssl/relay.pem"]
from = "AcmeX <acmex@example.test>"
to = ["ops@example.test", "audit@example.test"]
"#
        .parse()
        .unwrap();
        let manager = WebhookManager::from_config(&config).unwrap();
        assert!(!manager.is_empty());
        assert_eq!(manager.emails.len(), 2);
        assert_eq!(manager.emails[0].name(), "email-0");
        assert_eq!(manager.emails[1].name(), "ops-mail");
        assert!(manager.emails[0].should_deliver("operation.created"));
        assert!(!manager.emails[0].should_deliver("audit.event"));
        assert!(manager.emails[1].should_deliver("audit.event"));

        // No notification sections at all: an empty, still-drainable manager.
        let empty = WebhookManager::from_config(
            &"[outbox]\nenabled = false\n"
                .parse::<crate::config::Config>()
                .unwrap(),
        )
        .unwrap();
        assert!(empty.is_empty());

        // A broken email section fails assembly instead of every delivery:
        // username without a password reference is rejected at assembly.
        let broken: crate::config::Config = r#"
[[notifications.email]]
smtp_host = "relay.example.test"
from = "acmex@example.test"
to = ["ops@example.test"]
username = "user"
"#
        .parse()
        .unwrap();
        assert!(WebhookManager::from_config(&broken).is_err());
    }

    /// The outbox delivery path respects the configured event-type filter:
    /// filtered-out events are skipped without a delivery attempt (no
    /// network error), matching events attempt delivery.
    #[tokio::test]
    async fn outbox_delivery_filters_by_event_type() {
        let make_manager = |filter: Vec<&str>| {
            WebhookManager::new(vec![WebhookConfig {
                name: "filtered".to_string(),
                // Unroutable address: a real delivery attempt fails fast.
                url: "http://127.0.0.1:9/hook".to_string(),
                events: Vec::new(),
                format: WebhookFormat::Json,
                auth_token: None,
                signing_secret: None,
                timeout_secs: 1,
                max_retries: 1,
                event_type_filter: filter.into_iter().map(String::from).collect(),
            }])
        };
        let event = OutboxEvent {
            sequence: 1,
            event_id: "evt_filter".to_string(),
            event_type: "audit.event".to_string(),
            payload: serde_json::json!({}),
            created_at: jiff::Timestamp::now(),
            attempts: 0,
            last_error: None,
            next_attempt_at: None,
            processed: false,
            dead_lettered: false,
        };

        // Filtered out: delivered without touching the network.
        make_manager(vec!["operation.created"])
            .deliver(&event)
            .await
            .unwrap();
        // No filter: every event is delivered (and fails on the dead URL).
        assert!(make_manager(Vec::new()).deliver(&event).await.is_err());
        // Matching filter: attempts delivery.
        assert!(
            make_manager(vec!["audit.event"])
                .deliver(&event)
                .await
                .is_err()
        );
    }

    #[test]
    fn test_slack_format() {
        let config = WebhookConfig {
            name: "slack".to_string(),
            url: "https://hooks.slack.com".to_string(),
            events: vec![EventType::RenewalSuccess],
            format: WebhookFormat::Slack,
            auth_token: None,
            signing_secret: None,
            timeout_secs: 30,
            max_retries: 3,
            event_type_filter: Vec::new(),
        };

        let client = WebhookClient::new(config);
        let event = WebhookEvent::new(
            EventType::RenewalSuccess,
            vec!["example.com".to_string()],
            "Test".to_string(),
            "Test message".to_string(),
        );

        let formatted = client.format_event(&event);
        assert!(formatted["attachments"].is_array());
    }

    #[test]
    fn webhook_signatures_are_stable_and_prefixed() {
        let sig = webhook_signature(b"secret", "2026-01-01T00:00:00Z", br#"{"ok":true}"#).unwrap();
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
    }

    /// Builds the same headers a signed delivery would carry, via the same
    /// signing helpers the sender uses.
    fn signed_headers(
        secret: &[u8],
        timestamp: &str,
        body: &[u8],
        event_id: &str,
    ) -> reqwest::header::HeaderMap {
        let signature = webhook_signature(secret, timestamp, body).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(WEBHOOK_EVENT_ID_HEADER, event_id.parse().unwrap());
        headers.insert(
            WEBHOOK_SIGNATURE_TIMESTAMP_HEADER,
            timestamp.parse().unwrap(),
        );
        headers.insert(WEBHOOK_SIGNATURE_HEADER, signature.parse().unwrap());
        headers
    }

    const TEST_SKEW: Duration = Duration::from_secs(300);

    #[test]
    fn verify_webhook_signature_accepts_fresh_signatures() {
        let body = br#"{"event_type":"renewal_success"}"#;
        let headers = signed_headers(b"topsecret", &signing_timestamp(), body, "evt_1");
        let event_id = verify_webhook_signature(&headers, body, b"topsecret", TEST_SKEW).unwrap();
        assert_eq!(event_id, "evt_1");
    }

    #[test]
    fn verify_webhook_signature_rejects_stale_timestamps() {
        let body = br#"{"a":1}"#;
        let stale = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().hours(1))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let headers = signed_headers(b"topsecret", &stale, body, "evt_1");
        assert_eq!(
            verify_webhook_signature(&headers, body, b"topsecret", TEST_SKEW),
            Err(WebhookVerificationError::StaleTimestamp)
        );
    }

    #[test]
    fn verify_webhook_signature_rejects_future_timestamps() {
        // A timestamp from the far future is equally outside the window.
        let body = br#"{"a":1}"#;
        let future = jiff::Timestamp::now()
            .checked_add(jiff::Span::new().hours(1))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let headers = signed_headers(b"topsecret", &future, body, "evt_1");
        assert_eq!(
            verify_webhook_signature(&headers, body, b"topsecret", TEST_SKEW),
            Err(WebhookVerificationError::StaleTimestamp)
        );
    }

    #[test]
    fn verify_webhook_signature_rejects_tampered_body() {
        let signed_body = br#"{"amount":1}"#;
        let tampered_body = br#"{"amount":2}"#;
        let headers = signed_headers(b"topsecret", &signing_timestamp(), signed_body, "evt_1");
        assert_eq!(
            verify_webhook_signature(&headers, tampered_body, b"topsecret", TEST_SKEW),
            Err(WebhookVerificationError::BadSignature)
        );
    }

    #[test]
    fn verify_webhook_signature_rejects_wrong_secret() {
        let body = br#"{"a":1}"#;
        let headers = signed_headers(b"topsecret", &signing_timestamp(), body, "evt_1");
        assert_eq!(
            verify_webhook_signature(&headers, body, b"other-secret", TEST_SKEW),
            Err(WebhookVerificationError::BadSignature)
        );
    }

    #[test]
    fn verify_webhook_signature_requires_all_three_headers() {
        let body = br#"{"a":1}"#;
        let mut headers = signed_headers(b"topsecret", &signing_timestamp(), body, "evt_1");
        headers.remove(WEBHOOK_SIGNATURE_HEADER);
        assert_eq!(
            verify_webhook_signature(&headers, body, b"topsecret", TEST_SKEW),
            Err(WebhookVerificationError::MissingHeader(
                WEBHOOK_SIGNATURE_HEADER
            ))
        );

        let mut headers = signed_headers(b"topsecret", &signing_timestamp(), body, "evt_1");
        headers.remove(WEBHOOK_EVENT_ID_HEADER);
        assert_eq!(
            verify_webhook_signature(&headers, body, b"topsecret", TEST_SKEW),
            Err(WebhookVerificationError::MissingHeader(
                WEBHOOK_EVENT_ID_HEADER
            ))
        );
    }

    #[test]
    fn verify_webhook_signature_rejects_unparsable_timestamp() {
        let body = br#"{"a":1}"#;
        // Signed like the sender would, but with a garbage timestamp value.
        let headers = signed_headers(b"topsecret", "not-a-timestamp", body, "evt_1");
        assert_eq!(
            verify_webhook_signature(&headers, body, b"topsecret", TEST_SKEW),
            Err(WebhookVerificationError::InvalidTimestamp)
        );
    }

    #[test]
    fn verify_webhook_signature_rejects_malformed_signature_value() {
        let body = br#"{"a":1}"#;
        let mut headers = signed_headers(b"topsecret", &signing_timestamp(), body, "evt_1");
        headers.insert(WEBHOOK_SIGNATURE_HEADER, "rawhex".parse().unwrap());
        assert_eq!(
            verify_webhook_signature(&headers, body, b"topsecret", TEST_SKEW),
            Err(WebhookVerificationError::BadSignature)
        );
    }

    // -------------------------------------------------------------------------
    // outbox consumer wiring (`[outbox]` config mapping and `run_forever`)
    // -------------------------------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Delivery stub that counts `deliver` calls and always succeeds.
    struct CountingDelivery {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl OutboxDelivery for CountingDelivery {
        async fn deliver(&self, _event: &OutboxEvent) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn outbox_settings_map_into_consumer_config() {
        let settings = OutboxSettings {
            enabled: true,
            interval_secs: 7,
            batch_size: 12,
            owner: Some("outbox-prod-eu-1".to_string()),
            lease_ttl_secs: 45,
            max_attempts: 3,
        };
        let config = OutboxConsumerConfig::from(&settings);
        assert_eq!(config.batch_size, 12);
        // An explicitly configured owner is passed through verbatim; the
        // operator is responsible for its global uniqueness.
        assert_eq!(config.owner, "outbox-prod-eu-1");
        assert_eq!(config.lease_ttl, Duration::from_secs(45));
        assert_eq!(config.max_attempts, 3);
        // The retry backoff keeps the consumer default (not yet exposed by
        // the section).
        let default = OutboxConsumerConfig::default();
        assert_eq!(config.retry_backoff_base, default.retry_backoff_base);
        assert_eq!(config.retry_backoff_max, default.retry_backoff_max);

        // An unset owner generates a fresh unique owner per construction.
        let unset = OutboxSettings {
            owner: None,
            ..settings.clone()
        };
        let first = OutboxConsumerConfig::from(&unset);
        let second = OutboxConsumerConfig::from(&unset);
        assert_ne!(first.owner, second.owner);
    }

    /// The default lease owner must differ between constructions: container
    /// replicas can observe the same PID, so a PID-only owner would collide,
    /// and lease acquisition re-grants an unexpired lease to a caller
    /// presenting the same owner — colliding owners silently break outbox
    /// mutual exclusion.
    #[test]
    fn default_outbox_owner_is_unique_per_construction() {
        let first = OutboxConsumerConfig::default();
        let second = OutboxConsumerConfig::default();
        assert_ne!(first.owner, second.owner);
        assert!(first.owner.starts_with("outbox-"));
        // The random suffix guarantees the difference even where both
        // processes share a PID.
        assert_ne!(first.owner, format!("outbox-{}", std::process::id()));
    }

    /// A manager without endpoints delivers nothing (no network I/O) and
    /// reports success, so a consumer wired this way drains the outbox as a
    /// cheap no-op instead of failing every event.
    #[tokio::test]
    async fn webhook_manager_without_endpoints_is_a_cheap_noop() {
        let manager = WebhookManager::new(Vec::new());
        assert!(manager.is_empty());
        let event = OutboxEvent {
            sequence: 1,
            event_id: "evt_noop".to_string(),
            event_type: "operation.created".to_string(),
            payload: serde_json::json!({"operation_id": "op_1"}),
            created_at: jiff::Timestamp::now(),
            attempts: 0,
            last_error: None,
            next_attempt_at: None,
            processed: false,
            dead_lettered: false,
        };
        manager.deliver(&event).await.unwrap();
    }

    #[tokio::test]
    async fn run_forever_drains_backlog_and_aborts_cleanly() {
        let set = crate::repository::MemoryRepository::new().into_set();
        set.outbox
            .append(
                "operation.created",
                serde_json::json!({"operation_id": "op_1"}),
                None,
            )
            .await
            .unwrap();
        let delivery = Arc::new(CountingDelivery {
            calls: AtomicUsize::new(0),
        });
        let consumer = OutboxConsumer::new(
            set.clone(),
            delivery.clone(),
            OutboxConsumerConfig::default(),
        );

        let handle =
            tokio::spawn(async move { consumer.run_forever(Duration::from_secs(60)).await });

        // The first tick completes immediately, so the backlog drains without
        // waiting out the interval.
        tokio::time::timeout(Duration::from_secs(10), async {
            while delivery.calls.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("run_forever should deliver the pending event");
        assert!(set.outbox.list_pending(10).await.unwrap().is_empty());

        // Aborting the loop must cancel it promptly instead of hanging.
        handle.abort();
        let err = handle.await.unwrap_err();
        assert!(err.is_cancelled(), "abort must cancel the loop: {err}");
    }

    struct LoopTempDir {
        path: std::path::PathBuf,
    }

    impl Drop for LoopTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Repository failures must not terminate the loop: after several failing
    /// passes the task is still running and still retrying.
    #[tokio::test]
    async fn run_forever_survives_repeated_pass_errors() {
        // The `outbox` aggregate directory is replaced by a regular file, so
        // every pass fails in `list_pending` before any delivery is attempted.
        let path = std::env::temp_dir().join(format!(
            "acmex-outbox-loop-{}-{}",
            std::process::id(),
            jiff::Timestamp::now().as_millisecond()
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        let dir = LoopTempDir { path };
        let set = crate::repository::FileRepository::new(&dir.path)
            .await
            .unwrap()
            .into_set();
        std::fs::remove_dir_all(dir.path.join("outbox")).expect("remove outbox dir");
        std::fs::write(dir.path.join("outbox"), b"blocked").expect("block outbox dir");

        let metrics = Arc::new(crate::metrics::MetricsRegistry::new());
        let consumer = OutboxConsumer::new(
            set,
            Arc::new(CountingDelivery {
                calls: AtomicUsize::new(0),
            }),
            OutboxConsumerConfig::default(),
        )
        .with_metrics(metrics.clone());

        let handle =
            tokio::spawn(async move { consumer.run_forever(Duration::from_millis(10)).await });

        // Every failed scan increments the repository error counter, so the
        // count doubling as a progress signal is deterministic.
        let scan_errors = || {
            metrics
                .gather_text()
                .lines()
                .find(|line| {
                    line.starts_with(r#"acmex_repository_errors_total{backend="file""#)
                        && line.contains(r#"operation="scan""#)
                })
                .and_then(|line| line.rsplit(' ').next())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            while scan_errors() < 3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("passes should keep failing and counting");

        assert!(
            !handle.is_finished(),
            "run_forever must keep running after failing passes"
        );
        handle.abort();
        let _ = handle.await;
    }
}
