//! Webhook notification system for AcmeX
//!
//! This module provides event-driven webhook notifications for certificate events.
//! Supports multiple webhook endpoints, retry logic, and event filtering.

use crate::dns::spec::{EnvFileSecretResolver, SecretRef, SecretResolver};
use crate::error::{AcmeError, Result};
use crate::repository::{LeaseOutcome, OutboxEvent, RepositorySet};
use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use jiff::Zoned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
    pub events: Vec<EventType>,
    pub format: WebhookFormat,
    pub auth_token: Option<SecretRef>,
    pub signing_secret: Option<SecretRef>,
    pub timeout_secs: u64,
    pub max_retries: u32,
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
            client: reqwest::Client::new(),
            secrets,
        }
    }

    /// Check if webhook should handle this event
    pub fn should_handle(&self, event_type: EventType) -> bool {
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

        info!("Sending webhook to: {}", self.config.url);

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

        let response = request
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Transport(format!(
                "Webhook returned status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn send_outbox(&self, event: &OutboxEvent) -> Result<()> {
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

/// Webhook manager for multiple webhooks
pub struct WebhookManager {
    webhooks: Vec<WebhookClient>,
}

impl WebhookManager {
    /// Create a new webhook manager
    pub fn new(configs: Vec<WebhookConfig>) -> Self {
        let webhooks = configs.into_iter().map(WebhookClient::new).collect();

        Self { webhooks }
    }

    pub fn is_empty(&self) -> bool {
        self.webhooks.is_empty()
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
    async fn deliver(&self, event: &OutboxEvent) -> Result<()> {
        for webhook in &self.webhooks {
            webhook.send_outbox(event).await?;
        }
        Ok(())
    }
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
            owner: format!("outbox-{}", std::process::id()),
            lease_ttl: Duration::from_secs(30),
            batch_size: 32,
            max_attempts: 6,
            retry_backoff_base: Duration::from_secs(1),
            retry_backoff_max: Duration::from_secs(300),
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

    /// Attaches the shared metrics registry: `acmex_outbox_pending` tracks
    /// the batch backlog per event type (a lower bound of the true backlog,
    /// which a single `list_pending` batch cannot observe).
    pub fn with_metrics(mut self, metrics: crate::metrics::SharedMetrics) -> Self {
        self.repositories = self.repositories.clone().observe_errors(metrics.clone());
        self.metrics = Some(metrics);
        self
    }

    pub async fn run_once(&self) -> Result<OutboxConsumerReport> {
        self.run_once_inner().await
    }

    async fn run_once_inner(&self) -> Result<OutboxConsumerReport> {
        let pending = self
            .repositories
            .outbox
            .list_pending(self.config.batch_size)
            .await?;
        let mut report = OutboxConsumerReport::default();
        for event in pending {
            if let Some(metrics) = &self.metrics {
                metrics
                    .outbox_pending
                    .with_label_values(&[&event.event_type])
                    .inc();
            }
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

            let result = self.delivery.deliver(&event).await;
            match result {
                Ok(()) => {
                    self.repositories
                        .outbox
                        .mark_processed(event.sequence)
                        .await?;
                    if let Some(metrics) = &self.metrics {
                        metrics
                            .outbox_pending
                            .with_label_values(&[&event.event_type])
                            .dec();
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
                        report.dead_lettered += 1;
                    } else {
                        let retry_at = self
                            .repositories
                            .clock
                            .now()
                            .checked_add(
                                jiff::Span::new()
                                    .milliseconds(self.backoff(next_attempt).as_millis() as i64),
                            )
                            .expect("outbox retry backoff overflow");
                        self.repositories
                            .outbox
                            .mark_failed(event.sequence, &error, Some(retry_at))
                            .await?;
                        report.failed += 1;
                    }
                }
            }

            self.repositories
                .leases
                .release(&lease_key, &grant.owner, grant.fencing_token)
                .await?;
        }
        Ok(report)
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(16);
        self.config
            .retry_backoff_base
            .saturating_mul(2_u32.saturating_pow(shift))
            .min(self.config.retry_backoff_max)
    }
}

fn stable_delivery_error(err: &AcmeError) -> String {
    match err {
        AcmeError::RateLimited(_) => "RATE_LIMITED".to_string(),
        AcmeError::Timeout(_) => "TIMEOUT".to_string(),
        AcmeError::Transport(_) => "WEBHOOK_TRANSPORT".to_string(),
        AcmeError::Configuration(_) => "WEBHOOK_CONFIGURATION".to_string(),
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
        };

        let client = WebhookClient::new(config);
        assert!(client.should_handle(EventType::RenewalSuccess));
        assert!(!client.should_handle(EventType::RenewalFailed));
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
}
