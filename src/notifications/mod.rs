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
                .header("X-AcmeX-Event-Id", &event.event_id)
                .header("X-AcmeX-Event-Type", &event.event_type)
                .header("X-AcmeX-Signature-Timestamp", timestamp)
                .header("X-AcmeX-Signature", signature);
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
        }
    }

    pub async fn run_once(&self) -> Result<OutboxConsumerReport> {
        let pending = self
            .repositories
            .outbox
            .list_pending(self.config.batch_size)
            .await?;
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

            let result = self.delivery.deliver(&event).await;
            match result {
                Ok(()) => {
                    self.repositories
                        .outbox
                        .mark_processed(event.sequence)
                        .await?;
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

fn signing_timestamp() -> String {
    Zoned::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
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
}
