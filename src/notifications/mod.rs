//! Webhook notification system for AcmeX
//!
//! This module provides event-driven webhook notifications for certificate events.
//! Supports multiple webhook endpoints, retry logic, and event filtering.

use crate::error::Result;
use jiff::Zoned;
use serde::{Deserialize, Serialize};
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
    pub auth_token: Option<String>,
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
}

impl WebhookClient {
    /// Create a new webhook client
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
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
            match self.send_once(&body, timeout).await {
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
    async fn send_once(&self, body: &serde_json::Value, timeout: Duration) -> Result<()> {
        let mut request = self
            .client
            .post(&self.config.url)
            .timeout(timeout)
            .json(body);

        // Add authorization header if provided
        if let Some(ref token) = self.config.auth_token {
            request = request.header("Authorization", format!("Bearer {}", token));
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
}
