/// CloudFlare DNS provider implementation.
/// This provider uses the CloudFlare Client API v4 to manage DNS records.
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};

/// Configuration for the CloudFlare DNS provider.
#[derive(Debug, Clone)]
pub struct CloudFlareConfig {
    /// API token with DNS:Edit permissions.
    pub api_token: String,
    /// The Zone ID of the domain being validated.
    pub zone_id: String,
}

/// CloudFlare DNS provider for handling DNS-01 challenges.
pub struct CloudFlareDnsProvider {
    /// Provider configuration.
    config: CloudFlareConfig,
    /// Internal HTTP client.
    http_client: reqwest::Client,
}

impl CloudFlareDnsProvider {
    /// Creates a new `CloudFlareDnsProvider` with the given configuration.
    pub fn new(config: CloudFlareConfig) -> Self {
        tracing::debug!(
            "Initializing CloudFlareDnsProvider for Zone: {}",
            config.zone_id
        );
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }
}

/// Request structure for creating a DNS record in CloudFlare.
#[derive(Debug, Serialize)]
struct CloudFlareRecordCreateRequest<'a> {
    /// Record type (e.g., "TXT").
    r#type: &'a str,
    /// Record name (e.g., "_acme-challenge.example.com").
    name: &'a str,
    /// Record content (the challenge value).
    content: &'a str,
    /// Time to Live (TTL) in seconds.
    ttl: u32,
}

/// Response structure from CloudFlare API.
#[derive(Debug, Deserialize)]
struct CloudFlareRecordResponse {
    /// The result object containing the record details.
    result: CloudFlareRecordResult,
}

/// Details of the created DNS record.
#[derive(Debug, Deserialize)]
struct CloudFlareRecordResult {
    /// The unique ID of the DNS record.
    id: String,
}

#[async_trait]
impl DnsProvider for CloudFlareDnsProvider {
    /// Creates a TXT record for the DNS-01 challenge.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        tracing::info!("Creating CloudFlare TXT record for domain: {}", domain);
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.config.zone_id
        );

        let payload = CloudFlareRecordCreateRequest {
            r#type: "TXT",
            name: domain,
            content: value,
            ttl: 60, // Short TTL for faster validation
        };

        let response = self
            .http_client
            .post(url)
            .bearer_auth(&self.config.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error while creating CloudFlare record: {}", e);
                AcmeError::transport(format!("CloudFlare create record failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            tracing::error!("CloudFlare API error ({}): {}", status, text);
            return Err(AcmeError::storage(format!(
                "CloudFlare create record failed: {}",
                text
            )));
        }

        let body: CloudFlareRecordResponse = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse CloudFlare response: {}", e);
            AcmeError::storage(format!("CloudFlare parse response failed: {}", e))
        })?;

        tracing::info!(
            "Successfully created CloudFlare TXT record with ID: {}",
            body.result.id
        );
        Ok(body.result.id)
    }

    /// Deletes the TXT record after validation is complete.
    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        tracing::info!("Deleting CloudFlare TXT record ID: {}", record_id);
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.config.zone_id, record_id
        );

        let response = self
            .http_client
            .delete(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error while deleting CloudFlare record: {}", e);
                AcmeError::transport(format!("CloudFlare delete record failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            tracing::error!(
                "CloudFlare API error during deletion ({}): {}",
                status,
                text
            );
            return Err(AcmeError::storage(format!(
                "CloudFlare delete record failed: {}",
                text
            )));
        }

        tracing::info!("Successfully deleted CloudFlare TXT record: {}", record_id);
        Ok(())
    }

    /// Verifies that the TXT record is correctly propagated in CloudFlare's systems.
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        tracing::debug!("Verifying CloudFlare TXT record for domain: {}", domain);
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            self.config.zone_id, domain
        );

        let response = self
            .http_client
            .get(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error while verifying CloudFlare record: {}", e);
                AcmeError::transport(format!("CloudFlare verify record failed: {}", e))
            })?;

        if !response.status().is_success() {
            tracing::warn!(
                "CloudFlare record verification returned status: {}",
                response.status()
            );
            return Ok(false);
        }

        let text = response.text().await.unwrap_or_default();
        let verified = text.contains(value);
        if verified {
            tracing::debug!("CloudFlare record verification successful");
        } else {
            tracing::warn!("CloudFlare record verification failed: value not found in response");
        }
        Ok(verified)
    }
}
