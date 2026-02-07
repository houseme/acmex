/// CloudFlare DNS provider
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};

/// CloudFlare DNS provider configuration
#[derive(Debug, Clone)]
pub struct CloudFlareConfig {
    pub api_token: String,
    pub zone_id: String,
}

/// CloudFlare DNS provider
pub struct CloudFlareDnsProvider {
    config: CloudFlareConfig,
    http_client: reqwest::Client,
}

impl CloudFlareDnsProvider {
    pub fn new(config: CloudFlareConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CloudFlareRecordCreateRequest<'a> {
    r#type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CloudFlareRecordResponse {
    result: CloudFlareRecordResult,
}

#[derive(Debug, Deserialize)]
struct CloudFlareRecordResult {
    id: String,
}

#[async_trait]
impl DnsProvider for CloudFlareDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.config.zone_id
        );

        let payload = CloudFlareRecordCreateRequest {
            r#type: "TXT",
            name: domain,
            content: value,
            ttl: 60,
        };

        let response = self
            .http_client
            .post(url)
            .bearer_auth(&self.config.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("CloudFlare create record failed: {}", e)))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AcmeError::storage(format!(
                "CloudFlare create record failed: {}",
                text
            )));
        }

        let body: CloudFlareRecordResponse = response
            .json()
            .await
            .map_err(|e| AcmeError::storage(format!("CloudFlare parse response failed: {}", e)))?;

        Ok(body.result.id)
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
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
            .map_err(|e| AcmeError::transport(format!("CloudFlare delete record failed: {}", e)))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AcmeError::storage(format!(
                "CloudFlare delete record failed: {}",
                text
            )));
        }

        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
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
            .map_err(|e| AcmeError::transport(format!("CloudFlare verify record failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let text = response.text().await.unwrap_or_default();
        Ok(text.contains(value))
    }
}
