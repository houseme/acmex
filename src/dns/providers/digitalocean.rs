/// DigitalOcean DNS provider
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};

/// DigitalOcean DNS provider configuration
#[derive(Debug, Clone)]
pub struct DigitalOceanConfig {
    pub api_token: String,
    pub domain: String,
}

/// DigitalOcean DNS provider
pub struct DigitalOceanDnsProvider {
    config: DigitalOceanConfig,
    http_client: reqwest::Client,
}

impl DigitalOceanDnsProvider {
    pub fn new(config: DigitalOceanConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DigitalOceanRecordCreateRequest<'a> {
    r#type: &'a str,
    name: &'a str,
    data: &'a str,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct DigitalOceanRecordResponse {
    domain_record: DigitalOceanRecord,
}

#[derive(Debug, Deserialize)]
struct DigitalOceanRecord {
    id: u64,
}

#[async_trait]
impl DnsProvider for DigitalOceanDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        let url = format!(
            "https://api.digitalocean.com/v2/domains/{}/records",
            self.config.domain
        );

        let payload = DigitalOceanRecordCreateRequest {
            r#type: "TXT",
            name: domain,
            data: value,
            ttl: 60,
        };

        let response = self
            .http_client
            .post(url)
            .bearer_auth(&self.config.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                AcmeError::transport(format!("DigitalOcean create record failed: {}", e))
            })?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AcmeError::storage(format!(
                "DigitalOcean create record failed: {}",
                text
            )));
        }

        let body: DigitalOceanRecordResponse = response.json().await.map_err(|e| {
            AcmeError::storage(format!("DigitalOcean parse response failed: {}", e))
        })?;

        Ok(body.domain_record.id.to_string())
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        let url = format!(
            "https://api.digitalocean.com/v2/domains/{}/records/{}",
            self.config.domain, record_id
        );

        let response = self
            .http_client
            .delete(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| {
                AcmeError::transport(format!("DigitalOcean delete record failed: {}", e))
            })?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AcmeError::storage(format!(
                "DigitalOcean delete record failed: {}",
                text
            )));
        }

        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        let url = format!(
            "https://api.digitalocean.com/v2/domains/{}/records?type=TXT&name={}",
            self.config.domain, domain
        );

        let response = self
            .http_client
            .get(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| {
                AcmeError::transport(format!("DigitalOcean verify record failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let text = response.text().await.unwrap_or_default();
        Ok(text.contains(value))
    }
}
