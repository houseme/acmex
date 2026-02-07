/// Linode DNS provider
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};

/// Linode DNS provider configuration
#[derive(Debug, Clone)]
pub struct LinodeConfig {
    pub api_token: String,
    pub domain_id: u64,
}

/// Linode DNS provider
pub struct LinodeDnsProvider {
    config: LinodeConfig,
    http_client: reqwest::Client,
}

impl LinodeDnsProvider {
    pub fn new(config: LinodeConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct LinodeRecordCreateRequest<'a> {
    r#type: &'a str,
    name: &'a str,
    target: &'a str,
    ttl_sec: u32,
}

#[derive(Debug, Deserialize)]
struct LinodeRecordResponse {
    id: u64,
}

#[async_trait]
impl DnsProvider for LinodeDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        let url = format!(
            "https://api.linode.com/v4/domains/{}/records",
            self.config.domain_id
        );

        let payload = LinodeRecordCreateRequest {
            r#type: "TXT",
            name: domain,
            target: value,
            ttl_sec: 60,
        };

        let response = self
            .http_client
            .post(url)
            .bearer_auth(&self.config.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Linode create record failed: {}", e)))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AcmeError::storage(format!(
                "Linode create record failed: {}",
                text
            )));
        }

        let body: LinodeRecordResponse = response
            .json()
            .await
            .map_err(|e| AcmeError::storage(format!("Linode parse response failed: {}", e)))?;

        Ok(body.id.to_string())
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        let url = format!(
            "https://api.linode.com/v4/domains/{}/records/{}",
            self.config.domain_id, record_id
        );

        let response = self
            .http_client
            .delete(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Linode delete record failed: {}", e)))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AcmeError::storage(format!(
                "Linode delete record failed: {}",
                text
            )));
        }

        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        let url = format!(
            "https://api.linode.com/v4/domains/{}/records?type=TXT&name={}",
            self.config.domain_id, domain
        );

        let response = self
            .http_client
            .get(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Linode verify record failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let text = response.text().await.unwrap_or_default();
        Ok(text.contains(value))
    }
}
