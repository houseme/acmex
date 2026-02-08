//! Linode DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Linode DNS.
//! Supports domain and record management via Linode API v4.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

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

#[derive(Debug, Deserialize)]
struct LinodeListResponse {
    data: Vec<LinodeRecord>,
}

#[derive(Debug, Deserialize)]
struct LinodeRecord {
    _id: u64,
    target: String,
}

#[async_trait]
impl DnsProvider for LinodeDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in Linode DNS: {}", domain);

        let url = format!(
            "https://api.linode.com/v4/domains/{}/records",
            self.config.domain_id
        );

        // Linode expects the subdomain part only if it's a subdomain
        // We'll need to handle this if we want to be more robust, but for now we use the full domain
        let payload = LinodeRecordCreateRequest {
            r#type: "TXT",
            name: domain,
            target: value,
            ttl_sec: 300,
        };

        let response = self
            .http_client
            .post(url)
            .bearer_auth(&self.config.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Linode API failed: {}", e)))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            error!("Linode create record error: {}", text);
            return Err(AcmeError::protocol(format!("Linode error: {}", text)));
        }

        let body: LinodeRecordResponse = response
            .json()
            .await
            .map_err(|e| AcmeError::protocol(format!("Failed to parse Linode response: {}", e)))?;

        info!("Linode TXT record created successfully, ID: {}", body.id);
        Ok(body.id.to_string())
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from Linode DNS: {}", record_id);

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
            .map_err(|e| AcmeError::transport(format!("Linode API delete failed: {}", e)))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            error!("Linode delete record error: {}", text);
            return Err(AcmeError::protocol(format!(
                "Linode delete error: {}",
                text
            )));
        }

        info!("Linode TXT record deleted successfully");
        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        debug!("Verifying Linode DNS record for: {}", domain);

        let url = format!(
            "https://api.linode.com/v4/domains/{}/records",
            self.config.domain_id
        );

        let response = self
            .http_client
            .get(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Linode API verify failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let body: LinodeListResponse = response
            .json()
            .await
            .map_err(|_| AcmeError::protocol("Failed to parse Linode list response".to_string()))?;

        for record in body.data {
            if record.target == value {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
