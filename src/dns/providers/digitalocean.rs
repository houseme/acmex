//! DigitalOcean DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for DigitalOcean DNS.
//! Supports domain and record management via DigitalOcean API v2.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, error};

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
struct DigitalOceanListResponse {
    domain_records: Vec<DigitalOceanRecord>,
}

#[derive(Debug, Deserialize)]
struct DigitalOceanRecord {
    id: u64,
    data: String,
    name: String,
}

#[async_trait]
impl DnsProvider for DigitalOceanDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in DigitalOcean DNS: {}", domain);

        let url = format!(
            "https://api.digitalocean.com/v2/domains/{}/records",
            self.config.domain
        );

        // DigitalOcean expects the relative name (e.g., _acme-challenge)
        let record_name = if domain == self.config.domain {
            "@"
        } else {
            domain.strip_suffix(&format!(".{}", self.config.domain)).unwrap_or(domain)
        };

        let payload = DigitalOceanRecordCreateRequest {
            r#type: "TXT",
            name: record_name,
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
                AcmeError::transport(format!("DigitalOcean API failed: {}", e))
            })?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            error!("DigitalOcean create record error: {}", text);
            return Err(AcmeError::protocol(format!("DigitalOcean error: {}", text)));
        }

        let body: DigitalOceanRecordResponse = response.json().await.map_err(|e| {
            AcmeError::protocol(format!("Failed to parse DigitalOcean response: {}", e))
        })?;

        info!("DigitalOcean TXT record created successfully, ID: {}", body.domain_record.id);
        Ok(body.domain_record.id.to_string())
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from DigitalOcean DNS: {}", record_id);

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
                AcmeError::transport(format!("DigitalOcean API delete failed: {}", e))
            })?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            error!("DigitalOcean delete record error: {}", text);
            return Err(AcmeError::protocol(format!("DigitalOcean delete error: {}", text)));
        }

        info!("DigitalOcean TXT record deleted successfully");
        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        debug!("Verifying DigitalOcean DNS record for: {}", domain);

        let url = format!(
            "https://api.digitalocean.com/v2/domains/{}/records?type=TXT",
            self.config.domain
        );

        let response = self
            .http_client
            .get(url)
            .bearer_auth(&self.config.api_token)
            .send()
            .await
            .map_err(|e| {
                AcmeError::transport(format!("DigitalOcean API verify failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let body: DigitalOceanListResponse = response.json().await.map_err(|_| {
            AcmeError::protocol("Failed to parse DigitalOcean list response".to_string())
        })?;

        let record_name = if domain == self.config.domain {
            "@"
        } else {
            domain.strip_suffix(&format!(".{}", self.config.domain)).unwrap_or(domain)
        };

        for record in body.domain_records {
            if record.name == record_name && record.data == value {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
