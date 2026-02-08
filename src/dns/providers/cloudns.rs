//! ClouDNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for ClouDNS.

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, info, error};

/// ClouDNS DNS Provider configuration
#[derive(Debug, Clone)]
pub struct ClouDnsProvider {
    auth_id: String,
    auth_password: String,
    client: reqwest::Client,
}

impl ClouDnsProvider {
    /// Create a new ClouDNS provider instance
    pub fn new(auth_id: String, auth_password: String) -> Self {
        Self {
            auth_id,
            auth_password,
            client: reqwest::Client::new(),
        }
    }

    fn get_domain_and_host(&self, domain: &str) -> (String, String) {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            let domain_name = parts[parts.len() - 2..].join(".");
            let host = domain.strip_suffix(&format!(".{}", domain_name)).unwrap_or("").to_string();
            (domain_name, host)
        } else {
            (domain.to_string(), "".to_string())
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClouDnsResponse {
    status: String,
    #[serde(rename = "statusDescription")]
    status_description: Option<String>,
    #[serde(rename = "recordID")]
    record_id: Option<serde_json::Value>, // Can be string or number
}

#[async_trait]
impl DnsProvider for ClouDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in ClouDNS: {}", domain);

        let (domain_name, host) = self.get_domain_and_host(domain);

        let url = "https://api.cloudns.net/index.php";
        let params = [
            ("Action", "addRecord"),
            ("auth-id", &self.auth_id),
            ("auth-password", &self.auth_password),
            ("domain-name", &domain_name),
            ("record-type", "TXT"),
            ("host", &host),
            ("record", value),
            ("ttl", "60"),
        ];

        let response = self.client.get(url).query(&params).send().await
            .map_err(|e| AcmeError::transport(format!("ClouDNS API failed: {}", e)))?;

        let body: ClouDnsResponse = response.json().await.map_err(|e| {
            AcmeError::protocol(format!("Failed to parse ClouDNS response: {}", e))
        })?;

        if body.status != "Success" {
            let desc = body.status_description.unwrap_or_else(|| "Unknown error".to_string());
            error!("ClouDNS create record error: {}", desc);
            return Err(AcmeError::protocol(format!("ClouDNS error: {}", desc)));
        }

        let record_id = body.record_id.ok_or_else(|| AcmeError::protocol("No recordID in ClouDNS response".to_string()))?;
        let id_str = match record_id {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            _ => return Err(AcmeError::protocol("Invalid recordID format".to_string())),
        };

        info!("ClouDNS TXT record created successfully, ID: {}", id_str);
        Ok(id_str)
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from ClouDNS: {}", record_id);

        let (domain_name, _) = self.get_domain_and_host(domain);

        let url = "https://api.cloudns.net/index.php";
        let params = [
            ("Action", "deleteRecord"),
            ("auth-id", &self.auth_id),
            ("auth-password", &self.auth_password),
            ("domain-name", &domain_name),
            ("record-id", record_id),
        ];

        let response = self.client.get(url).query(&params).send().await
            .map_err(|e| AcmeError::transport(format!("ClouDNS API delete failed: {}", e)))?;

        let body: ClouDnsResponse = response.json().await.map_err(|e| {
            AcmeError::protocol(format!("Failed to parse ClouDNS response: {}", e))
        })?;

        if body.status != "Success" {
            let desc = body.status_description.unwrap_or_else(|| "Unknown error".to_string());
            error!("ClouDNS delete record error: {}", desc);
            return Err(AcmeError::protocol(format!("ClouDNS delete error: {}", desc)));
        }

        info!("ClouDNS TXT record deleted successfully");
        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        debug!("Verifying ClouDNS record for: {}", domain);
        let (domain_name, host) = self.get_domain_and_host(domain);

        let url = "https://api.cloudns.net/index.php";
        let params = [
            ("Action", "getRecords"),
            ("auth-id", &self.auth_id),
            ("auth-password", &self.auth_password),
            ("domain-name", &domain_name),
            ("host", &host),
            ("type", "TXT"),
        ];

        let response = self.client.get(url).query(&params).send().await
            .map_err(|e| AcmeError::transport(format!("ClouDNS API list failed: {}", e)))?;

        let records: serde_json::Value = response.json().await.unwrap_or_default();
        if let Some(records_map) = records.as_object() {
            for (_, record) in records_map {
                if record["record"].as_str() == Some(value) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}
