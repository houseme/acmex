//! CloudNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for CloudNS.

use crate::challenge::DnsProvider;
use crate::error::Result;
use async_trait::async_trait;
use tracing::{debug, info};

/// CloudNS DNS Provider configuration
#[derive(Debug, Clone)]
pub struct ClouDnsProvider {
    auth_id: String,
    auth_password: String,
    client: reqwest::Client,
}

impl ClouDnsProvider {
    /// Create a new CloudNS provider instance
    pub fn new(auth_id: String, auth_password: String) -> Self {
        Self {
            auth_id,
            auth_password,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl DnsProvider for ClouDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in CloudNS for domain: {}", domain);

        // Host is usually the part before domain
        let (domain_name, host) = if let Some(idx) = domain.find('.') {
            (&domain[idx + 1..], &domain[..idx])
        } else {
            (domain, "")
        };

        let url = format!(
            "https://api.cloudns.net/index.php?Action=addRecord&auth-id={}&auth-password={}&domain-name={}&record-type=TXT&host={}&record={}",
            self.auth_id, self.auth_password, domain_name, host, value
        );

        // Placeholder for real REST call
        debug!("CloudNS API request: {}", url);

        Ok("cloudns-record-id".to_string())
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from CloudNS: {}", record_id);

        let (domain_name, _) = if let Some(idx) = domain.find('.') {
            (&domain[idx + 1..], &domain[..idx])
        } else {
            (domain, "")
        };

        let url = format!(
            "https://api.cloudns.net/index.php?Action=deleteRecord&auth-id={}&auth-password={}&domain-name={}&record-id={}",
            self.auth_id, self.auth_password, domain_name, record_id
        );

        let response = self.client.get(&url).send().await.map_err(|e| {
            crate::error::AcmeError::transport(format!("CloudNS API delete failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::protocol(format!(
                "CloudNS delete error: HTTP {}",
                response.status()
            )));
        }

        info!("CloudNS TXT record deleted successfully");
        Ok(())
    }

    async fn verify_record(&self, _domain: &str, _value: &str) -> Result<bool> {
        // CloudNS API implementation placeholder
        Ok(true)
    }
}
