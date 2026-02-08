//! GoDaddy DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for GoDaddy DNS.
//! Supports domain and record management via GoDaddy REST API.

use crate::challenge::DnsProvider;
use crate::error::Result;
use async_trait::async_trait;
use tracing::{debug, info};

/// GoDaddy DNS Provider configuration
#[derive(Debug, Clone)]
pub struct GodaddyDnsProvider {
    api_key: String,
    api_secret: String,
    production: bool,
    client: reqwest::Client,
}

impl GodaddyDnsProvider {
    /// Create a new GoDaddy DNS provider instance
    pub fn new(api_key: String, api_secret: String) -> Self {
        Self {
            api_key,
            api_secret,
            production: false,
            client: reqwest::Client::new(),
        }
    }

    /// Use production GoDaddy API
    pub fn production(mut self) -> Self {
        self.production = true;
        self
    }

    /// Use test GoDaddy API
    pub fn test(mut self) -> Self {
        self.production = false;
        self
    }

    /// Get GoDaddy API base URL
    fn api_base_url(&self) -> &'static str {
        if self.production {
            "https://api.godaddy.com"
        } else {
            "https://api.ote.godaddy.com"
        }
    }

    /// Get domain name from full domain
    fn get_domain_name(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            domain.to_string()
        }
    }

    /// Get record name from full domain
    fn get_record_name(&self, domain: &str) -> String {
        let domain_name = self.get_domain_name(domain);
        domain
            .strip_suffix(&format!(".{}", domain_name))
            .unwrap_or("@")
            .to_string()
    }

    /// Create authorization header
    fn auth_header(&self) -> String {
        format!("sso-key {}:{}", self.api_key, self.api_secret)
    }
}

#[async_trait]
impl DnsProvider for GodaddyDnsProvider {
    /// Create a TXT record in GoDaddy DNS
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in GoDaddy DNS for domain: {}", domain);

        let domain_name = self.get_domain_name(domain);
        let record_name = self.get_record_name(domain);

        let api_url = format!(
            "{}/v1/domains/{}/records/TXT/{}",
            self.api_base_url(),
            domain_name,
            record_name
        );

        let body = serde_json::json!([
            {
                "data": value,
                "ttl": 300
            }
        ]);

        debug!("Creating GoDaddy DNS TXT record: {} = {}", domain, value);

        let response = self
            .client
            .put(&api_url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to create GoDaddy DNS record: {}",
                response.status()
            )));
        }

        info!("GoDaddy DNS TXT record created successfully");
        Ok(record_name)
    }

    /// Delete a TXT record from GoDaddy DNS
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!(
            "Deleting TXT record from GoDaddy DNS for domain: {}",
            domain
        );

        let domain_name = self.get_domain_name(domain);

        let api_url = format!(
            "{}/v1/domains/{}/records/TXT/{}",
            self.api_base_url(),
            domain_name,
            record_id
        );

        debug!("Deleting GoDaddy DNS record: {}", domain);

        let response = self
            .client
            .delete(&api_url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() && response.status().as_u16() != 404 {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to delete GoDaddy DNS record: {}",
                response.status()
            )));
        }

        info!("GoDaddy DNS TXT record deleted successfully");
        Ok(())
    }

    /// Verify that the DNS record is propagated
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        info!("Verifying DNS record for domain: {}", domain);

        let domain_name = self.get_domain_name(domain);
        let record_name = self.get_record_name(domain);

        let api_url = format!(
            "{}/v1/domains/{}/records/TXT/{}",
            self.api_base_url(),
            domain_name,
            record_name
        );

        let response = match self
            .client
            .get(&api_url)
            .header("Authorization", self.auth_header())
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };

        if !response.status().is_success() {
            return Ok(false);
        }

        let body: serde_json::Value = match response.json().await {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };

        if let Some(records_array) = body.as_array() {
            for record in records_array {
                if let Some(data) = record["data"].as_str()
                    && data == value
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_domain_name() {
        let provider = GodaddyDnsProvider::new("key".to_string(), "secret".to_string());

        assert_eq!(provider.get_domain_name("example.com"), "example.com");
        assert_eq!(
            provider.get_domain_name("_acme-challenge.example.com"),
            "example.com"
        );
        assert_eq!(provider.get_domain_name("sub.example.com"), "example.com");
    }

    #[test]
    fn test_get_record_name() {
        let provider = GodaddyDnsProvider::new("key".to_string(), "secret".to_string());

        assert_eq!(provider.get_record_name("example.com"), "@");
        assert_eq!(
            provider.get_record_name("_acme-challenge.example.com"),
            "_acme-challenge"
        );
        assert_eq!(provider.get_record_name("sub.example.com"), "sub");
    }

    #[test]
    fn test_auth_header() {
        let provider = GodaddyDnsProvider::new("mykey".to_string(), "mysecret".to_string());
        assert_eq!(provider.auth_header(), "sso-key mykey:mysecret");
    }

    #[test]
    fn test_api_base_url() {
        let test_provider = GodaddyDnsProvider::new("key".to_string(), "secret".to_string());
        assert_eq!(test_provider.api_base_url(), "https://api.ote.godaddy.com");

        let prod_provider =
            GodaddyDnsProvider::new("key".to_string(), "secret".to_string()).production();
        assert_eq!(prod_provider.api_base_url(), "https://api.godaddy.com");
    }
}
