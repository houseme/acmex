//! Azure DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Azure DNS.
//! Supports resource group and DNS zone operations via Azure REST API.

use crate::challenge::DnsProvider;
use crate::error::Result;
use async_trait::async_trait;
use tracing::{debug, info};

/// Azure DNS Provider configuration
#[derive(Debug, Clone)]
pub struct AzureDnsProvider {
    subscription_id: String,
    resource_group: String,
    client_id: String,
    client_secret: String,
    tenant_id: String,
    client: reqwest::Client,
}

impl AzureDnsProvider {
    /// Create a new Azure DNS provider instance
    pub fn new(
        subscription_id: String,
        resource_group: String,
        client_id: String,
        client_secret: String,
        tenant_id: String,
    ) -> Self {
        Self {
            subscription_id,
            resource_group,
            client_id,
            client_secret,
            tenant_id,
            client: reqwest::Client::new(),
        }
    }

    /// Get Azure access token
    async fn get_access_token(&self) -> Result<String> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", "https://management.azure.com/.default"),
        ];

        // Build form-encoded body
        let form_body = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let response = self
            .client
            .post(&token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        body["access_token"]
            .as_str()
            .ok_or_else(|| {
                crate::error::AcmeError::Protocol("Failed to get Azure access token".to_string())
            })
            .map(|s| s.to_string())
    }

    /// Parse domain to get zone name
    fn parse_zone_name(&self, domain: &str) -> String {
        // Extract the zone name from the domain
        // For example: _acme-challenge.example.com -> example.com
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            parts[1..].join(".")
        } else {
            domain.to_string()
        }
    }
}

#[async_trait]
impl DnsProvider for AzureDnsProvider {
    /// Create a TXT record in Azure DNS
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in Azure DNS for domain: {}", domain);

        let token = self.get_access_token().await?;
        let zone_name = self.parse_zone_name(domain);

        // Extract record name
        let record_name = if domain == zone_name {
            "@".to_string()
        } else {
            domain
                .strip_suffix(&format!(".{}", zone_name))
                .unwrap_or(domain)
                .to_string()
        };

        let api_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id, self.resource_group, zone_name, record_name
        );

        let body = serde_json::json!({
            "properties": {
                "TTL": 300,
                "TXTRecords": [
                    {
                        "value": [value]
                    }
                ]
            }
        });

        debug!("Creating Azure DNS TXT record: {} = {}", domain, value);

        let response = self
            .client
            .put(&api_url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to create Azure DNS record: {}",
                response.status()
            )));
        }

        info!("Azure DNS TXT record created successfully");
        Ok(record_name)
    }

    /// Delete a TXT record from Azure DNS
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from Azure DNS for domain: {}", domain);

        let token = self.get_access_token().await?;
        let zone_name = self.parse_zone_name(domain);

        let api_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id, self.resource_group, zone_name, record_id
        );

        debug!("Deleting Azure DNS TXT record: {}", domain);

        let response = self
            .client
            .delete(&api_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to delete Azure DNS record: {}",
                response.status()
            )));
        }

        info!("Azure DNS TXT record deleted successfully");
        Ok(())
    }

    /// Verify that the DNS record is propagated
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        info!("Verifying DNS record for domain: {}", domain);

        let token = self.get_access_token().await?;
        let zone_name = self.parse_zone_name(domain);

        let record_name = if domain == zone_name {
            "@".to_string()
        } else {
            domain
                .strip_suffix(&format!(".{}", zone_name))
                .unwrap_or(domain)
                .to_string()
        };

        let api_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id, self.resource_group, zone_name, record_name
        );

        let response = self
            .client
            .get(&api_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        // Check if the record value matches
        if let Some(txt_records) = body["properties"]["TXTRecords"].as_array() {
            for record in txt_records {
                if let Some(values) = record["value"].as_array() {
                    for v in values {
                        if let Some(s) = v.as_str()
                            && s == value {
                                return Ok(true);
                            }
                    }
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
    fn test_parse_zone_name() {
        let provider = AzureDnsProvider::new(
            "sub123".to_string(),
            "rg1".to_string(),
            "client".to_string(),
            "secret".to_string(),
            "tenant".to_string(),
        );

        assert_eq!(provider.parse_zone_name("example.com"), "example.com");
        assert_eq!(
            provider.parse_zone_name("_acme-challenge.example.com"),
            "example.com"
        );
        assert_eq!(provider.parse_zone_name("sub.example.com"), "example.com");
    }
}
