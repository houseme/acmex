//! Azure DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Azure DNS.
//! Supports resource group and DNS zone operations via Azure REST API.

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use tracing::info;

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

    /// Get Azure access token using Client Credentials Flow
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

        let response = self
            .client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Azure token request failed: {}", e)))?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            AcmeError::protocol(format!("Failed to parse Azure token response: {}", e))
        })?;

        if !status.is_success() {
            return Err(AcmeError::protocol(format!(
                "Azure auth error: {} - {}",
                body["error"].as_str().unwrap_or("Unknown"),
                body["error_description"].as_str().unwrap_or("")
            )));
        }

        body["access_token"]
            .as_str()
            .ok_or_else(|| AcmeError::protocol("access_token not found in response".to_string()))
            .map(|s| s.to_string())
    }

    /// Parse domain to get zone name (e.g., _acme-challenge.example.com -> example.com)
    fn parse_zone_name(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            domain.to_string()
        }
    }

    /// Get record name relative to the zone
    fn get_record_name(&self, domain: &str, zone_name: &str) -> String {
        if domain == zone_name {
            "@".to_string()
        } else {
            domain
                .strip_suffix(&format!(".{}", zone_name))
                .unwrap_or(domain)
                .to_string()
        }
    }
}

#[async_trait]
impl DnsProvider for AzureDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in Azure DNS: {}", domain);

        let token = self.get_access_token().await?;
        let zone_name = self.parse_zone_name(domain);
        let record_name = self.get_record_name(domain, &zone_name);

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

        let response = self
            .client
            .put(&api_url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Azure API failed: {}", e)))?;

        if !response.status().is_success() {
            let error_body: serde_json::Value = response.json().await.unwrap_or_default();
            return Err(AcmeError::protocol(format!(
                "Azure DNS create error: {}",
                error_body["error"]["message"].as_str().unwrap_or("Unknown error")
            )));
        }

        Ok(record_name)
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from Azure DNS: {}", domain);

        let token = self.get_access_token().await?;
        let zone_name = self.parse_zone_name(domain);

        let api_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id, self.resource_group, zone_name, record_id
        );

        let response = self
            .client
            .delete(&api_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Azure API delete failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AcmeError::protocol(format!(
                "Azure DNS delete failed with status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        let token = self.get_access_token().await?;
        let zone_name = self.parse_zone_name(domain);
        let record_name = self.get_record_name(domain, &zone_name);

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
            .map_err(|e| AcmeError::transport(format!("Azure API verify failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let body: serde_json::Value = response.json().await.map_err(|_| AcmeError::protocol("Failed to parse response"))?;

        if let Some(txt_records) = body["properties"]["TXTRecords"].as_array() {
            for record in txt_records {
                if let Some(values) = record["value"].as_array() {
                    for v in values {
                        if v.as_str() == Some(value) {
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
            "sub".to_string(), "rg".to_string(), "c".to_string(), "s".to_string(), "t".to_string()
        );
        assert_eq!(provider.parse_zone_name("example.com"), "example.com");
        assert_eq!(provider.parse_zone_name("_acme-challenge.example.com"), "example.com");
    }
}
