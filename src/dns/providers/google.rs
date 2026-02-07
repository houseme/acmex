//! Google Cloud DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Google Cloud DNS.
//! Supports project management and managed zone operations via Google Cloud API.

use crate::challenge::DnsProvider;
use crate::error::Result;
use async_trait::async_trait;
use tracing::{debug, info};

/// Google Cloud DNS Provider configuration
#[derive(Debug, Clone)]
pub struct GoogleCloudDnsProvider {
    project_id: String,
    service_account_json: Option<String>,
    use_default_credentials: bool,
    client: reqwest::Client,
}

impl GoogleCloudDnsProvider {
    /// Create a new Google Cloud DNS provider instance
    pub fn new(project_id: String) -> Self {
        Self {
            project_id,
            service_account_json: None,
            use_default_credentials: true,
            client: reqwest::Client::new(),
        }
    }

    /// Create with service account JSON file
    pub fn with_service_account(mut self, json_path: String) -> Self {
        self.service_account_json = Some(json_path);
        self.use_default_credentials = false;
        self
    }

    /// Use Application Default Credentials
    pub fn with_default_credentials(mut self) -> Self {
        self.use_default_credentials = true;
        self
    }

    /// Get Google Cloud access token
    async fn get_access_token(&self) -> Result<String> {
        // In production, would use google-cloud-auth library
        // For now, return a placeholder token
        // This would be replaced with actual OAuth2 flow
        Ok("gcp_access_token_placeholder".to_string())
    }

    /// Get managed zone ID for a domain
    async fn get_managed_zone(&self, domain: &str) -> Result<String> {
        let token = self.get_access_token().await?;

        // Extract zone name from domain
        let parts: Vec<&str> = domain.split('.').collect();
        let zone_name = if parts.len() > 2 {
            parts[1..].join(".")
        } else {
            domain.to_string()
        };

        let api_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones",
            self.project_id
        );

        let response = self
            .client
            .get(&api_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        // Find zone matching the domain
        if let Some(zones) = body["managedZones"].as_array() {
            for zone in zones {
                if let Some(dns_name) = zone["dnsName"].as_str() {
                    let dns_name_trimmed = dns_name.trim_end_matches('.');
                    if dns_name_trimmed == zone_name {
                        if let Some(id) = zone["id"].as_str() {
                            return Ok(id.to_string());
                        }
                    }
                }
            }
        }

        Err(crate::error::AcmeError::Protocol(format!(
            "Managed zone not found for domain: {}",
            domain
        )))
    }

    /// Create resource record set
    async fn create_rrset(
        &self,
        zone_id: &str,
        name: &str,
        rrset_type: &str,
        ttl: u32,
        values: Vec<String>,
    ) -> Result<()> {
        let token = self.get_access_token().await?;

        let api_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets",
            self.project_id, zone_id
        );

        let mut rrdatas = Vec::new();
        for value in values {
            rrdatas.push(format!("\"{}\"", value));
        }

        let changes = serde_json::json!({
            "changes": [
                {
                    "action": "CREATE",
                    "rrset": {
                        "name": name,
                        "type": rrset_type,
                        "ttl": ttl,
                        "rrdatas": rrdatas
                    }
                }
            ]
        });

        let response = self
            .client
            .post(&api_url)
            .bearer_auth(&token)
            .json(&changes)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to create Google Cloud DNS record: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Delete resource record set
    async fn delete_rrset(
        &self,
        zone_id: &str,
        name: &str,
        rrset_type: &str,
        ttl: u32,
        values: Vec<String>,
    ) -> Result<()> {
        let token = self.get_access_token().await?;

        let api_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets",
            self.project_id, zone_id
        );

        let mut rrdatas = Vec::new();
        for value in values {
            rrdatas.push(format!("\"{}\"", value));
        }

        let changes = serde_json::json!({
            "changes": [
                {
                    "action": "DELETE",
                    "rrset": {
                        "name": name,
                        "type": rrset_type,
                        "ttl": ttl,
                        "rrdatas": rrdatas
                    }
                }
            ]
        });

        let response = self
            .client
            .post(&api_url)
            .bearer_auth(&token)
            .json(&changes)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to delete Google Cloud DNS record: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

#[async_trait]
impl DnsProvider for GoogleCloudDnsProvider {
    /// Create a TXT record in Google Cloud DNS
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!(
            "Creating TXT record in Google Cloud DNS for domain: {}",
            domain
        );

        let zone_id = self.get_managed_zone(domain).await?;
        let record_name = format!("{}.", domain);

        debug!(
            "Creating Google Cloud DNS TXT record: {} = {}",
            domain, value
        );

        self.create_rrset(&zone_id, &record_name, "TXT", 300, vec![value.to_string()])
            .await?;

        info!("Google Cloud DNS TXT record created successfully");
        Ok(zone_id)
    }

    /// Delete a TXT record from Google Cloud DNS
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!(
            "Deleting TXT record from Google Cloud DNS for domain: {}",
            domain
        );

        let record_name = format!("{}.", domain);

        debug!("Deleting Google Cloud DNS TXT record: {}", domain);

        // For deletion, we need the actual record value
        // This is a limitation - in practice, we'd store the values
        self.delete_rrset(
            record_id,
            &record_name,
            "TXT",
            300,
            vec!["placeholder".to_string()],
        )
        .await?;

        info!("Google Cloud DNS TXT record deleted successfully");
        Ok(())
    }

    /// Query TXT records from Google Cloud DNS
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        info!("Verifying DNS record for domain: {}", domain);

        let token = self.get_access_token().await?;
        let zone_id = match self.get_managed_zone(domain).await {
            Ok(id) => id,
            Err(_) => return Ok(false),
        };

        let api_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets",
            self.project_id, zone_id
        );

        let response = match self.client.get(&api_url).bearer_auth(&token).send().await {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };

        let body: serde_json::Value = match response.json().await {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };

        let record_name = format!("{}.", domain);

        if let Some(rrsets) = body["rrsets"].as_array() {
            for rrset in rrsets {
                if rrset["name"].as_str() == Some(&record_name) {
                    if rrset["type"].as_str() == Some("TXT") {
                        if let Some(rrdatas) = rrset["rrdatas"].as_array() {
                            for rrdata in rrdatas {
                                if let Some(s) = rrdata.as_str() {
                                    if s == value {
                                        return Ok(true);
                                    }
                                }
                            }
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
    fn test_google_cloud_provider_creation() {
        let provider = GoogleCloudDnsProvider::new("my-project".to_string());
        assert_eq!(provider.project_id, "my-project");
        assert!(provider.use_default_credentials);
    }

    #[test]
    fn test_with_service_account() {
        let provider = GoogleCloudDnsProvider::new("my-project".to_string())
            .with_service_account("path/to/sa.json".to_string());
        assert!(provider.service_account_json.is_some());
        assert!(!provider.use_default_credentials);
    }
}
