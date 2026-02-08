//! Google Cloud DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Google Cloud DNS.
//! Supports project management and managed zone operations via Google Cloud API.

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use tracing::{debug, info, error};

/// Google Cloud DNS Provider configuration
#[derive(Debug, Clone)]
pub struct GoogleCloudDnsProvider {
    project_id: String,
    #[allow(dead_code)]
    service_account_json: Option<String>,
    #[allow(dead_code)]
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
        // Note: In a production environment, we would use the `yup-oauth2` or `google-cloud-auth` crate.
        // For this implementation, we assume the token is provided via environment or a local metadata server
        // if running on GCP. For local development, we'll look for GOOGLE_OAUTH_ACCESS_TOKEN.
        if let Ok(token) = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN") {
            return Ok(token);
        }

        // Fallback to metadata server (GCP environment)
        let metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
        let response = self.client.get(metadata_url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.map_err(|e| AcmeError::protocol(format!("Failed to parse metadata token: {}", e)))?;
                body["access_token"].as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| AcmeError::protocol("access_token not found in metadata response".to_string()))
            },
            _ => Err(AcmeError::configuration("Google Cloud credentials not found. Please set GOOGLE_OAUTH_ACCESS_TOKEN or run on GCP.".to_string()))
        }
    }

    /// Get managed zone ID for a domain
    async fn get_managed_zone(&self, domain: &str) -> Result<String> {
        let token = self.get_access_token().await?;

        // Extract zone name from domain (e.g., _acme-challenge.example.com -> example.com)
        let parts: Vec<&str> = domain.split('.').collect();
        let zone_dns_name = if parts.len() > 2 {
            format!("{}.", parts[parts.len()-2..].join("."))
        } else {
            format!("{}.", domain)
        };

        debug!("Searching for Google Cloud DNS managed zone for: {}", zone_dns_name);

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
            .map_err(|e| AcmeError::transport(format!("Google API list zones failed: {}", e)))?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AcmeError::protocol(format!("Failed to parse zones response: {}", e)))?;

        if let Some(zones) = body["managedZones"].as_array() {
            for zone in zones {
                if let Some(dns_name) = zone["dnsName"].as_str()
                    && dns_name == zone_dns_name {
                        let name = zone["name"].as_str().unwrap_or_default().to_string();
                        debug!("Found managed zone: {} for DNS name: {}", name, dns_name);
                        return Ok(name);
                    }
            }
        }

        error!("No managed zone found in GCP project {} matching {}", self.project_id, zone_dns_name);
        Err(AcmeError::protocol(format!(
            "Managed zone not found for domain: {}",
            domain
        )))
    }
}

#[async_trait]
impl DnsProvider for GoogleCloudDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in Google Cloud DNS: {}", domain);

        let zone_name = self.get_managed_zone(domain).await?;
        let token = self.get_access_token().await?;
        let record_name = format!("{}.", domain);

        let api_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes",
            self.project_id, zone_name
        );

        let payload = serde_json::json!({
            "additions": [
                {
                    "name": record_name,
                    "type": "TXT",
                    "ttl": 300,
                    "rrdatas": [format!("\"{}\"", value)]
                }
            ]
        });

        let response = self
            .client
            .post(&api_url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Google API create record failed: {}", e)))?;

        if !response.status().is_success() {
            let err_text = response.text().await.unwrap_or_default();
            error!("Google Cloud DNS create error: {}", err_text);
            return Err(AcmeError::protocol(format!("GCP DNS error: {}", err_text)));
        }

        info!("Google Cloud DNS TXT record created successfully in zone: {}", zone_name);
        // Return zone_name as record_id for deletion
        Ok(zone_name)
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from Google Cloud DNS: {}", domain);

        let token = self.get_access_token().await?;
        let record_name = format!("{}.", domain);
        let zone_name = record_id; // We stored zone_name as record_id

        // To delete in GCP, we first need to fetch the current rrdatas to match exactly
        let _get_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets/{}",
            self.project_id, zone_name, record_name
        );

        // Note: GCP requires the full rrset for deletion.
        // For simplicity in ACME, we'll list and find the one to delete.
        let list_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets?name={}&type=TXT",
            self.project_id, zone_name, record_name
        );

        let list_resp = self.client.get(&list_url).bearer_auth(&token).send().await
            .map_err(|e| AcmeError::transport(format!("GCP list rrsets failed: {}", e)))?;

        let body: serde_json::Value = list_resp.json().await.unwrap_or_default();
        let rrsets = body["rrsets"].as_array().ok_or_else(|| AcmeError::protocol("No rrsets found for deletion".to_string()))?;

        let api_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes",
            self.project_id, zone_name
        );

        let payload = serde_json::json!({
            "deletions": rrsets
        });

        let response = self
            .client
            .post(&api_url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Google API delete record failed: {}", e)))?;

        if !response.status().is_success() {
            error!("Google Cloud DNS delete error: {}", response.status());
            return Err(AcmeError::protocol("GCP DNS delete failed".to_string()));
        }

        info!("Google Cloud DNS TXT record deleted successfully");
        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        let zone_name = match self.get_managed_zone(domain).await {
            Ok(name) => name,
            Err(_) => return Ok(false),
        };
        let token = self.get_access_token().await?;
        let record_name = format!("{}.", domain);

        let api_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets?name={}&type=TXT",
            self.project_id, zone_name, record_name
        );

        let response = self.client.get(&api_url).bearer_auth(&token).send().await
            .map_err(|e| AcmeError::transport(format!("GCP verify failed: {}", e)))?;

        let body: serde_json::Value = response.json().await.unwrap_or_default();
        let quoted_value = format!("\"{}\"", value);

        if let Some(rrsets) = body["rrsets"].as_array() {
            for rrset in rrsets {
                if let Some(rrdatas) = rrset["rrdatas"].as_array() {
                    for data in rrdatas {
                        if data.as_str() == Some(&quoted_value) {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}
