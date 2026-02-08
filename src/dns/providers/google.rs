/// Google Cloud DNS Provider implementation.
/// This module provides DNS record management for Google Cloud DNS using the Cloud DNS REST API.
use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;

/// Google Cloud DNS Provider for handling DNS-01 challenges.
#[derive(Debug, Clone)]
pub struct GoogleCloudDnsProvider {
    /// Google Cloud Project ID.
    project_id: String,
    /// Path to the service account JSON file (optional).
    #[allow(dead_code)]
    service_account_json: Option<String>,
    /// Whether to use Application Default Credentials (ADC).
    #[allow(dead_code)]
    use_default_credentials: bool,
    /// Internal HTTP client.
    client: reqwest::Client,
}

impl GoogleCloudDnsProvider {
    /// Creates a new `GoogleCloudDnsProvider` instance for the specified project.
    pub fn new(project_id: String) -> Self {
        tracing::debug!("Initializing GoogleCloudDnsProvider for Project: {}", project_id);
        Self {
            project_id,
            service_account_json: None,
            use_default_credentials: true,
            client: reqwest::Client::new(),
        }
    }

    /// Configures the provider to use a specific service account JSON file.
    pub fn with_service_account(mut self, json_path: String) -> Self {
        self.service_account_json = Some(json_path);
        self.use_default_credentials = false;
        self
    }

    /// Configures the provider to use Application Default Credentials (ADC).
    pub fn with_default_credentials(mut self) -> Self {
        self.use_default_credentials = true;
        self
    }

    /// Obtains a Google Cloud access token.
    /// Currently supports environment variables and the GCP metadata server.
    async fn get_access_token(&self) -> Result<String> {
        tracing::debug!("Attempting to obtain Google Cloud access token");
        // Check environment variable first
        if let Ok(token) = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN") {
            tracing::debug!("Using access token from GOOGLE_OAUTH_ACCESS_TOKEN environment variable");
            return Ok(token);
        }

        // Fallback to metadata server (GCP environment)
        tracing::debug!("Attempting to fetch token from GCP metadata server");
        let metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
        let response = self.client.get(metadata_url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.map_err(|e| {
                    tracing::error!("Failed to parse metadata server response: {}", e);
                    AcmeError::protocol(format!("Failed to parse metadata token: {}", e))
                })?;
                body["access_token"].as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| {
                        tracing::error!("'access_token' missing in metadata server response");
                        AcmeError::protocol("access_token not found in metadata response".to_string())
                    })
            },
            _ => {
                tracing::error!("Google Cloud credentials not found. Set GOOGLE_OAUTH_ACCESS_TOKEN or run on GCP.");
                Err(AcmeError::configuration("Google Cloud credentials not found. Please set GOOGLE_OAUTH_ACCESS_TOKEN or run on GCP.".to_string()))
            }
        }
    }

    /// Finds the managed zone ID for a given domain.
    async fn get_managed_zone(&self, domain: &str) -> Result<String> {
        let token = self.get_access_token().await?;

        // Extract zone name from domain (e.g., _acme-challenge.example.com -> example.com)
        let parts: Vec<&str> = domain.split('.').collect();
        let zone_dns_name = if parts.len() > 2 {
            format!("{}.", parts[parts.len()-2..].join("."))
        } else {
            format!("{}.", domain)
        };

        tracing::debug!("Searching for Google Cloud DNS managed zone for: {}", zone_dns_name);

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
            .map_err(|e| {
                tracing::error!("Network error while listing Google Cloud DNS zones: {}", e);
                AcmeError::transport(format!("Google API list zones failed: {}", e))
            })?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse Google Cloud DNS zones response: {}", e);
                AcmeError::protocol(format!("Failed to parse zones response: {}", e))
            })?;

        if let Some(zones) = body["managedZones"].as_array() {
            for zone in zones {
                if let Some(dns_name) = zone["dnsName"].as_str() {
                    if dns_name == zone_dns_name {
                        let name = zone["name"].as_str().unwrap_or_default().to_string();
                        tracing::debug!("Found managed zone: {} for DNS name: {}", name, dns_name);
                        return Ok(name);
                    }
                }
            }
        }

        tracing::error!("No managed zone found in GCP project {} matching {}", self.project_id, zone_dns_name);
        Err(AcmeError::protocol(format!(
            "Managed zone not found for domain: {}",
            domain
        )))
    }
}

#[async_trait]
impl DnsProvider for GoogleCloudDnsProvider {
    /// Creates a TXT record in Google Cloud DNS.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        tracing::info!("Creating TXT record in Google Cloud DNS for domain: {}", domain);

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
            .map_err(|e| {
                tracing::error!("Network error during Google Cloud DNS record creation: {}", e);
                AcmeError::transport(format!("Google API create record failed: {}", e))
            })?;

        if !response.status().is_success() {
            let err_text = response.text().await.unwrap_or_default();
            tracing::error!("Google Cloud DNS API error: {}", err_text);
            return Err(AcmeError::protocol(format!("GCP DNS error: {}", err_text)));
        }

        tracing::info!("Successfully created Google Cloud DNS TXT record in zone: {}", zone_name);
        // Return zone_name as record_id for deletion
        Ok(zone_name)
    }

    /// Deletes a TXT record from Google Cloud DNS.
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        tracing::info!("Deleting TXT record from Google Cloud DNS for domain: {}", domain);

        let token = self.get_access_token().await?;
        let record_name = format!("{}.", domain);
        let zone_name = record_id; // We stored zone_name as record_id

        // Fetch the current rrsets to find the exact record to delete
        let list_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets?name={}&type=TXT",
            self.project_id, zone_name, record_name
        );

        let list_resp = self.client.get(&list_url).bearer_auth(&token).send().await
            .map_err(|e| {
                tracing::error!("Network error while listing Google Cloud DNS rrsets: {}", e);
                AcmeError::transport(format!("GCP list rrsets failed: {}", e))
            })?;

        let body: serde_json::Value = list_resp.json().await.unwrap_or_default();
        let rrsets = body["rrsets"].as_array().ok_or_else(|| {
            tracing::error!("No TXT rrsets found for deletion in Google Cloud DNS");
            AcmeError::protocol("No rrsets found for deletion".to_string())
        })?;

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
            .map_err(|e| {
                tracing::error!("Network error during Google Cloud DNS record deletion: {}", e);
                AcmeError::transport(format!("Google API delete record failed: {}", e))
            })?;

        if !response.status().is_success() {
            tracing::error!("Google Cloud DNS API deletion failed with status: {}", response.status());
            return Err(AcmeError::protocol("GCP DNS delete failed".to_string()));
        }

        tracing::info!("Successfully deleted Google Cloud DNS TXT record");
        Ok(())
    }

    /// Verifies the existence of a TXT record in Google Cloud DNS.
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        tracing::debug!("Verifying TXT record in Google Cloud DNS for domain: {}", domain);
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
            .map_err(|e| {
                tracing::error!("Network error during Google Cloud DNS record verification: {}", e);
                AcmeError::transport(format!("GCP verify failed: {}", e))
            })?;

        let body: serde_json::Value = response.json().await.unwrap_or_default();
        let quoted_value = format!("\"{}\"", value);

        if let Some(rrsets) = body["rrsets"].as_array() {
            for rrset in rrsets {
                if let Some(rrdatas) = rrset["rrdatas"].as_array() {
                    for data in rrdatas {
                        if data.as_str() == Some(&quoted_value) {
                            tracing::debug!("Google Cloud DNS record verification successful");
                            return Ok(true);
                        }
                    }
                }
            }
        }

        tracing::warn!("Google Cloud DNS record verification failed: value not found");
        Ok(false)
    }
}
