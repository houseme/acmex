/// Azure DNS Provider implementation.
/// This module provides DNS record management for Azure DNS using the Azure Resource Manager REST API.
use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;

/// Azure DNS Provider for handling DNS-01 challenges.
#[derive(Debug, Clone)]
pub struct AzureDnsProvider {
    /// Azure Subscription ID.
    subscription_id: String,
    /// Azure Resource Group name where the DNS zone resides.
    resource_group: String,
    /// Azure Client ID (Application ID).
    client_id: String,
    /// Azure Client Secret.
    client_secret: String,
    /// Azure Tenant ID.
    tenant_id: String,
    /// Internal HTTP client.
    client: reqwest::Client,
}

impl AzureDnsProvider {
    /// Creates a new `AzureDnsProvider` instance.
    pub fn new(
        subscription_id: String,
        resource_group: String,
        client_id: String,
        client_secret: String,
        tenant_id: String,
    ) -> Self {
        tracing::debug!(
            "Initializing AzureDnsProvider for Subscription: {}",
            subscription_id
        );
        Self {
            subscription_id,
            resource_group,
            client_id,
            client_secret,
            tenant_id,
            client: reqwest::Client::new(),
        }
    }

    /// Obtains an Azure access token using the Client Credentials Flow.
    async fn get_access_token(&self) -> Result<String> {
        tracing::debug!(
            "Requesting Azure access token for Tenant: {}",
            self.tenant_id
        );
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
            .map_err(|e| {
                tracing::error!("Network error during Azure token request: {}", e);
                AcmeError::transport(format!("Azure token request failed: {}", e))
            })?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse Azure token response JSON: {}", e);
            AcmeError::protocol(format!("Failed to parse Azure token response: {}", e))
        })?;

        if !status.is_success() {
            let error = body["error"].as_str().unwrap_or("Unknown");
            let description = body["error_description"].as_str().unwrap_or("");
            tracing::error!("Azure authentication failed: {} - {}", error, description);
            return Err(AcmeError::protocol(format!(
                "Azure auth error: {} - {}",
                error, description
            )));
        }

        body["access_token"]
            .as_str()
            .ok_or_else(|| {
                tracing::error!("'access_token' missing in Azure response");
                AcmeError::protocol("access_token not found in response".to_string())
            })
            .map(|s| s.to_string())
    }

    /// Parses the full domain to extract the DNS zone name.
    fn parse_zone_name(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            domain.to_string()
        }
    }

    /// Returns the record name relative to the DNS zone.
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
    /// Creates a TXT record in Azure DNS.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        tracing::info!("Creating TXT record in Azure DNS for domain: {}", domain);

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
            .map_err(|e| {
                tracing::error!("Network error during Azure DNS record creation: {}", e);
                AcmeError::transport(format!("Azure API failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_body: serde_json::Value = response.json().await.unwrap_or_default();
            let message = error_body["error"]["message"]
                .as_str()
                .unwrap_or("Unknown error");
            tracing::error!("Azure DNS API error: {}", message);
            return Err(AcmeError::protocol(format!(
                "Azure DNS create error: {}",
                message
            )));
        }

        tracing::info!("Successfully created Azure TXT record: {}", record_name);
        Ok(record_name)
    }

    /// Deletes a TXT record from Azure DNS.
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        tracing::info!("Deleting TXT record from Azure DNS for domain: {}", domain);

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
            .map_err(|e| {
                tracing::error!("Network error during Azure DNS record deletion: {}", e);
                AcmeError::transport(format!("Azure API delete failed: {}", e))
            })?;

        if !response.status().is_success() {
            tracing::error!(
                "Azure DNS API deletion failed with status: {}",
                response.status()
            );
            return Err(AcmeError::protocol(format!(
                "Azure DNS delete failed with status: {}",
                response.status()
            )));
        }

        tracing::info!("Successfully deleted Azure TXT record: {}", record_id);
        Ok(())
    }

    /// Verifies the existence of a TXT record in Azure DNS.
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        tracing::debug!("Verifying TXT record in Azure DNS for domain: {}", domain);
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
            .map_err(|e| {
                tracing::error!("Network error during Azure DNS record verification: {}", e);
                AcmeError::transport(format!("Azure API verify failed: {}", e))
            })?;

        if !response.status().is_success() {
            tracing::warn!(
                "Azure DNS record verification returned status: {}",
                response.status()
            );
            return Ok(false);
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse Azure DNS verification response: {}", e);
            AcmeError::protocol("Failed to parse response")
        })?;

        if let Some(txt_records) = body["properties"]["TXTRecords"].as_array() {
            for record in txt_records {
                if let Some(values) = record["value"].as_array() {
                    for v in values {
                        if v.as_str() == Some(value) {
                            tracing::debug!("Azure DNS record verification successful");
                            return Ok(true);
                        }
                    }
                }
            }
        }

        tracing::warn!("Azure DNS record verification failed: value not found");
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_zone_name() {
        let provider = AzureDnsProvider::new(
            "sub".to_string(),
            "rg".to_string(),
            "c".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        assert_eq!(provider.parse_zone_name("example.com"), "example.com");
        assert_eq!(
            provider.parse_zone_name("_acme-challenge.example.com"),
            "example.com"
        );
    }
}
