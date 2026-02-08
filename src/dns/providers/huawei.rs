/// Huawei Cloud DNS Provider implementation.
/// This module provides DNS record management for Huawei Cloud DNS using the SDKV2 / SIGV4 signing process.
use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use jiff::Zoned;
use sha2::{Digest, Sha256};

/// Huawei Cloud DNS Provider for handling DNS-01 challenges.
#[derive(Debug, Clone)]
pub struct HuaweiCloudDnsProvider {
    /// Huawei Cloud Access Key (AK).
    access_key: String,
    /// Huawei Cloud Secret Key (SK).
    secret_key: String,
    /// Huawei Cloud Project ID.
    #[allow(dead_code)]
    project_id: String,
    /// Huawei Cloud Region (e.g., "cn-north-4").
    region: String,
    /// Internal HTTP client.
    client: reqwest::Client,
}

impl HuaweiCloudDnsProvider {
    /// Creates a new `HuaweiCloudDnsProvider` instance.
    pub fn new(access_key: String, secret_key: String, project_id: String, region: String) -> Self {
        tracing::debug!("Initializing HuaweiCloudDnsProvider for region: {}", region);
        Self {
            access_key,
            secret_key,
            project_id,
            region,
            client: reqwest::Client::new(),
        }
    }

    /// Signs the request for Huawei Cloud API using the SDKV2 / SIGV4 algorithm.
    fn sign_request(&self, method: &str, url: &str, payload: &str) -> (String, String) {
        let now = Zoned::now();
        let timestamp = now.strftime("%Y%m%dT%H%M%SZ").to_string();

        // 1. Construct Canonical Request
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let hashed_payload = hex::encode(hasher.finalize());

        let canonical_request = format!(
            "{}\n{}\n\nhost:dns.{}.myhuaweicloud.com\nx-sdk-date:{}\n\nhost;x-sdk-date\n{}",
            method, url, self.region, timestamp, hashed_payload
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        let hashed_canonical = hex::encode(hasher.finalize());

        // 2. Construct String to Sign
        let string_to_sign = format!("SDK-HMAC-SHA256\n{}\n{}", timestamp, hashed_canonical);

        // 3. Calculate Signature
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(string_to_sign.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        (timestamp, signature)
    }

    /// Finds the zone ID for a given domain in Huawei Cloud DNS.
    async fn find_zone_id(&self, domain: &str) -> Result<String> {
        // Extract the base domain (e.g., _acme-challenge.example.com -> example.com)
        let parts: Vec<&str> = domain.split('.').collect();
        let zone_name = if parts.len() > 2 {
            format!("{}.", parts[parts.len() - 2..].join("."))
        } else {
            format!("{}.", domain)
        };

        tracing::debug!("Searching for Huawei Cloud DNS zone: {}", zone_name);

        let url = "/v2/zones";
        let (timestamp, signature) = self.sign_request("GET", url, "");
        let endpoint = format!("https://dns.{}.myhuaweicloud.com{}", self.region, url);

        let response = self
            .client
            .get(&endpoint)
            .header("X-Sdk-Date", timestamp)
            .header(
                "Authorization",
                format!(
                    "SDK-HMAC-SHA256 Access={}, SignedHeaders=host;x-sdk-date, Signature={}",
                    self.access_key, signature
                ),
            )
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error while listing Huawei Cloud DNS zones: {}", e);
                AcmeError::transport(format!("Huawei API list zones failed: {}", e))
            })?;

        let body: serde_json::Value = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse Huawei Cloud DNS zones response: {}", e);
            AcmeError::protocol(format!("Failed to parse Huawei zones response: {}", e))
        })?;

        if let Some(zones) = body["zones"].as_array() {
            for zone in zones {
                if zone["name"].as_str() == Some(&zone_name) {
                    let id = zone["id"].as_str().unwrap_or_default().to_string();
                    tracing::debug!("Found Huawei zone ID: {} for {}", id, zone_name);
                    return Ok(id);
                }
            }
        }

        tracing::error!("Huawei Cloud DNS zone not found for: {}", zone_name);
        Err(AcmeError::protocol(format!(
            "Zone not found for domain: {}",
            domain
        )))
    }
}

#[async_trait]
impl DnsProvider for HuaweiCloudDnsProvider {
    /// Creates a TXT record in Huawei Cloud DNS.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        tracing::info!(
            "Creating TXT record in Huawei Cloud DNS for domain: {}",
            domain
        );

        let zone_id = self.find_zone_id(domain).await?;
        let url = format!("/v2/zones/{}/recordsets", zone_id);
        let payload = serde_json::json!({
            "name": format!("{}.", domain),
            "type": "TXT",
            "records": [format!("\"{}\"", value)],
            "ttl": 300
        })
        .to_string();

        let (timestamp, signature) = self.sign_request("POST", &url, &payload);
        let endpoint = format!("https://dns.{}.myhuaweicloud.com{}", self.region, url);

        let response = self
            .client
            .post(&endpoint)
            .header("X-Sdk-Date", timestamp)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!(
                    "SDK-HMAC-SHA256 Access={}, SignedHeaders=host;x-sdk-date, Signature={}",
                    self.access_key, signature
                ),
            )
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(
                    "Network error during Huawei Cloud DNS record creation: {}",
                    e
                );
                AcmeError::transport(format!("Huawei API create failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!("Huawei Cloud DNS API error: {}", error_text);
            return Err(AcmeError::protocol(format!("Huawei error: {}", error_text)));
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse Huawei Cloud DNS creation response: {}", e);
            AcmeError::protocol(format!("Failed to parse Huawei response: {}", e))
        })?;

        let record_id = body["id"].as_str().ok_or_else(|| {
            tracing::error!("'id' missing in Huawei Cloud DNS creation response");
            AcmeError::protocol("Huawei response missing record ID".to_string())
        })?;

        tracing::info!(
            "Successfully created Huawei Cloud DNS TXT record with ID: {}",
            record_id
        );
        // Return a composite ID: zone_id:record_id for deletion
        Ok(format!("{}:{}", zone_id, record_id))
    }

    /// Deletes a TXT record from Huawei Cloud DNS.
    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        tracing::info!(
            "Deleting TXT record from Huawei Cloud DNS, ID: {}",
            record_id
        );

        let parts: Vec<&str> = record_id.split(':').collect();
        if parts.len() != 2 {
            tracing::error!("Invalid Huawei record ID format: {}", record_id);
            return Err(AcmeError::invalid_input("Invalid Huawei record ID format"));
        }
        let zone_id = parts[0];
        let real_record_id = parts[1];

        let url = format!("/v2/zones/{}/recordsets/{}", zone_id, real_record_id);
        let (timestamp, signature) = self.sign_request("DELETE", &url, "");

        let endpoint = format!("https://dns.{}.myhuaweicloud.com{}", self.region, url);

        let response = self
            .client
            .delete(&endpoint)
            .header("X-Sdk-Date", timestamp)
            .header(
                "Authorization",
                format!(
                    "SDK-HMAC-SHA256 Access={}, SignedHeaders=host;x-sdk-date, Signature={}",
                    self.access_key, signature
                ),
            )
            .send()
            .await
            .map_err(|e| {
                tracing::error!(
                    "Network error during Huawei Cloud DNS record deletion: {}",
                    e
                );
                AcmeError::transport(format!("Huawei API delete failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!("Huawei Cloud DNS API deletion failed: {}", error_text);
            return Err(AcmeError::protocol(format!(
                "Huawei delete error: {}",
                error_text
            )));
        }

        tracing::info!("Successfully deleted Huawei Cloud DNS TXT record");
        Ok(())
    }

    /// Verifies the existence of a TXT record in Huawei Cloud DNS.
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        tracing::debug!(
            "Verifying TXT record in Huawei Cloud DNS for domain: {}",
            domain
        );
        let zone_id = match self.find_zone_id(domain).await {
            Ok(id) => id,
            Err(_) => return Ok(false),
        };

        let url = format!("/v2/zones/{zone_id}/recordsets?name={domain}&type=TXT");
        let (timestamp, signature) = self.sign_request("GET", &url, "");
        let endpoint = format!("https://dns.{}.myhuaweicloud.com{url}", self.region);

        let response = self.client.get(&endpoint)
            .header("X-Sdk-Date", timestamp)
            .header("Authorization", format!(
                "SDK-HMAC-SHA256 Access={}, SignedHeaders=host;x-sdk-date, Signature={signature}",
                self.access_key
            ))
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during Huawei Cloud DNS record verification: {}", e);
                AcmeError::transport(format!("Huawei API verify failed: {}", e))
            })?;

        let body: serde_json::Value = response.json().await.unwrap_or_default();
        let quoted_value = format!("\"{}\"", value);

        if let Some(recordsets) = body["recordsets"].as_array() {
            for rs in recordsets {
                if let Some(records) = rs["records"].as_array() {
                    for r in records {
                        if r.as_str() == Some(&quoted_value) {
                            tracing::debug!("Huawei Cloud DNS record verification successful");
                            return Ok(true);
                        }
                    }
                }
            }
        }

        tracing::warn!("Huawei Cloud DNS record verification failed: value not found");
        Ok(false)
    }
}
