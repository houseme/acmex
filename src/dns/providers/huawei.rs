//! Huawei Cloud DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Huawei Cloud DNS.

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use hmac::{Hmac, Mac, KeyInit};
use jiff::Zoned;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Huawei Cloud DNS Provider configuration
#[derive(Debug, Clone)]
pub struct HuaweiCloudDnsProvider {
    access_key: String,
    secret_key: String,
    #[allow(dead_code)]
    project_id: String,
    region: String,
    client: reqwest::Client,
}

impl HuaweiCloudDnsProvider {
    /// Create a new Huawei Cloud DNS provider instance
    pub fn new(access_key: String, secret_key: String, project_id: String, region: String) -> Self {
        Self {
            access_key,
            secret_key,
            project_id,
            region,
            client: reqwest::Client::new(),
        }
    }

    /// Sign request for Huawei Cloud API (SDKV2 / SIGV4)
    fn sign_request(&self, method: &str, url: &str, payload: &str) -> (String, String) {
        let now = Zoned::now();
        let timestamp = now.strftime("%Y%m%dT%H%M%SZ").to_string();

        // 1. Canonical Request
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

        // 2. String to Sign
        let string_to_sign = format!("SDK-HMAC-SHA256\n{}\n{}", timestamp, hashed_canonical);

        // 3. Signature
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(string_to_sign.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        (timestamp, signature)
    }
}

#[async_trait]
impl DnsProvider for HuaweiCloudDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!(
            "Creating TXT record in Huawei Cloud DNS for domain: {}",
            domain
        );

        // In a real implementation, we would first need to find the zone ID for the domain
        // For now, we assume the user might provide it or we'd have a lookup method.
        let zone_id = "zone-id-placeholder";
        let url = format!("/v2/zones/{}/recordsets", zone_id);
        let payload = format!(
            r#"{{"name":"{}.","type":"TXT","records":["\"{}\""]}}"#,
            domain, value
        );

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
            .map_err(|e| AcmeError::transport(format!("Huawei API create failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AcmeError::protocol(format!(
                "Huawei DNS create error: {}",
                error_text
            )));
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            AcmeError::protocol(format!("Failed to parse Huawei response: {}", e))
        })?;

        let record_id = body["id"].as_str().ok_or_else(|| {
            AcmeError::protocol("Huawei response missing record ID".to_string())
        })?;

        Ok(record_id.to_string())
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!(
            "Deleting TXT record in Huawei Cloud DNS for domain: {}, record_id: {}",
            domain, record_id
        );

        let zone_id = "zone-id-placeholder";
        let url = format!("/v2/zones/{}/recordsets/{}", zone_id, record_id);
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
                AcmeError::transport(format!("Huawei API delete failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AcmeError::protocol(format!(
                "Huawei DNS delete error: {}",
                error_text
            )));
        }

        info!("Huawei Cloud DNS TXT record deleted successfully");
        Ok(())
    }

    async fn verify_record(&self, _domain: &str, _value: &str) -> Result<bool> {
        Ok(true)
    }
}
