/// Tencent Cloud DNS Provider implementation.
/// This module provides DNS record management for Tencent Cloud DNS (DNSPod) using the Tencent Cloud API v3.
use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use jiff::Zoned;
use sha2::{Digest, Sha256};

/// Tencent Cloud DNS Provider for handling DNS-01 challenges.
#[derive(Debug, Clone)]
pub struct TencentCloudDnsProvider {
    /// Tencent Cloud Secret ID.
    secret_id: String,
    /// Tencent Cloud Secret Key.
    secret_key: String,
    /// Target region (currently unused for DNSPod API).
    #[allow(dead_code)]
    region: String,
    /// Internal HTTP client.
    client: reqwest::Client,
}

impl TencentCloudDnsProvider {
    /// Creates a new `TencentCloudDnsProvider` instance.
    pub fn new(secret_id: String, secret_key: String, region: String) -> Self {
        tracing::debug!("Initializing TencentCloudDnsProvider for region: {}", region);
        Self {
            secret_id,
            secret_key,
            region,
            client: reqwest::Client::new(),
        }
    }

    /// Signs the request for Tencent Cloud API v3 using the TC3-HMAC-SHA256 algorithm.
    fn sign_request(
        &self,
        method: &str,
        service: &str,
        _action: &str,
        payload: &str,
    ) -> (String, String) {
        let now = Zoned::now();
        let timestamp = now.timestamp().as_second().to_string();
        let date = now.strftime("%Y-%m-%d").to_string();

        // 1. Construct Canonical Request
        let canonical_uri = "/";
        let canonical_querystring = "";
        let canonical_headers =
            "content-type:application/json\nhost:dnspod.tencentcloudapi.com\n".to_string();
        let signed_headers = "content-type;host";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let hashed_payload = hex::encode(hasher.finalize());
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            hashed_payload
        );

        // 2. Construct String to Sign
        let algorithm = "TC3-HMAC-SHA256";
        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        let hashed_canonical_request = hex::encode(hasher.finalize());
        let credential_scope = format!("{}/{}/tc3_request", date, service);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm, timestamp, credential_scope, hashed_canonical_request
        );

        // 3. Calculate Signature
        let hmac_sha256 = |key: &[u8], msg: &[u8]| -> Vec<u8> {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        };

        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, service.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        (timestamp, signature)
    }

    /// Extracts the root domain from a full domain string.
    fn get_domain(&self, full_domain: &str) -> String {
        let parts: Vec<&str> = full_domain.split('.').collect();
        if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            full_domain.to_string()
        }
    }

    /// Extracts the record name (subdomain) from a full domain string.
    fn get_record_name(&self, full_domain: &str) -> String {
        let domain = self.get_domain(full_domain);
        let name = full_domain
            .strip_suffix(&format!(".{}", domain))
            .unwrap_or("")
            .to_string();
        if name.is_empty() && full_domain != domain {
            full_domain
                .strip_suffix(&domain)
                .unwrap_or("")
                .trim_end_matches('.')
                .to_string()
        } else {
            name
        }
    }
}

#[async_trait]
impl DnsProvider for TencentCloudDnsProvider {
    /// Creates a TXT record in Tencent Cloud DNS.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        tracing::info!("Creating TXT record in Tencent Cloud DNS for domain: {}", domain);

        let domain_name = self.get_domain(domain);
        let record_name = self.get_record_name(domain);

        let payload = serde_json::json!({
            "Domain": domain_name,
            "SubDomain": record_name,
            "RecordType": "TXT",
            "RecordLine": "默认",
            "Value": value,
            "TTL": 600
        })
        .to_string();

        let service = "dnspod";
        let action = "CreateRecord";
        let (timestamp, signature) = self.sign_request("POST", service, action, &payload);

        let date = Zoned::now().strftime("%Y-%m-%d").to_string();
        let auth_header = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/{}/tc3_request, SignedHeaders=content-type;host, Signature={}",
            self.secret_id, date, service, signature
        );

        let response = self
            .client
            .post("https://dnspod.tencentcloudapi.com/")
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .header("X-TC-Action", action)
            .header("X-TC-Timestamp", timestamp)
            .header("X-TC-Version", "2021-03-23")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during Tencent Cloud API call: {}", e);
                AcmeError::transport(format!("Tencent API failed: {}", e))
            })?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse Tencent Cloud API response: {}", e);
                AcmeError::protocol(format!("Failed to parse Tencent response: {}", e))
            })?;

        if let Some(err) = body["Response"]["Error"].as_object() {
            let code = err["Code"].as_str().unwrap_or("Unknown");
            let message = err["Message"].as_str().unwrap_or("");
            tracing::error!("Tencent Cloud DNS API error ({}): {}", code, message);
            return Err(AcmeError::protocol(format!(
                "Tencent DNS error: {} - {}",
                code, message
            )));
        }

        let record_id = body["Response"]["RecordId"]
            .as_u64()
            .map(|id| id.to_string())
            .or_else(|| body["Response"]["RecordId"].as_str().map(|s| s.to_string()))
            .ok_or_else(|| {
                tracing::error!("'RecordId' missing in Tencent Cloud DNS creation response");
                AcmeError::protocol("RecordId not found in response".to_string())
            })?;

        tracing::info!("Successfully created Tencent Cloud TXT record with ID: {}", record_id);
        Ok(record_id)
    }

    /// Deletes a TXT record from Tencent Cloud DNS.
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        tracing::info!("Deleting TXT record from Tencent Cloud DNS, ID: {}", record_id);

        let domain_name = self.get_domain(domain);
        let payload = serde_json::json!({
            "Domain": domain_name,
            "RecordId": record_id.parse::<u64>().map_err(|_| {
                tracing::error!("Invalid Tencent record ID format: {}", record_id);
                AcmeError::invalid_input("Invalid record ID")
            })?
        }).to_string();

        let service = "dnspod";
        let action = "DeleteRecord";
        let (timestamp, signature) = self.sign_request("POST", service, action, &payload);

        let date = Zoned::now().strftime("%Y-%m-%d").to_string();
        let auth_header = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/{}/tc3_request, SignedHeaders=content-type;host, Signature={}",
            self.secret_id, date, service, signature
        );

        let response = self
            .client
            .post("https://dnspod.tencentcloudapi.com/")
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .header("X-TC-Action", action)
            .header("X-TC-Timestamp", timestamp)
            .header("X-TC-Version", "2021-03-23")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during Tencent Cloud DNS record deletion: {}", e);
                AcmeError::transport(format!("Tencent API delete failed: {}", e))
            })?;

        if !response.status().is_success() {
            tracing::error!("Tencent Cloud DNS API deletion failed with status: {}", response.status());
            return Err(AcmeError::protocol(
                "Tencent DNS delete request failed".to_string(),
            ));
        }

        tracing::info!("Successfully deleted Tencent Cloud TXT record: {}", record_id);
        Ok(())
    }

    /// Verifies the existence of a TXT record in Tencent Cloud DNS.
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        tracing::debug!("Verifying TXT record in Tencent Cloud DNS for domain: {}", domain);
        let domain_name = self.get_domain(domain);
        let record_name = self.get_record_name(domain);

        let payload = serde_json::json!({
            "Domain": domain_name,
            "Subdomain": record_name,
            "RecordType": "TXT"
        })
        .to_string();

        let service = "dnspod";
        let action = "DescribeRecordList";
        let (timestamp, signature) = self.sign_request("POST", service, action, &payload);

        let date = Zoned::now().strftime("%Y-%m-%d").to_string();
        let auth_header = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/{}/tc3_request, SignedHeaders=content-type;host, Signature={}",
            self.secret_id, date, service, signature
        );

        let response = self
            .client
            .post("https://dnspod.tencentcloudapi.com/")
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .header("X-TC-Action", action)
            .header("X-TC-Timestamp", timestamp)
            .header("X-TC-Version", "2021-03-23")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during Tencent Cloud DNS record verification: {}", e);
                AcmeError::transport(format!("Tencent API verify failed: {}", e))
            })?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse Tencent Cloud DNS verification response: {}", e);
                AcmeError::protocol(format!("Failed to parse Tencent response: {}", e))
            })?;

        if let Some(records) = body["Response"]["RecordList"].as_array() {
            for record in records {
                if record["Value"].as_str() == Some(value) {
                    tracing::debug!("Tencent Cloud DNS record verification successful");
                    return Ok(true);
                }
            }
        }

        tracing::warn!("Tencent Cloud DNS record verification failed: value not found");
        Ok(false)
    }
}
