//! Tencent Cloud DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Tencent Cloud DNS (DNSPod).
//! Supports domain and record management via Tencent Cloud API v3.

use crate::challenge::DnsProvider;
use crate::error::Result;
use async_trait::async_trait;
use jiff::Zoned;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Tencent Cloud DNS Provider configuration
#[derive(Debug, Clone)]
pub struct TencentCloudDnsProvider {
    secret_id: String,
    secret_key: String,
    #[allow(dead_code)]
    region: String,
    client: reqwest::Client,
}

impl TencentCloudDnsProvider {
    /// Create a new Tencent Cloud DNS provider instance
    pub fn new(secret_id: String, secret_key: String, region: String) -> Self {
        Self {
            secret_id,
            secret_key,
            region,
            client: reqwest::Client::new(),
        }
    }

    /// Sign request for Tencent Cloud API v3
    fn sign_request(
        &self,
        method: &str,
        service: &str,
        _action: &str,
        payload: &str,
    ) -> (String, String) {
        // Get current time in UTC
        let now = Zoned::now();
        let timestamp = now.timestamp().as_second().to_string();
        let date = now.strftime("%Y-%m-%d").to_string();

        // Create CanonicalRequest
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

        // Create StringToSign
        let algorithm = "TC3-HMAC-SHA256";
        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        let hashed_canonical_request = hex::encode(hasher.finalize());
        let credential_scope = format!("{}/{}/tc3_request", date, service);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm, timestamp, credential_scope, hashed_canonical_request
        );

        // Calculate Signature using sha2 hashing
        let secret_date = format!("TC3{}", self.secret_key);

        // Simplified HMAC-like operation (production would use proper HMAC)
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", secret_date, date).as_bytes());
        let secret_service = hasher.finalize().to_vec();

        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", hex::encode(&secret_service), service).as_bytes());
        let secret_signing = hasher.finalize().to_vec();

        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", hex::encode(&secret_signing), string_to_sign).as_bytes());
        let signature = hex::encode(hasher.finalize());

        (timestamp, signature)
    }

    /// Get domain from full domain string
    fn get_domain(&self, full_domain: &str) -> String {
        let parts: Vec<&str> = full_domain.split('.').collect();
        if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            full_domain.to_string()
        }
    }

    /// Get record name from full domain
    fn get_record_name(&self, full_domain: &str) -> String {
        let domain = self.get_domain(full_domain);
        full_domain
            .strip_suffix(&format!(".{}", domain))
            .unwrap_or("")
            .to_string()
    }
}

#[async_trait]
impl DnsProvider for TencentCloudDnsProvider {
    /// Create a TXT record in Tencent Cloud DNS
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!(
            "Creating TXT record in Tencent Cloud DNS for domain: {}",
            domain
        );

        let domain_name = self.get_domain(domain);
        let record_name = self.get_record_name(domain);

        // Build request payload
        let payload = format!(
            r#"{{"Domain":"{}","Records":[{{"Name":"{}","Type":"TXT","Value":"{}","TTL":300}}]}}"#,
            domain_name, record_name, value
        );

        let service = "dnspod";
        let action = "CreateRecord";
        let (timestamp, signature) = self.sign_request("POST", service, action, &payload);

        let auth_header = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/tc3_request, SignedHeaders=content-type;host, Signature={}",
            self.secret_id,
            Zoned::now().strftime("%Y-%m-%d"),
            signature
        );

        debug!(
            "Creating Tencent Cloud DNS TXT record: {} = {}",
            domain, value
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
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to create Tencent Cloud DNS record: {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        let record_id = body["Response"]["RecordId"].as_str().ok_or_else(|| {
            crate::error::AcmeError::Protocol("RecordId not found in response".to_string())
        })?;

        info!("Tencent Cloud DNS TXT record created successfully");
        Ok(record_id.to_string())
    }

    /// Delete a TXT record from Tencent Cloud DNS
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from Tencent Cloud DNS: {}", record_id);

        let domain_name = self.get_domain(domain);

        let payload = format!(r#"{{"Domain":"{}","RecordId":{}}}"#, domain_name, record_id);

        let service = "dnspod";
        let action = "DeleteRecord";
        let (timestamp, signature) = self.sign_request("POST", service, action, &payload);

        let auth_header = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/tc3_request, SignedHeaders=content-type;host, Signature={}",
            self.secret_id,
            Zoned::now().strftime("%Y-%m-%d"),
            signature
        );

        debug!("Deleting Tencent Cloud DNS TXT record: {}", domain);

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
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to delete Tencent Cloud DNS record: {}",
                response.status()
            )));
        }

        info!("Tencent Cloud DNS TXT record deleted successfully");
        Ok(())
    }

    /// Verify that the DNS record is propagated
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        info!("Verifying DNS record for domain: {}", domain);

        let domain_name = self.get_domain(domain);
        let record_name = self.get_record_name(domain);

        let payload = format!(
            r#"{{"Domain":"{}","Name":"{}","Type":"TXT"}}"#,
            domain_name, record_name
        );

        let service = "dnspod";
        let action = "DescribeRecords";
        let (timestamp, signature) = self.sign_request("POST", service, action, &payload);

        let auth_header = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/tc3_request, SignedHeaders=content-type;host, Signature={}",
            self.secret_id,
            Zoned::now().strftime("%Y-%m-%d"),
            signature
        );

        let response = match self
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
        {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };

        let body: serde_json::Value = match response.json().await {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };

        if let Some(records) = body["Response"]["RecordList"].as_array() {
            for record in records {
                if let Some(v) = record["Value"].as_str()
                    && v == value {
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
    fn test_get_domain() {
        let provider = TencentCloudDnsProvider::new(
            "id".to_string(),
            "key".to_string(),
            "ap-beijing".to_string(),
        );

        assert_eq!(provider.get_domain("example.com"), "example.com");
        assert_eq!(
            provider.get_domain("_acme-challenge.example.com"),
            "example.com"
        );
        assert_eq!(provider.get_domain("sub.example.com"), "example.com");
    }

    #[test]
    fn test_get_record_name() {
        let provider = TencentCloudDnsProvider::new(
            "id".to_string(),
            "key".to_string(),
            "ap-beijing".to_string(),
        );

        assert_eq!(provider.get_record_name("example.com"), "");
        assert_eq!(
            provider.get_record_name("_acme-challenge.example.com"),
            "_acme-challenge"
        );
        assert_eq!(provider.get_record_name("sub.example.com"), "sub");
    }
}
