//! Alibaba Cloud DNS Provider implementation for AcmeX
//!
//! This module provides DNS record management for Alibaba Cloud DNS.
//! Supports domain and record management via Alibaba Cloud REST API.

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, Mac, KeyInit};
use jiff::Zoned;
use sha2::Sha256;
use std::collections::BTreeMap;
use tracing::{debug, info};

/// Alibaba Cloud DNS Provider configuration
#[derive(Debug, Clone)]
pub struct AlibabaCloudDnsProvider {
    access_key_id: String,
    access_key_secret: String,
    #[allow(dead_code)]
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

    /// Sign request for Alibaba Cloud API (POP RPC Style)
    fn sign_request(&self, method: &str, params: &BTreeMap<String, String>) -> String {
        // 1. Sort parameters and build canonical query string
        let canonical_query_string = params
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    self.percent_encode(k),
                    self.percent_encode(v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        // 2. Build string to sign
        let string_to_sign = format!(
            "{}&%2F&{}",
            method.to_uppercase(),
            self.percent_encode(&canonical_query_string)
        );

        // 3. Calculate HMAC-SHA1 signature (Alibaba Cloud uses SHA1 for this style)
        // Note: Some newer APIs support SHA256, but SHA1 is the standard for RPC style.
        use hmac::Hmac;
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;

        let secret = format!("{}&", self.access_key_secret);
        let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(string_to_sign.as_bytes());

        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    fn percent_encode(&self, s: &str) -> String {
        urlencoding::encode(s)
            .replace("+", "%20")
            .replace("*", "%2A")
            .replace("%7E", "~")
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
        let name = domain
            .strip_suffix(&format!(".{}", domain_name))
            .unwrap_or("")
            .to_string();
        if name.is_empty() && domain != domain_name {
             domain.strip_suffix(domain_name).unwrap_or("").trim_end_matches('.').to_string()
        } else {
            name
        }
    }

    async fn do_request(&self, mut params: BTreeMap<String, String>) -> Result<serde_json::Value> {
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), "2015-01-09".to_string());
        params.insert("AccessKeyId".to_string(), self.access_key_id.clone());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), rand::random::<u64>().to_string());
        params.insert(
            "Timestamp".to_string(),
            Zoned::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );

        let signature = self.sign_request("GET", &params);
        params.insert("Signature".to_string(), signature);

        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", self.percent_encode(k), self.percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let url = format!("https://alidns.aliyuncs.com/?{}", query);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("Alibaba API failed: {}", e)))?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            AcmeError::protocol(format!("Failed to parse Alibaba response: {}", e))
        })?;

        if !status.is_success() {
            return Err(AcmeError::protocol(format!(
                "Alibaba DNS error: {} - {}",
                body["Code"].as_str().unwrap_or("Unknown"),
                body["Message"].as_str().unwrap_or("")
            )));
        }

        Ok(body)
    }
}

#[async_trait]
impl DnsProvider for AlibabaCloudDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        info!("Creating TXT record in Alibaba Cloud DNS: {}", domain);

        let domain_name = self.get_domain_name(domain);
        let record_name = self.get_record_name(domain);

        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "AddDomainRecord".to_string());
        params.insert("DomainName".to_string(), domain_name);
        params.insert("RR".to_string(), record_name);
        params.insert("Type".to_string(), "TXT".to_string());
        params.insert("Value".to_string(), value.to_string());
        params.insert("TTL".to_string(), "600".to_string());

        let body = self.do_request(params).await?;

        let record_id = body["RecordId"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AcmeError::protocol("RecordId not found in response".to_string()))?;

        Ok(record_id)
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        info!("Deleting TXT record from Alibaba Cloud DNS: {}", record_id);

        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "DeleteDomainRecord".to_string());
        params.insert("RecordId".to_string(), record_id.to_string());

        self.do_request(params).await?;
        Ok(())
    }

    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        let domain_name = self.get_domain_name(domain);
        let record_name = self.get_record_name(domain);

        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "DescribeDomainRecords".to_string());
        params.insert("DomainName".to_string(), domain_name);
        params.insert("RRKeyWord".to_string(), record_name);
        params.insert("TypeKeyWord".to_string(), "TXT".to_string());

        let body = self.do_request(params).await?;

        if let Some(records) = body["DomainRecords"]["Record"].as_array() {
            for record in records {
                if record["Value"].as_str() == Some(value) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}
