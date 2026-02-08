/// Alibaba Cloud DNS Provider implementation.
/// This module provides DNS record management for Alibaba Cloud DNS (Alidns)
/// using the Alibaba Cloud POP RPC API style.
use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, Mac, KeyInit};
use jiff::Zoned;
use sha1::Sha1;
use std::collections::BTreeMap;

/// Alibaba Cloud DNS Provider for handling DNS-01 challenges.
#[derive(Debug, Clone)]
pub struct AlibabaCloudDnsProvider {
    /// Alibaba Cloud Access Key ID.
    access_key_id: String,
    /// Alibaba Cloud Access Key Secret.
    access_key_secret: String,
    /// Target region (e.g., "cn-hangzhou").
    #[allow(dead_code)]
    region: String,
    /// Internal HTTP client.
    client: reqwest::Client,
}

impl AlibabaCloudDnsProvider {
    /// Creates a new `AlibabaCloudDnsProvider` instance.
    pub fn new(access_key_id: String, access_key_secret: String, region: String) -> Self {
        tracing::debug!("Initializing AlibabaCloudDnsProvider for region: {}", region);
        Self {
            access_key_id,
            access_key_secret,
            region,
            client: reqwest::Client::new(),
        }
    }

    /// Signs the request for Alibaba Cloud API using HMAC-SHA1 (POP RPC Style).
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

        // 3. Calculate HMAC-SHA1 signature
        type HmacSha1 = Hmac<Sha1>;

        let secret = format!("{}&", self.access_key_secret);
        let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(string_to_sign.as_bytes());

        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    /// Performs percent-encoding according to Alibaba Cloud's specific requirements.
    fn percent_encode(&self, s: &str) -> String {
        urlencoding::encode(s)
            .replace("+", "%20")
            .replace("*", "%2A")
            .replace("%7E", "~")
    }

    /// Extracts the root domain name from a full domain string.
    fn get_domain_name(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            domain.to_string()
        }
    }

    /// Extracts the record name (RR) from a full domain string.
    fn get_record_name(&self, domain: &str) -> String {
        let domain_name = self.get_domain_name(domain);
        let name = domain
            .strip_suffix(&format!(".{}", domain_name))
            .unwrap_or("")
            .to_string();
        if name.is_empty() && domain != domain_name {
             domain.strip_suffix(&domain_name).unwrap_or("").trim_end_matches('.').to_string()
        } else {
            name
        }
    }

    /// Executes a signed request to the Alibaba Cloud DNS API.
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
            .map_err(|e| {
                tracing::error!("Network error during Alibaba Cloud API call: {}", e);
                AcmeError::transport(format!("Alibaba API failed: {}", e))
            })?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse Alibaba Cloud API response: {}", e);
            AcmeError::protocol(format!("Failed to parse Alibaba response: {}", e))
        })?;

        if !status.is_success() {
            let code = body["Code"].as_str().unwrap_or("Unknown");
            let message = body["Message"].as_str().unwrap_or("");
            tracing::error!("Alibaba Cloud DNS API error ({}): {}", code, message);
            return Err(AcmeError::protocol(format!(
                "Alibaba DNS error: {} - {}",
                code, message
            )));
        }

        Ok(body)
    }
}

#[async_trait]
impl DnsProvider for AlibabaCloudDnsProvider {
    /// Creates a TXT record in Alibaba Cloud DNS.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        tracing::info!("Creating TXT record in Alibaba Cloud DNS for domain: {}", domain);

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
            .ok_or_else(|| {
                tracing::error!("RecordId missing in Alibaba Cloud AddDomainRecord response");
                AcmeError::protocol("RecordId not found in response".to_string())
            })?;

        tracing::info!("Successfully created Alibaba Cloud TXT record with ID: {}", record_id);
        Ok(record_id)
    }

    /// Deletes a TXT record from Alibaba Cloud DNS.
    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> Result<()> {
        tracing::info!("Deleting TXT record from Alibaba Cloud DNS, ID: {}", record_id);

        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "DeleteDomainRecord".to_string());
        params.insert("RecordId".to_string(), record_id.to_string());

        self.do_request(params).await?;
        tracing::info!("Successfully deleted Alibaba Cloud TXT record: {}", record_id);
        Ok(())
    }

    /// Verifies the existence of a TXT record in Alibaba Cloud DNS.
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        tracing::debug!("Verifying TXT record in Alibaba Cloud DNS for domain: {}", domain);
        let domain_name = self.get_domain_name(domain);
        let record_name = self.get_record_name(domain);

        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "DescribeDomainRecords".to_string());
        params.insert("DomainName".to_string(), domain_name);
        params.insert("RRKeyWord".to_string(), record_name);
        params.insert("TypeKeyWord".to_string(), "TXT".to_string());

        let body = self.do_request(params).await?;

        if let Some(domain_records) = body["DomainRecords"]["Record"].as_array() {
            for record in domain_records {
                if record["Value"].as_str() == Some(value) {
                    tracing::debug!("Alibaba Cloud record verification successful");
                    return Ok(true);
                }
            }
        }

        tracing::warn!("Alibaba Cloud record verification failed: value not found");
        Ok(false)
    }
}
