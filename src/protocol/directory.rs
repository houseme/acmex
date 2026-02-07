/// ACME Directory management
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// ACME Directory response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Directory {
    /// New nonce endpoint
    #[serde(rename = "newNonce")]
    pub new_nonce: String,

    /// New account endpoint
    #[serde(rename = "newAccount")]
    pub new_account: String,

    /// New order endpoint
    #[serde(rename = "newOrder")]
    pub new_order: String,

    /// Revoke cert endpoint
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,

    /// Key change endpoint
    #[serde(rename = "keyChange")]
    pub key_change: String,

    /// Directory metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<DirectoryMeta>,
}

/// Directory metadata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectoryMeta {
    /// Terms of Service URL
    #[serde(rename = "termsOfService")]
    pub terms_of_service: Option<String>,

    /// Website URL
    pub website: Option<String>,

    /// CAA identities
    #[serde(rename = "caaIdentities")]
    pub caa_identities: Option<Vec<String>>,

    /// External account required flag
    #[serde(rename = "externalAccountRequired")]
    pub external_account_required: Option<bool>,
}

/// Manager for ACME directory with caching
pub struct DirectoryManager {
    url: String,
    directory: Arc<RwLock<Option<Directory>>>,
    http_client: reqwest::Client,
}

impl DirectoryManager {
    /// Create a new directory manager
    pub fn new(url: impl Into<String>, http_client: reqwest::Client) -> Self {
        Self {
            url: url.into(),
            directory: Arc::new(RwLock::new(None)),
            http_client,
        }
    }

    /// Fetch fresh directory from server
    pub async fn fetch(&self) -> Result<Directory> {
        let response = self.http_client.get(&self.url).send().await.map_err(|e| {
            crate::error::AcmeError::transport(format!("Failed to fetch directory: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::protocol(format!(
                "Failed to fetch directory: HTTP {}",
                response.status()
            )));
        }

        let directory: Directory = response.json().await.map_err(|e| {
            crate::error::AcmeError::protocol(format!("Failed to parse directory: {}", e))
        })?;

        let mut cached = self.directory.write().await;
        *cached = Some(directory.clone());

        Ok(directory)
    }

    /// Get cached directory or fetch if not cached
    pub async fn get(&self) -> Result<Directory> {
        {
            let cached = self.directory.read().await;
            if let Some(dir) = cached.clone() {
                return Ok(dir);
            }
        }

        self.fetch().await
    }

    /// Clear cached directory
    pub async fn clear_cache(&self) {
        let mut cached = self.directory.write().await;
        *cached = None;
    }

    /// Get directory URL
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_parsing() {
        let json = r#"{
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert",
            "keyChange": "https://example.com/acme/key-change"
        }"#;

        let dir: Directory = serde_json::from_str(json).expect("Failed to parse directory");
        assert_eq!(dir.new_nonce, "https://example.com/acme/new-nonce");
        assert_eq!(dir.new_account, "https://example.com/acme/new-account");
    }

    #[test]
    fn test_directory_with_meta() {
        let json = r#"{
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert",
            "keyChange": "https://example.com/acme/key-change",
            "meta": {
                "termsOfService": "https://example.com/tos",
                "website": "https://example.com",
                "caaIdentities": ["example.com"],
                "externalAccountRequired": false
            }
        }"#;

        let dir: Directory = serde_json::from_str(json).expect("Failed to parse directory");
        assert!(dir.meta.is_some());
        let meta = dir.meta.unwrap();
        assert_eq!(
            meta.terms_of_service,
            Some("https://example.com/tos".to_string())
        );
        assert_eq!(meta.external_account_required, Some(false));
    }
}
