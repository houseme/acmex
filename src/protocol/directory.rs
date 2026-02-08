/// ACME Directory management.
/// This module handles the discovery of ACME service endpoints from the directory URL.
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Represents the ACME Directory response containing service endpoints.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Directory {
    /// Endpoint for obtaining a new anti-replay nonce.
    #[serde(rename = "newNonce")]
    pub new_nonce: String,

    /// Endpoint for creating a new account.
    #[serde(rename = "newAccount")]
    pub new_account: String,

    /// Endpoint for creating a new certificate order.
    #[serde(rename = "newOrder")]
    pub new_order: String,

    /// Endpoint for revoking a certificate.
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,

    /// Endpoint for changing the account key.
    #[serde(rename = "keyChange")]
    pub key_change: String,

    /// Optional metadata provided by the ACME server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<DirectoryMeta>,
}

/// Metadata associated with the ACME directory.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectoryMeta {
    /// URL for the server's Terms of Service.
    #[serde(rename = "termsOfService")]
    pub terms_of_service: Option<String>,

    /// URL for the server's website.
    pub website: Option<String>,

    /// List of hostnames that the server will use in CAA checks.
    #[serde(rename = "caaIdentities")]
    pub caa_identities: Option<Vec<String>>,

    /// Indicates whether the server requires an external account binding.
    #[serde(rename = "externalAccountRequired")]
    pub external_account_required: Option<bool>,
}

/// A thread-safe manager for the ACME directory with caching capabilities.
pub struct DirectoryManager {
    /// The base directory URL.
    url: String,
    /// Cached directory information.
    directory: Arc<RwLock<Option<Directory>>>,
    /// The HTTP client used for fetching the directory.
    http_client: reqwest::Client,
}

impl DirectoryManager {
    /// Creates a new `DirectoryManager` for the given ACME directory URL.
    pub fn new(url: impl Into<String>, http_client: reqwest::Client) -> Self {
        let url = url.into();
        tracing::debug!("Initializing DirectoryManager for URL: {}", url);
        Self {
            url,
            directory: Arc::new(RwLock::new(None)),
            http_client,
        }
    }

    /// Fetches a fresh copy of the directory from the ACME server.
    pub async fn fetch(&self) -> Result<Directory> {
        tracing::info!("Fetching ACME directory from: {}", self.url);
        let response = self.http_client.get(&self.url).send().await.map_err(|e| {
            tracing::error!("Failed to connect to ACME directory: {}", e);
            crate::error::AcmeError::transport(format!("Failed to fetch directory: {}", e))
        })?;

        if !response.status().is_success() {
            tracing::error!(
                "ACME directory request failed with status: {}",
                response.status()
            );
            return Err(crate::error::AcmeError::protocol(format!(
                "Failed to fetch directory: HTTP {}",
                response.status()
            )));
        }

        let directory: Directory = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse ACME directory JSON: {}", e);
            crate::error::AcmeError::protocol(format!("Failed to parse directory: {}", e))
        })?;

        tracing::debug!("Successfully fetched and parsed ACME directory");
        let mut cached = self.directory.write().await;
        *cached = Some(directory.clone());

        Ok(directory)
    }

    /// Returns the cached directory or fetches it if it's not already cached.
    pub async fn get(&self) -> Result<Directory> {
        {
            let cached = self.directory.read().await;
            if let Some(dir) = cached.clone() {
                tracing::debug!("Using cached ACME directory");
                return Ok(dir);
            }
        }

        self.fetch().await
    }

    /// Clears the cached directory information.
    pub async fn clear_cache(&self) {
        tracing::debug!("Clearing ACME directory cache");
        let mut cached = self.directory.write().await;
        *cached = None;
    }

    /// Returns the base directory URL.
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
