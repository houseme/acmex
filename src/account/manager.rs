/// Account management for ACME.
/// This module provides the `AccountManager` which handles account registration,
/// updates, and deactivation according to RFC 8555.
use crate::error::Result;
use crate::protocol::{DirectoryManager, Jwk, JwsSigner, NonceManager};
use crate::types::Contact;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::credentials::KeyPair;

/// Represents an ACME account as returned by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// The unique account ID (usually a URL).
    #[serde(default)]
    pub id: String,

    /// The current status of the account (e.g., "valid", "deactivated", "revoked").
    pub status: String,

    /// A list of contact URIs (e.g., "mailto:admin@example.com").
    pub contact: Vec<String>,

    /// Indicates if the user has agreed to the terms of service.
    #[serde(rename = "termsOfServiceAgreed", default)]
    pub terms_of_service_agreed: bool,

    /// The timestamp when the account was created.
    #[serde(default)]
    pub created_at: Option<String>,

    /// The IP address from which the account was initially created.
    #[serde(default)]
    pub initial_ip: Option<String>,

    /// The URL for retrieving orders associated with this account.
    #[serde(default)]
    pub orders: Option<String>,

    /// Information about external account binding, if applicable.
    #[serde(default)]
    pub external_account_binding: Option<String>,
}

/// Manages the lifecycle of an ACME account.
pub struct AccountManager<'a> {
    /// The key pair used for signing requests.
    #[allow(dead_code)]
    pub(crate) key_pair: &'a KeyPair,
    /// The JWS signer for creating signed requests.
    pub(crate) signer: JwsSigner<'a>,
    /// The JSON Web Key (JWK) representation of the public key.
    pub(crate) jwk: Jwk,
    /// Manager for handling nonces.
    pub(crate) nonce_manager: &'a NonceManager,
    /// Manager for retrieving ACME directory information.
    pub(crate) directory_manager: &'a DirectoryManager,
    /// The HTTP client used for network requests.
    pub(crate) http_client: &'a reqwest::Client,
}

impl<'a> AccountManager<'a> {
    /// Creates a new `AccountManager` with the provided dependencies.
    pub fn new(
        key_pair: &'a KeyPair,
        nonce_manager: &'a NonceManager,
        directory_manager: &'a DirectoryManager,
        http_client: &'a reqwest::Client,
    ) -> Result<Self> {
        tracing::debug!("Initializing AccountManager");
        let signer = JwsSigner::new(&key_pair.0);
        let jwk = Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(key_pair.public_key_bytes()));

        Ok(Self {
            key_pair,
            signer,
            jwk,
            nonce_manager,
            directory_manager,
            http_client,
        })
    }

    /// Registers a new account with the ACME server.
    ///
    /// # Arguments
    /// * `contacts` - A list of contact information for the account.
    /// * `terms_of_service_agreed` - Must be true to proceed with registration.
    pub async fn register(
        &self,
        contacts: Vec<Contact>,
        terms_of_service_agreed: bool,
    ) -> Result<Account> {
        tracing::info!("Registering new ACME account with contacts: {:?}", contacts);
        let directory = self.directory_manager.get().await?;
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "jwk": self.jwk.to_value(),
            "nonce": nonce,
            "url": directory.new_account,
        });

        let contacts_uri: Vec<String> = contacts.iter().map(|c| c.to_uri()).collect();
        let payload = json!({
            "termsOfServiceAgreed": terms_of_service_agreed,
            "contact": contacts_uri,
        });

        let jws = self.signer.sign(&header, &payload)?;

        let response = self
            .http_client
            .post(&directory.new_account)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during account registration: {}", e);
                crate::error::AcmeError::transport(format!("Failed to register account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        // Extract account URL before consuming response
        let account_url = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                tracing::error!("ACME server did not return a Location header for the new account");
                crate::error::AcmeError::account(
                    "Missing location header in account response".to_string(),
                )
            })?
            .to_string();

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!(
                "Account registration failed with status {}: {}",
                status,
                error_text
            );
            return Err(crate::error::AcmeError::account(format!(
                "Failed to register account: HTTP {}: {}",
                status, error_text
            )));
        }

        let mut account: Account = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse account JSON response: {}", e);
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        account.id = account_url;
        tracing::info!("Account registered successfully with ID: {}", account.id);
        Ok(account)
    }

    /// Updates the contact information for an existing account.
    pub async fn update_contacts(
        &self,
        account_id: &str,
        contacts: Vec<Contact>,
    ) -> Result<Account> {
        tracing::info!(
            "Updating contacts for account {}: {:?}",
            account_id,
            contacts
        );
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": account_id,
            "nonce": nonce,
            "url": account_id,
        });

        let contacts_uri: Vec<String> = contacts.iter().map(|c| c.to_uri()).collect();
        let payload = json!({
            "contact": contacts_uri,
        });

        let jws = self.signer.sign(&header, &payload)?;

        let response = self
            .http_client
            .post(account_id)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during contact update: {}", e);
                crate::error::AcmeError::transport(format!("Failed to update account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!(
                "Contact update failed with status {}: {}",
                status,
                error_text
            );
            return Err(crate::error::AcmeError::account(format!(
                "Failed to update account: HTTP {}: {}",
                status, error_text
            )));
        }

        let account: Account = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse updated account JSON: {}", e);
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        tracing::info!("Contacts updated successfully for account {}", account_id);
        Ok(account)
    }

    /// Retrieves the current account information from the ACME server.
    pub async fn get_account(&self, account_id: &str) -> Result<Account> {
        tracing::debug!("Fetching account info for {}", account_id);
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": account_id,
            "nonce": nonce,
            "url": account_id,
        });

        let payload = json!({});

        let jws = self.signer.sign(&header, &payload)?;

        let response = self
            .http_client
            .post(account_id)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error while fetching account: {}", e);
                crate::error::AcmeError::transport(format!("Failed to get account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            tracing::error!("Failed to fetch account {}, status: {}", account_id, status);
            return Err(crate::error::AcmeError::account(format!(
                "Failed to get account: HTTP {}",
                status
            )));
        }

        let mut account: Account = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse account JSON: {}", e);
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        account.id = account_id.to_string();
        Ok(account)
    }

    /// Deactivates the account on the ACME server.
    /// Once deactivated, the account cannot be used for further operations.
    pub async fn deactivate(&self, account_id: &str) -> Result<()> {
        tracing::info!("Deactivating account {}", account_id);
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": account_id,
            "nonce": nonce,
            "url": account_id,
        });

        let payload = json!({
            "status": "deactivated"
        });

        let jws = self.signer.sign(&header, &payload)?;

        let response = self
            .http_client
            .post(account_id)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during account deactivation: {}", e);
                crate::error::AcmeError::transport(format!("Failed to deactivate account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            tracing::error!(
                "Account deactivation failed for {}, status: {}",
                account_id,
                status
            );
            return Err(crate::error::AcmeError::account(format!(
                "Failed to deactivate account: HTTP {}",
                status
            )));
        }

        tracing::info!("Account {} successfully deactivated", account_id);
        Ok(())
    }

    /// Computes the key authorization string for a given challenge token.
    /// The format is `token.jwk_thumbprint`.
    pub fn compute_key_authorization(&self, token: &str) -> Result<String> {
        let thumbprint = self.jwk.thumbprint_sha256()?;
        Ok(format!("{}.{}", token, thumbprint))
    }

    /// Returns the SHA-256 thumbprint of the account's JSON Web Key (JWK).
    pub fn get_jwk_thumbprint(&self) -> Result<String> {
        self.jwk.thumbprint_sha256()
    }

    /// Returns a reference to the account's JSON Web Key (JWK).
    pub fn get_jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// Returns a reference to the JWS signer.
    pub fn get_signer(&self) -> &JwsSigner<'a> {
        &self.signer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_parsing() {
        let json = r#"{
            "status": "valid",
            "contact": ["mailto:admin@example.com"],
            "termsOfServiceAgreed": true,
            "orders": "https://example.com/acme/acct/123/orders"
        }"#;

        let account: Account = serde_json::from_str(json).expect("Failed to parse account");
        assert_eq!(account.status, "valid");
        assert_eq!(account.contact.len(), 1);
        assert!(account.terms_of_service_agreed);
    }
}
