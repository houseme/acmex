/// Account management for ACME
use crate::error::Result;
use crate::protocol::{DirectoryManager, Jwk, JwsSigner, NonceManager};
use crate::types::Contact;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::credentials::KeyPair;

/// Account information from ACME server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account ID (URL)
    #[serde(default)]
    pub id: String,

    /// Account status (valid, deactivated, revoked)
    pub status: String,

    /// Contact URIs
    pub contact: Vec<String>,

    /// Terms of service agreed
    #[serde(rename = "termsOfServiceAgreed", default)]
    pub terms_of_service_agreed: bool,

    /// Account creation date
    #[serde(default)]
    pub created_at: Option<String>,

    /// Initial IP address
    #[serde(default)]
    pub initial_ip: Option<String>,

    /// Orders URL
    #[serde(default)]
    pub orders: Option<String>,

    /// External account binding
    #[serde(default)]
    pub external_account_binding: Option<String>,
}

/// Account manager for handling account lifecycle
pub struct AccountManager<'a> {
    #[allow(dead_code)]
    pub(crate) key_pair: &'a KeyPair,
    pub(crate) signer: JwsSigner<'a>,
    pub(crate) jwk: Jwk,
    pub(crate) nonce_manager: &'a NonceManager,
    pub(crate) directory_manager: &'a DirectoryManager,
    pub(crate) http_client: &'a reqwest::Client,
}

impl<'a> AccountManager<'a> {
    /// Create a new account manager
    pub fn new(
        key_pair: &'a KeyPair,
        nonce_manager: &'a NonceManager,
        directory_manager: &'a DirectoryManager,
        http_client: &'a reqwest::Client,
    ) -> Result<Self> {
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

    /// Register a new account
    pub async fn register(
        &self,
        contacts: Vec<Contact>,
        terms_of_service_agreed: bool,
    ) -> Result<Account> {
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
                crate::error::AcmeError::transport(format!("Failed to register account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str() {
                self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
            }

        // Extract account URL before consuming response
        let account_url = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
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
            return Err(crate::error::AcmeError::account(format!(
                "Failed to register account: HTTP {}: {}",
                status, error_text
            )));
        }

        let mut account: Account = response.json().await.map_err(|e| {
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        account.id = account_url;
        Ok(account)
    }

    /// Update account contacts
    pub async fn update_contacts(
        &self,
        account_id: &str,
        contacts: Vec<Contact>,
    ) -> Result<Account> {
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
                crate::error::AcmeError::transport(format!("Failed to update account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str() {
                self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
            }

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(crate::error::AcmeError::account(format!(
                "Failed to update account: HTTP {}: {}",
                status, error_text
            )));
        }

        let account: Account = response.json().await.map_err(|e| {
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        Ok(account)
    }

    /// Get account information
    pub async fn get_account(&self, account_id: &str) -> Result<Account> {
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
                crate::error::AcmeError::transport(format!("Failed to get account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str() {
                self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
            }

        let status = response.status();
        if !status.is_success() {
            return Err(crate::error::AcmeError::account(format!(
                "Failed to get account: HTTP {}",
                status
            )));
        }

        let mut account: Account = response.json().await.map_err(|e| {
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        account.id = account_id.to_string();
        Ok(account)
    }

    /// Deactivate account
    pub async fn deactivate(&self, account_id: &str) -> Result<()> {
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
                crate::error::AcmeError::transport(format!("Failed to deactivate account: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str() {
                self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
            }

        let status = response.status();
        if !status.is_success() {
            return Err(crate::error::AcmeError::account(format!(
                "Failed to deactivate account: HTTP {}",
                status
            )));
        }

        Ok(())
    }

    /// Compute key authorization for a challenge token
    /// Format: token.jwk_thumbprint
    pub fn compute_key_authorization(&self, token: &str) -> Result<String> {
        let thumbprint = self.jwk.thumbprint_sha256()?;
        Ok(format!("{}.{}", token, thumbprint))
    }

    /// Get JWK thumbprint
    pub fn get_jwk_thumbprint(&self) -> Result<String> {
        self.jwk.thumbprint_sha256()
    }

    /// Get JWK for this account
    pub fn get_jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// Get signer
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
