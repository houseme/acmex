/// Account Key Rollover implementation.
/// This module handles the process of changing the cryptographic key pair
/// associated with an ACME account (RFC 8555 Section 7.3.5).
use crate::account::{Account, AccountManager, KeyPair};
use crate::error::Result;
use serde_json::json;

/// Manages the process of rotating an ACME account's key pair.
pub struct KeyRollover<'a> {
    /// The manager for the current account.
    account_manager: &'a AccountManager<'a>,
    /// The new key pair to be associated with the account.
    new_key_pair: KeyPair,
}

impl<'a> KeyRollover<'a> {
    /// Creates a new `KeyRollover` manager and generates a new random key pair.
    pub fn new(account_manager: &'a AccountManager<'a>) -> Result<Self> {
        tracing::debug!("Initializing KeyRollover with a new random key pair");
        let new_key_pair = KeyPair::generate()?;
        Ok(Self {
            account_manager,
            new_key_pair,
        })
    }

    /// Creates a `KeyRollover` manager with a specific pre-generated key pair.
    pub fn with_new_key(account_manager: &'a AccountManager<'a>, new_key_pair: KeyPair) -> Self {
        tracing::debug!("Initializing KeyRollover with a provided key pair");
        Self {
            account_manager,
            new_key_pair,
        }
    }

    /// Executes the key rollover process on the ACME server.
    /// This involves a double-signed JWS (inner signed by new key, outer by old key).
    pub async fn execute(&self, account_url: &str) -> Result<Account> {
        tracing::info!("Starting account key rollover for account: {}", account_url);

        // 1. Get directory to find keyChange endpoint
        let directory = self.account_manager.directory_manager.get().await?;
        let key_change_url = directory.key_change;

        // 2. Create inner JWS (signed by NEW key). The construction is
        // shared with the production ca_backend path to avoid protocol drift
        // while this legacy CLI facade remains available.
        tracing::debug!("Creating inner JWS signed by the new key");
        let inner_jws_obj = crate::ca_backend::backend::key_change_inner_jws(
            account_url,
            &key_change_url,
            self.account_manager.get_jwk(),
            &self.new_key_pair,
        )?;

        // 3. Create outer JWS (signed by OLD key)
        tracing::debug!("Creating outer JWS signed by the old key");
        let nonce = self.account_manager.nonce_manager.get_nonce().await?;

        let outer_header = json!({
            "alg": "EdDSA",
            "kid": account_url,
            "nonce": nonce,
            "url": key_change_url
        });

        let outer_jws = self
            .account_manager
            .get_signer()
            .sign(&outer_header, &inner_jws_obj)?;

        // 4. Send request to the keyChange endpoint
        tracing::info!("Sending keyChange request to: {}", key_change_url);
        let response = self
            .account_manager
            .http_client
            .post(&key_change_url)
            .header("Content-Type", "application/jose+json")
            .body(outer_jws)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error during keyChange request: {}", e);
                crate::error::AcmeError::transport(format!("Failed to change key: {}", e))
            })?;

        // Cache the nonce from response
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.account_manager
                .nonce_manager
                .cache_nonce(nonce_str.to_string())
                .await;
        }

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("Key rollover failed with status {}: {}", status, error_text);
            return Err(crate::error::AcmeError::account(format!(
                "Failed to change key: HTTP {}: {}",
                status, error_text
            )));
        }

        let mut account: Account = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse account response after key rollover: {}", e);
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        account.id = account_url.to_string();
        tracing::info!(
            "Account key rollover completed successfully for {}",
            account.id
        );

        Ok(account)
    }

    /// Returns a reference to the new key pair.
    pub fn new_key_pair(&self) -> &KeyPair {
        &self.new_key_pair
    }
}
