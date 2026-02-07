/// Account Key Rollover implementation
use crate::account::{Account, AccountManager, KeyPair};
use crate::error::Result;
use crate::protocol::{Jwk, JwsSigner};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

/// Key Rollover manager
pub struct KeyRollover<'a> {
    account_manager: &'a AccountManager<'a>,
    new_key_pair: KeyPair,
}

impl<'a> KeyRollover<'a> {
    /// Create a new key rollover manager
    pub fn new(account_manager: &'a AccountManager<'a>) -> Result<Self> {
        let new_key_pair = KeyPair::generate()?;
        Ok(Self {
            account_manager,
            new_key_pair,
        })
    }

    /// Create with specific new key pair
    pub fn with_new_key(account_manager: &'a AccountManager<'a>, new_key_pair: KeyPair) -> Self {
        Self {
            account_manager,
            new_key_pair,
        }
    }

    /// Execute key rollover
    pub async fn execute(&self, account_url: &str) -> Result<Account> {
        // 1. Get directory to find keyChange endpoint
        let directory = self.account_manager.directory_manager.get().await?;
        let key_change_url = directory.key_change;

        // 2. Prepare new key information
        let new_jwk =
            Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(self.new_key_pair.public_key_bytes()));

        // 3. Create inner JWS (signed by NEW key)
        // The payload is the new key's JWK
        // The URL in the header is the keyChange URL
        let inner_payload = json!({
            "account": account_url,
            "oldKey": self.account_manager.get_jwk()
        });

        let new_signer = JwsSigner::new(&self.new_key_pair.0);
        let inner_header = json!({
            "alg": "EdDSA",
            "jwk": new_jwk.to_value(),
            "url": key_change_url
        });

        let inner_jws = new_signer.sign(&inner_header, &inner_payload)?;

        // 4. Create outer JWS (signed by OLD key)
        // The payload is the inner JWS
        // The URL in the header is the keyChange URL
        let nonce = self.account_manager.nonce_manager.get_nonce().await?;

        let outer_header = json!({
            "alg": "EdDSA",
            "kid": account_url,
            "nonce": nonce,
            "url": key_change_url
        });

        // The payload for the outer JWS is the inner JWS object, not string
        // We need to parse the inner JWS string back to JSON or construct it manually
        // But wait, RFC 8555 Section 7.3.5 says:
        // The payload of the outer JWS is the inner JWS.
        // Let's verify the structure.
        // Actually, the payload of the outer JWS is the inner JWS *object*.

        // Let's construct the inner JWS object structure
        let inner_jws_parts: Vec<&str> = inner_jws.split('.').collect();
        let inner_jws_obj = json!({
            "protected": inner_jws_parts[0],
            "payload": inner_jws_parts[1],
            "signature": inner_jws_parts[2]
        });

        let outer_jws = self
            .account_manager
            .get_signer()
            .sign(&outer_header, &inner_jws_obj)?;

        // 5. Send request
        let response = self
            .account_manager
            .http_client
            .post(&key_change_url)
            .header("Content-Type", "application/jose+json")
            .body(outer_jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to change key: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce") {
            if let Ok(nonce_str) = nonce_header.to_str() {
                self.account_manager
                    .nonce_manager
                    .cache_nonce(nonce_str.to_string())
                    .await;
            }
        }

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(crate::error::AcmeError::account(format!(
                "Failed to change key: HTTP {}: {}",
                status, error_text
            )));
        }

        let mut account: Account = response.json().await.map_err(|e| {
            crate::error::AcmeError::account(format!("Failed to parse account response: {}", e))
        })?;

        account.id = account_url.to_string();

        Ok(account)
    }

    /// Get the new key pair
    pub fn new_key_pair(&self) -> &KeyPair {
        &self.new_key_pair
    }
}
