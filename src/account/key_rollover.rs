/// Account Key Rollover implementation.
/// This module handles the process of changing the cryptographic key pair
/// associated with an ACME account (RFC 8555 Section 7.3.5).
use crate::account::{Account, AccountManager, KeyPair};
use crate::ca_backend::{AcmeSession, JwsPayload, ReqwestAcmeTransport, SessionAuth};
use crate::error::Result;
use std::sync::Arc;

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
        let key_change_url = directory.key_change.clone();

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

        // 3. Delegate the outer JWS to the production session. The legacy
        // facade's public constructor lends us the old key, while sessions
        // own an Arc; reparse a private in-memory copy solely for this
        // request. This keeps the frozen facade API intact while giving this
        // RFC 8555 request the canonical nonce, badNonce and status handling.
        let inner_object: serde_json::Value = serde_json::from_str(&inner_jws_obj)
            .map_err(|e| crate::error::AcmeError::protocol(format!("inner key-change JWS: {e}")))?;
        let old_key = KeyPair::from_pem(&self.account_manager.key_pair.serialize_pem())?;
        let session = AcmeSession::new(
            "legacy-acmeclient",
            self.account_manager.directory_manager.url(),
            SessionAuth::with_account(Arc::new(old_key), account_url),
            Arc::new(ReqwestAcmeTransport::with_client(
                self.account_manager.http_client.clone(),
            )),
        );
        session.prime_directory(directory).await;

        tracing::info!("Sending keyChange request through the shared ACME session");
        let response = session
            .execute_jws(&key_change_url, JwsPayload::Object(inner_object))
            .await?;
        let mut account: Account = serde_json::from_slice(&response.body).map_err(|e| {
            tracing::error!("Failed to parse account response after key rollover: {e}");
            crate::error::AcmeError::account(format!("Failed to parse account response: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DirectoryManager, NonceManager};
    use mockito::Server;

    fn directory_body(server: &mockito::ServerGuard) -> String {
        serde_json::json!({
            "newNonce": format!("{}/new-nonce", server.url()),
            "newAccount": format!("{}/new-account", server.url()),
            "newOrder": format!("{}/new-order", server.url()),
            "revokeCert": format!("{}/revoke-cert", server.url()),
            "keyChange": format!("{}/key-change", server.url()),
        })
        .to_string()
    }

    #[tokio::test]
    async fn legacy_rollover_retries_bad_nonce_through_shared_session() {
        let mut server = Server::new_async().await;
        let directory = server
            .mock("GET", "/directory")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(directory_body(&server))
            .expect(1)
            .create_async()
            .await;
        let nonce = server
            .mock("HEAD", "/new-nonce")
            .with_status(200)
            .with_header("Replay-Nonce", "initial-nonce")
            .expect(1)
            .create_async()
            .await;
        let rejected = server
            .mock("POST", "/key-change")
            .with_status(400)
            .with_header("content-type", "application/problem+json")
            .with_header("Replay-Nonce", "replacement-nonce")
            .with_body(r#"{"type":"urn:ietf:params:acme:error:badNonce"}"#)
            .expect(1)
            .create_async()
            .await;
        let accepted = server
            .mock("POST", "/key-change")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("Replay-Nonce", "next-nonce")
            .with_body(r#"{"status":"valid","contact":[]}"#)
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::new();
        let directory_manager =
            DirectoryManager::new(format!("{}/directory", server.url()), http_client.clone());
        let acme_directory = directory_manager.get().await.expect("directory");
        let nonce_manager = NonceManager::new(&acme_directory.new_nonce, http_client.clone());
        let old_key = KeyPair::generate().expect("old account key");
        let account_manager =
            AccountManager::new(&old_key, &nonce_manager, &directory_manager, &http_client)
                .expect("account manager");
        let rollover = KeyRollover::with_new_key(
            &account_manager,
            KeyPair::generate().expect("new account key"),
        );

        let account = rollover
            .execute(&format!("{}/account/1", server.url()))
            .await
            .expect("shared session retries badNonce");

        assert_eq!(account.id, format!("{}/account/1", server.url()));
        directory.assert_async().await;
        nonce.assert_async().await;
        rejected.assert_async().await;
        accepted.assert_async().await;
    }

    #[tokio::test]
    async fn legacy_rollover_uses_shared_rate_limit_classification() {
        let mut server = Server::new_async().await;
        let _directory = server
            .mock("GET", "/directory")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(directory_body(&server))
            .expect(1)
            .create_async()
            .await;
        let _nonce = server
            .mock("HEAD", "/new-nonce")
            .with_status(200)
            .with_header("Replay-Nonce", "initial-nonce")
            .expect(1)
            .create_async()
            .await;
        let rate_limited = server
            .mock("POST", "/key-change")
            .with_status(429)
            .with_header("content-type", "application/problem+json")
            .with_header("Retry-After", "30")
            .with_body(r#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"slow down"}"#)
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::new();
        let directory_manager =
            DirectoryManager::new(format!("{}/directory", server.url()), http_client.clone());
        let acme_directory = directory_manager.get().await.expect("directory");
        let nonce_manager = NonceManager::new(&acme_directory.new_nonce, http_client.clone());
        let old_key = KeyPair::generate().expect("old account key");
        let account_manager =
            AccountManager::new(&old_key, &nonce_manager, &directory_manager, &http_client)
                .expect("account manager");
        let rollover = KeyRollover::with_new_key(
            &account_manager,
            KeyPair::generate().expect("new account key"),
        );

        let error = rollover
            .execute(&format!("{}/account/1", server.url()))
            .await
            .expect_err("rate limit must not be downgraded to a legacy account error");

        assert!(
            error.to_string().contains("ACME_RATE_LIMITED"),
            "unexpected rollover error: {error}"
        );
        rate_limited.assert_async().await;
    }
}
