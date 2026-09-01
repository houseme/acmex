//! `AcmeSession`: one reusable CA session (directory + nonce + signer +
//! transport) with a single JWS execution path.
//!
//! Every ACME request — POST and POST-as-GET — goes through
//! [`AcmeSession::execute_jws`], which handles:
//!
//! * JWS protected headers (`alg`, `nonce`, `url`, `kid`/`jwk`);
//! * canonical POST-as-GET encoding (empty payload, `""`);
//! * Replay-Nonce capture from **every** response;
//! * `badNonce` recovery with a bounded internal retry that never
//!   propagates to the workflow layer (and never re-creates orders);
//! * problem documents and `Retry-After` classification via the transport
//!   helpers.

use std::collections::VecDeque;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use tokio::sync::{Mutex, RwLock};

use crate::account::KeyPair;
use crate::domain::error_codes;
use crate::error::{AcmeError, Result};
use crate::protocol::{Directory, Jwk, JwsSigner};

use super::transport::{AcmeMethod, AcmeRequest, AcmeResponse, AcmeTransport, classify_response};

/// How many times a badNonce is retried internally before surfacing.
const BAD_NONCE_MAX_RETRIES: usize = 3;

/// What the session signs with and how it addresses the account.
#[derive(Clone)]
pub struct SessionAuth {
    /// The account key.
    pub key_pair: Arc<KeyPair>,
    /// The ACME account URL (`kid`); `None` only for initial registration.
    pub account_url: Option<String>,
}

impl SessionAuth {
    /// Account-bound authentication.
    pub fn with_account(key_pair: Arc<KeyPair>, account_url: impl Into<String>) -> Self {
        Self {
            key_pair,
            account_url: Some(account_url.into()),
        }
    }

    /// JWK-only authentication (newAccount).
    pub fn key_only(key_pair: Arc<KeyPair>) -> Self {
        Self {
            key_pair,
            account_url: None,
        }
    }
}

/// Request payload variants for [`AcmeSession::execute_jws`].
pub enum JwsPayload {
    /// A JSON object payload.
    Object(Value),
    /// POST-as-GET: no payload (encoded as empty string).
    Empty,
}

/// A shared nonce pool: nonces captured from any response serve any
/// subsequent request through the same transport, regardless of which
/// session (registration vs. account-bound) issued it.
#[derive(Default)]
pub struct SharedNoncePool {
    nonces: Mutex<VecDeque<String>>,
}

impl SharedNoncePool {
    /// An empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a captured nonce (bounded).
    pub async fn capture(&self, nonce: &str) {
        let mut pool = self.nonces.lock().await;
        if pool.len() < 16 {
            pool.push_back(nonce.to_string());
        }
    }

    /// Takes a nonce, if any.
    pub async fn take(&self) -> Option<String> {
        self.nonces.lock().await.pop_front()
    }
}

/// A reusable ACME session bound to one CA, account key and transport.
pub struct AcmeSession {
    ca_id: String,
    directory_url: String,
    auth: SessionAuth,
    transport: Arc<dyn AcmeTransport>,
    directory: RwLock<Option<Directory>>,
    nonces: Arc<SharedNoncePool>,
}

impl AcmeSession {
    /// Creates a session with its own nonce pool.
    pub fn new(
        ca_id: impl Into<String>,
        directory_url: impl Into<String>,
        auth: SessionAuth,
        transport: Arc<dyn AcmeTransport>,
    ) -> Self {
        Self::with_nonce_pool(
            ca_id,
            directory_url,
            auth,
            transport,
            Arc::new(SharedNoncePool::new()),
        )
    }

    /// Creates a session sharing a nonce pool with sibling sessions.
    pub fn with_nonce_pool(
        ca_id: impl Into<String>,
        directory_url: impl Into<String>,
        auth: SessionAuth,
        transport: Arc<dyn AcmeTransport>,
        nonces: Arc<SharedNoncePool>,
    ) -> Self {
        Self {
            ca_id: ca_id.into(),
            directory_url: directory_url.into(),
            auth,
            transport,
            directory: RwLock::new(None),
            nonces,
        }
    }

    /// The session's CA identity.
    pub fn ca_id(&self) -> &str {
        &self.ca_id
    }

    /// The account URL, when bound.
    pub fn account_url(&self) -> Option<&str> {
        self.auth.account_url.as_deref()
    }

    /// Returns the (cached) directory, refreshing when absent.
    pub async fn directory(&self) -> Result<Directory> {
        if let Some(directory) = self.directory.read().await.clone() {
            return Ok(directory);
        }
        let response = self
            .transport
            .request(AcmeRequest {
                url: self.directory_url.clone(),
                method: AcmeMethod::Get,
                body: None,
            })
            .await?;
        let directory: Directory = serde_json::from_slice(&response.body)
            .map_err(|e| AcmeError::protocol(format!("invalid directory document: {e}")))?;
        *self.directory.write().await = Some(directory.clone());
        Ok(directory)
    }

    /// Drops the cached directory (e.g. after repeated endpoint errors).
    pub async fn invalidate_directory(&self) {
        *self.directory.write().await = None;
    }

    /// The JWK for the account key (Ed25519).
    fn jwk(&self) -> Jwk {
        Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(self.auth.key_pair.public_key_bytes()))
    }

    async fn capture_nonce(&self, response: &AcmeResponse) {
        if let Some(nonce) = &response.replay_nonce {
            self.nonces.capture(nonce).await;
        }
    }

    /// Fetches a fresh nonce from the newNonce endpoint.
    async fn fetch_nonce(&self, new_nonce_url: &str) -> Result<String> {
        let response = self
            .transport
            .request(AcmeRequest {
                url: new_nonce_url.to_string(),
                method: AcmeMethod::Head,
                body: None,
            })
            .await?;
        match response.replay_nonce {
            Some(nonce) => Ok(nonce),
            None => Err(AcmeError::protocol(
                "newNonce response did not carry a Replay-Nonce header".to_string(),
            )),
        }
    }

    /// Takes a nonce from the shared pool or fetches a new one.
    async fn next_nonce(&self) -> Result<String> {
        if let Some(nonce) = self.nonces.take().await {
            return Ok(nonce);
        }
        let directory = self.directory().await?;
        self.fetch_nonce(&directory.new_nonce).await
    }

    /// The single JWS execution path for all ACME requests.
    ///
    /// badNonce is retried internally (bounded); the workflow layer never
    /// sees it, and never re-creates orders because of it.
    pub async fn execute_jws(&self, endpoint: &str, payload: JwsPayload) -> Result<AcmeResponse> {
        let mut bad_nonce_attempts = 0;
        loop {
            let nonce = self.next_nonce().await?;
            let header = match &self.auth.account_url {
                Some(kid) => json!({
                    "alg": "EdDSA",
                    "kid": kid,
                    "nonce": nonce,
                    "url": endpoint,
                }),
                None => json!({
                    "alg": "EdDSA",
                    "jwk": self.jwk().to_value(),
                    "nonce": nonce,
                    "url": endpoint,
                }),
            };
            let body = match &payload {
                JwsPayload::Object(value) => value.clone(),
                JwsPayload::Empty => Value::Null,
            };
            let jws = {
                let signer = JwsSigner::new(&self.auth.key_pair.0);
                signer.sign(&header, &body)?
            };

            let response = self
                .transport
                .request(AcmeRequest {
                    url: endpoint.to_string(),
                    method: AcmeMethod::Post,
                    body: Some(jws.into_bytes()),
                })
                .await?;

            self.capture_nonce(&response).await;

            if response.is_bad_nonce() {
                bad_nonce_attempts += 1;
                if bad_nonce_attempts > BAD_NONCE_MAX_RETRIES {
                    return Err(AcmeError::protocol(format!(
                        "[{}] ACME_BAD_NONCE_EXHAUSTED: server kept rejecting nonces after {BAD_NONCE_MAX_RETRIES} retries",
                        error_codes::ACME_BAD_NONCE_EXHAUSTED.as_str(),
                    )));
                }
                tracing::debug!(
                    ca = self.ca_id,
                    endpoint,
                    attempt = bad_nonce_attempts,
                    "badNonce; retrying with the response nonce"
                );
                continue;
            }

            return classify_response(&response).map(|_| response);
        }
    }

    /// POST-as-GET: fetch a resource with an empty (canonical `""`) payload.
    pub async fn post_as_get(&self, url: &str) -> Result<Value> {
        let response = self.execute_jws(url, JwsPayload::Empty).await?;
        response.json()
    }

    /// POST-as-GET returning raw bytes (certificate download).
    pub async fn post_as_get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let response = self.execute_jws(url, JwsPayload::Empty).await?;
        Ok(response.body)
    }

    /// Unauthenticated GET (ARI, directory).
    pub async fn plain_get(&self, url: &str) -> Result<AcmeResponse> {
        let response = self
            .transport
            .request(AcmeRequest {
                url: url.to_string(),
                method: AcmeMethod::Get,
                body: None,
            })
            .await?;
        classify_response(&response).map(|_| response)
    }
}
