//! `AcmeCaBackend`: the production [`CaBackend`] over an [`AcmeSession`].

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use crate::account::KeyPair;
use crate::domain::{AccountRecord, AccountStatus, KeyAlgorithm, KeyId, KeyRef, TenantId};
use crate::error::{AcmeError, Result};
use crate::repository::RepositorySet;
use crate::types::Identifier;

use super::ari::{ari_cert_id_from_pem, parse_renewal_window, renewal_info_url};
use super::session::{AcmeSession, JwsPayload, SessionAuth};
use super::transport::{AcmeTransport, FakeAcmeTransport};
use super::types::{
    AccountHandle, AccountRef, AuthorizationRef, AuthorizationResource, CaCapabilities, CaId,
    CaProfile, ChallengeRef, IssuedChain, OrderHandle, OrderRequest, OrderResource, RenewalWindow,
    RevocationRequest,
};

/// The port every CA integration goes through (frozen for v0.9).
#[async_trait]
pub trait CaBackend: Send + Sync {
    /// The CA identity.
    fn ca_id(&self) -> &CaId;

    /// Capability discovery from the directory.
    async fn capabilities(&self) -> Result<CaCapabilities>;

    /// Creates or reuses an account; persists the account URL immediately.
    async fn ensure_account(&self, account: &AccountRef) -> Result<AccountHandle>;

    /// Creates an order (or, at the engine level, is skipped when a
    /// persisted handle already exists).
    async fn create_order(
        &self,
        account: &AccountHandle,
        request: &OrderRequest,
    ) -> Result<OrderHandle>;

    /// Fetches an order by handle.
    async fn get_order(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
    ) -> Result<OrderResource>;

    /// Fetches all authorizations of an order.
    async fn get_authorizations(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
    ) -> Result<Vec<AuthorizationResource>>;

    /// Fetches one authorization.
    async fn get_authorization(
        &self,
        account: &AccountHandle,
        authorization: &AuthorizationRef,
    ) -> Result<AuthorizationResource>;

    /// Tells the CA to start validating a challenge.
    async fn acknowledge_challenge(
        &self,
        account: &AccountHandle,
        challenge: &ChallengeRef,
    ) -> Result<()>;

    /// Submits the CSR (finalize).
    async fn finalize(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
        csr_der: &[u8],
    ) -> Result<()>;

    /// Downloads the issued chain once the order is valid.
    async fn download_certificate(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
    ) -> Result<IssuedChain>;

    /// RFC 9773 renewal window; `Ok(None)` when ARI is unavailable or has
    /// no suggestion (callers apply their fallback policy).
    async fn renewal_window(&self, chain_pem: &str) -> Result<Option<RenewalWindow>>;

    /// Revokes a certificate.
    async fn revoke(&self, account: &AccountHandle, request: &RevocationRequest) -> Result<()>;
}

/// ACME (RFC 8555) implementation of [`CaBackend`].
pub struct AcmeCaBackend {
    ca_id: CaId,
    directory_url: String,
    transport: Arc<dyn AcmeTransport>,
    key_pair: Arc<KeyPair>,
    repositories: RepositorySet,
    tenant: TenantId,
    nonce_pool: Arc<super::session::SharedNoncePool>,
    sessions: tokio::sync::RwLock<Vec<(String, Arc<AcmeSession>)>>,
}

impl AcmeCaBackend {
    /// Creates a backend. `key_pair` is the account key; accounts created
    /// here are persisted (URL + key reference) so restarts reuse them.
    pub fn new(
        ca_id: impl Into<String>,
        directory_url: impl Into<String>,
        transport: Arc<dyn AcmeTransport>,
        key_pair: Arc<KeyPair>,
        repositories: RepositorySet,
    ) -> Self {
        Self {
            ca_id: ca_id.into(),
            directory_url: directory_url.into(),
            transport,
            key_pair,
            repositories,
            tenant: TenantId::default_tenant(),
            nonce_pool: Arc::new(super::session::SharedNoncePool::new()),
            sessions: tokio::sync::RwLock::new(Vec::new()),
        }
    }

    /// A test/backend constructor over the fake transport.
    pub fn with_fake_transport(
        ca_id: impl Into<String>,
        directory_url: impl Into<String>,
        fake: Arc<FakeAcmeTransport>,
        key_pair: Arc<KeyPair>,
        repositories: RepositorySet,
    ) -> Self {
        Self::new(ca_id, directory_url, fake, key_pair, repositories)
    }

    fn account_repo_id(&self) -> String {
        AccountRecord::compute_id(&self.tenant, &self.ca_id)
    }

    /// The session bound to an account URL.
    async fn session_for(&self, account_url: &str) -> Result<Arc<AcmeSession>> {
        {
            let sessions = self.sessions.read().await;
            if let Some((_, session)) = sessions.iter().find(|(url, _)| url == account_url) {
                return Ok(Arc::clone(session));
            }
        }
        let session = Arc::new(AcmeSession::with_nonce_pool(
            self.ca_id.clone(),
            self.directory_url.clone(),
            SessionAuth::with_account(Arc::clone(&self.key_pair), account_url),
            Arc::clone(&self.transport),
            Arc::clone(&self.nonce_pool),
        ));
        self.sessions
            .write()
            .await
            .push((account_url.to_string(), Arc::clone(&session)));
        Ok(session)
    }

    /// The key-only session (registration).
    fn registration_session(&self) -> AcmeSession {
        AcmeSession::with_nonce_pool(
            self.ca_id.clone(),
            self.directory_url.clone(),
            SessionAuth::key_only(Arc::clone(&self.key_pair)),
            Arc::clone(&self.transport),
            Arc::clone(&self.nonce_pool),
        )
    }
}

#[async_trait]
impl CaBackend for AcmeCaBackend {
    fn ca_id(&self) -> &CaId {
        &self.ca_id
    }

    async fn capabilities(&self) -> Result<CaCapabilities> {
        let session = self.registration_session();
        let directory = session.directory().await?;
        let profiles = directory
            .profiles
            .as_ref()
            .map(|map| {
                map.keys()
                    .map(|name| CaProfile {
                        name: name.clone(),
                        short_lived: name.contains("shortlived") || name.contains("shortlived"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(CaCapabilities {
            ca_id: self.ca_id.clone(),
            directory_url: self.directory_url.clone(),
            // The ACME directory does not advertise identifier types; leave
            // unknown (DNS-only default) unless metadata says otherwise.
            identifier_types: Vec::new(),
            supports_ari: directory.renewal_info.is_some(),
            profiles,
            requires_eab: directory
                .meta
                .as_ref()
                .and_then(|m| m.external_account_required)
                .unwrap_or(false),
            renewal_info_url: directory.renewal_info.clone(),
            key_change_url: Some(directory.key_change.clone()),
            revoke_cert_url: Some(directory.revoke_cert.clone()),
        })
    }

    async fn ensure_account(&self, account: &AccountRef) -> Result<AccountHandle> {
        let repo_id = self.account_repo_id();
        // Reuse: an account with a persisted URL is never re-registered.
        if let Some(existing) = self.repositories.accounts.get(&repo_id).await? {
            if let Some(url) = existing.value.account_url {
                tracing::debug!(ca = self.ca_id, "reusing persisted ACME account");
                return Ok(AccountHandle {
                    ca_id: self.ca_id.clone(),
                    account_url: url,
                    key_id: existing.value.key_ref.key_id.to_string(),
                });
            }
        }

        let session = self.registration_session();
        let directory = session.directory().await?;
        let mut payload = json!({
            "termsOfServiceAgreed": account.tenant_terms_agreed(&self.tenant),
            "contact": account.contacts,
        });
        if let Some(eab) = &account.external_account_binding
            && let Some(hmac) = account.resolve_eab_hmac(eab)
        {
            let (kid, mac) = eab_protected(&self.key_pair, &eab.key_id);
            payload["externalAccountBinding"] = json!({
                "protected": kid,
                "payload": "",
                "signature": hmac_sign(&mac, &hmac),
            });
            let _ = (&kid, mac);
        }

        let response = session
            .execute_jws(&directory.new_account, JwsPayload::Object(payload))
            .await?;
        let account_url = response
            .location
            .clone()
            .or_else(|| {
                response.json().ok().and_then(|v| {
                    v.get("account")
                        .cloned()
                        .and_then(|a| a.as_str().map(str::to_string))
                })
            })
            .ok_or_else(|| {
                AcmeError::protocol("newAccount response missing Location header".to_string())
            })?;

        // Persist immediately: a restart must reuse, not re-register.
        let key_id = account_key_id(&self.key_pair.public_key_bytes());
        let now = self.repositories.clock.now();
        self.repositories
            .accounts
            .upsert(AccountRecord {
                id: repo_id,
                tenant_id: self.tenant.clone(),
                ca_id: self.ca_id.clone(),
                directory_url: self.directory_url.clone(),
                account_url: Some(account_url.clone()),
                key_ref: KeyRef::software(
                    KeyId::new(key_id.clone()).map_err(AcmeError::from)?,
                    KeyAlgorithm::Ed25519,
                ),
                contacts: account.contacts.clone(),
                eab_bound: account.external_account_binding.is_some(),
                status: AccountStatus::Active,
                created_at: now,
                updated_at: now,
            })
            .await?;

        Ok(AccountHandle {
            ca_id: self.ca_id.clone(),
            account_url,
            key_id: key_id.clone(),
        })
    }

    async fn create_order(
        &self,
        account: &AccountHandle,
        request: &OrderRequest,
    ) -> Result<OrderHandle> {
        let session = self.session_for(&account.account_url).await?;
        let directory = session.directory().await?;

        let mut payload = json!({
            "identifiers": request.identifiers,
        });
        if let Some(not_before) = &request.not_before {
            payload["notBefore"] = json!(not_before);
        }
        if let Some(not_after) = &request.not_after {
            payload["notAfter"] = json!(not_after);
        }
        if let Some(profile) = &request.profile {
            payload["profile"] = json!(profile);
        }
        if let Some(replaces) = &request.replaces {
            payload["replaces"] = json!(replaces);
        }

        let response = session
            .execute_jws(&directory.new_order, JwsPayload::Object(payload))
            .await?;
        let url = response
            .location
            .clone()
            .ok_or_else(|| AcmeError::protocol("newOrder response missing Location".to_string()))?;
        Ok(OrderHandle {
            ca_id: self.ca_id.clone(),
            url,
        })
    }

    async fn get_order(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
    ) -> Result<OrderResource> {
        let session = self.session_for(&account.account_url).await?;
        let value = session.post_as_get(&order.url).await?;
        let order_object: crate::order::Order = serde_json::from_value(value)
            .map_err(|e| AcmeError::protocol(format!("invalid order object: {e}")))?;
        Ok(OrderResource {
            url: order.url.clone(),
            order: order_object,
        })
    }

    async fn get_authorizations(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
    ) -> Result<Vec<AuthorizationResource>> {
        let order_resource = self.get_order(account, order).await?;
        let mut out = Vec::with_capacity(order_resource.order.authorizations.len());
        for url in &order_resource.order.authorizations {
            out.push(
                self.get_authorization(account, &AuthorizationRef { url: url.clone() })
                    .await?,
            );
        }
        Ok(out)
    }

    async fn get_authorization(
        &self,
        account: &AccountHandle,
        authorization: &AuthorizationRef,
    ) -> Result<AuthorizationResource> {
        let session = self.session_for(&account.account_url).await?;
        let value = session.post_as_get(&authorization.url).await?;
        let authorization_object: crate::order::Authorization = serde_json::from_value(value)
            .map_err(|e| AcmeError::protocol(format!("invalid authorization object: {e}")))?;
        Ok(AuthorizationResource {
            url: authorization.url.clone(),
            authorization: authorization_object,
        })
    }

    async fn acknowledge_challenge(
        &self,
        account: &AccountHandle,
        challenge: &ChallengeRef,
    ) -> Result<()> {
        let session = self.session_for(&account.account_url).await?;
        session
            .execute_jws(&challenge.url, JwsPayload::Object(json!({})))
            .await?;
        Ok(())
    }

    async fn finalize(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
        csr_der: &[u8],
    ) -> Result<()> {
        let session = self.session_for(&account.account_url).await?;
        let order_resource = self.get_order(account, order).await?;
        let payload = json!({ "csr": URL_SAFE_NO_PAD.encode(csr_der) });
        session
            .execute_jws(&order_resource.order.finalize, JwsPayload::Object(payload))
            .await?;
        Ok(())
    }

    async fn download_certificate(
        &self,
        account: &AccountHandle,
        order: &OrderHandle,
    ) -> Result<IssuedChain> {
        let order_resource = self.get_order(account, order).await?;
        let certificate_url = order_resource.order.certificate.clone().ok_or_else(|| {
            AcmeError::order(
                "order is not valid".to_string(),
                order_resource.order.status.clone(),
            )
        })?;
        let session = self.session_for(&account.account_url).await?;
        let body = session.post_as_get_bytes(&certificate_url).await?;
        let pem = String::from_utf8(body).map_err(|_| {
            AcmeError::certificate("certificate response was not valid UTF-8 PEM".to_string())
        })?;
        Ok(IssuedChain {
            pem,
            url: certificate_url,
        })
    }

    async fn renewal_window(&self, chain_pem: &str) -> Result<Option<RenewalWindow>> {
        let session = self.registration_session();
        let directory = session.directory().await?;
        let Some(base) = directory.renewal_info else {
            // ARI not advertised: not an error, callers fall back.
            return Ok(None);
        };
        let cert_id = ari_cert_id_from_pem(chain_pem)?;
        let url = renewal_info_url(&base, &cert_id);
        let response = session.plain_get(&url).await?;
        parse_renewal_window(&response.body, response.retry_after)
    }

    async fn revoke(&self, account: &AccountHandle, request: &RevocationRequest) -> Result<()> {
        let session = self.session_for(&account.account_url).await?;
        let directory = session.directory().await?;
        let payload = json!({
            "certificate": URL_SAFE_NO_PAD.encode(&request.certificate_der),
            "reason": request.reason.as_u8(),
        });
        session
            .execute_jws(&directory.revoke_cert, JwsPayload::Object(payload))
            .await?;
        Ok(())
    }
}

impl AccountRef {
    fn tenant_terms_agreed(&self, _tenant: &TenantId) -> bool {
        self.terms_of_service_agreed
    }

    fn resolve_eab_hmac(&self, _eab: &super::types::ExternalAccountBindingRef) -> Option<Vec<u8>> {
        // Secret resolution is centralized in T11's SecretResolver; until
        // then EAB HMAC values are supplied by callers out-of-band and this
        // returns None so no credential is embedded here.
        None
    }
}

/// Deterministic account key id from the public key bytes.
pub fn account_key_id(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    format!("key_acct_{}", &hex::encode(hasher.finalize())[..16])
}

fn eab_protected(_key: &KeyPair, _kid: &str) -> (String, Vec<u8>) {
    (String::new(), Vec::new())
}

fn hmac_sign(_mac: &[u8], _data: &[u8]) -> String {
    String::new()
}

/// Converts domain identifiers to wire identifiers (type/value maps).
pub fn identifiers_to_wire(identifiers: &[Identifier]) -> Vec<serde_json::Value> {
    identifiers
        .iter()
        .map(|id| json!({"type": id.acme_type(), "value": id.acme_value()}))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_key_id_is_deterministic() {
        let a = account_key_id(b"public-key-bytes");
        let b = account_key_id(b"public-key-bytes");
        let c = account_key_id(b"other");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("key_acct_"));
    }
}
