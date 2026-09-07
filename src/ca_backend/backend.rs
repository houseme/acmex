//! `AcmeCaBackend`: the production [`CaBackend`] over an [`AcmeSession`].

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use crate::account::KeyPair;
use crate::crypto::keypair::KeyType;
use crate::dns::spec::{EnvFileSecretResolver, SecretResolver};
use crate::domain::{AccountRecord, AccountStatus, KeyAlgorithm, KeyId, KeyRef, TenantId};
use crate::error::{AcmeError, Result};
use crate::protocol::{Jwk, JwsSigner};
use crate::repository::RepositorySet;
use crate::types::Identifier;

use super::ari::{ari_cert_id_from_pem, parse_renewal_window, renewal_info_url};
use super::session::{AcmeSession, JwsPayload, SessionAuth};
use super::transport::{AcmeTransport, FakeAcmeTransport};
use super::types::{
    AccountHandle, AccountRef, AuthorizationRef, AuthorizationResource, CaCapabilities, CaId,
    CaProfile, ChallengeRef, ExternalAccountBindingRef, IssuedChain, OrderHandle, OrderRequest,
    OrderResource, RenewalWindow, RevocationRequest,
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

    /// RFC 8555 §7.3.5 account key rollover — the documented T04 extension
    /// to the otherwise-frozen v0.9 trait.
    ///
    /// Sends the endpoint's double JWS: the outer JWS is signed by the
    /// current account key (`kid` = account URL, `url` = the directory
    /// keyChange endpoint) and carries an inner JWS signed by `new_key`
    /// (`jwk` header, `{account, oldKey}` payload). On success the switch
    /// is atomic and durable: the persisted account record's key
    /// reference, this backend's signing key and every cached session for
    /// the account URL move to `new_key` together, so the next request —
    /// and, after a restart, the first request — signs with the new key.
    ///
    /// # Failure invariant (no partial switch)
    ///
    /// On failure — transport error, non-2xx keyChange response or a
    /// persistence error — nothing changes: the old key keeps signing,
    /// the session cache stays intact and the stored account record still
    /// references the old key.
    async fn roll_account_key(
        &self,
        account: &AccountHandle,
        new_key: Arc<crate::account::KeyPair>,
    ) -> Result<()>;

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

    /// The JWK of the backend's *current* account key (RFC 7638), the re-sync
    /// source for the validation pipeline's key-authorization thumbprint.
    ///
    /// A rollover performed inside this process refreshes the pipeline's
    /// [`AccountJwkHandle`] directly; this method covers every other path —
    /// the key was changed out of band (another process, or before this
    /// worker assembled) — by letting `EnsureAccountStep` compare and
    /// re-publish before any key authorization is computed.
    ///
    /// The default reports a configuration error: backends that cannot
    /// expose their account key simply never trigger the re-sync. A
    /// default-implemented method keeps the frozen v0.9 trait
    /// source-compatible.
    async fn current_account_jwk(&self) -> Result<Jwk> {
        let _ = self;
        Err(AcmeError::configuration(
            "this CA backend does not expose its current account JWK",
        ))
    }
}

/// Shared, refreshable view of the account key's JWK.
///
/// The validation pipeline derives key authorizations (`token.thumbprint`,
/// RFC 8555 §8.1) from this JWK. It is deliberately a handle, not a startup
/// snapshot: an RFC 8555 §7.3.5 account key rollover changes the thumbprint,
/// and a pipeline computing key authorizations from the old JWK would fail
/// CA validation forever (review P3-6). The owning [`AcmeCaBackend`]
/// publishes the new key's JWK through the attached handle when its
/// rollover completes, and `EnsureAccountStep` re-syncs it from
/// [`CaBackend::current_account_jwk`] on every issuance. Cloning shares one
/// underlying slot.
///
/// The interior lock is a `std::sync::RwLock` whose critical sections never
/// await, so the handle is safe to read and write from async code.
#[derive(Clone)]
pub struct AccountJwkHandle {
    jwk: Arc<std::sync::RwLock<Jwk>>,
}

impl AccountJwkHandle {
    /// Pins the JWK of the account key current at assembly time.
    pub fn new(jwk: Jwk) -> Self {
        Self {
            jwk: Arc::new(std::sync::RwLock::new(jwk)),
        }
    }

    /// The current account JWK (cloned out; the lock is never held across
    /// an await).
    pub fn get(&self) -> Jwk {
        self.jwk
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Publishes the JWK of the new current account key (rollover refresh).
    pub fn set(&self, jwk: Jwk) {
        *self
            .jwk
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = jwk;
    }

    /// The RFC 7638 thumbprint of the current account JWK.
    pub fn thumbprint_sha256(&self) -> Result<String> {
        self.get().thumbprint_sha256()
    }
}

/// ACME (RFC 8555) implementation of [`CaBackend`].
pub struct AcmeCaBackend {
    ca_id: CaId,
    directory_url: String,
    transport: Arc<dyn AcmeTransport>,
    /// The account signing key. Behind a lock because a successful key
    /// rollover (RFC 8555 §7.3.5) swaps it atomically with the session
    /// cache. Always cloned out (never held across another lock): rollover
    /// acquires this lock first, then the session-cache lock.
    key_pair: tokio::sync::RwLock<Arc<KeyPair>>,
    /// The pipeline's account-JWK handle when attached
    /// ([`attach_jwk_handle`](Self::attach_jwk_handle)); refreshed after a
    /// successful rollover so key authorizations use the new thumbprint.
    /// A std lock taken outside the `key_pair`/`sessions` locks, and its
    /// critical sections never await.
    jwk_handle: std::sync::RwLock<Option<AccountJwkHandle>>,
    repositories: RepositorySet,
    tenant: TenantId,
    secrets: Arc<dyn SecretResolver>,
    nonce_pool: Arc<super::session::SharedNoncePool>,
    sessions: tokio::sync::RwLock<Vec<(String, Arc<AcmeSession>)>>,
    /// Deployment-declared identifier types the CA accepts (`dns`, `ip`, ...).
    /// The ACME directory has no field to advertise these, so the default is
    /// empty (DNS-only); deployments targeting an RFC 8738-capable CA declare
    /// the extra types via
    /// [`with_identifier_types`](Self::with_identifier_types).
    identifier_types: Vec<String>,
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
            key_pair: tokio::sync::RwLock::new(key_pair),
            jwk_handle: std::sync::RwLock::new(None),
            repositories,
            tenant: TenantId::default_tenant(),
            secrets: Arc::new(EnvFileSecretResolver),
            nonce_pool: Arc::new(super::session::SharedNoncePool::new()),
            sessions: tokio::sync::RwLock::new(Vec::new()),
            identifier_types: Vec::new(),
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

    /// Uses a deployment-provided secret resolver for EAB credentials.
    pub fn with_secret_resolver(mut self, secrets: Arc<dyn SecretResolver>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Declares the identifier types this CA accepts (`dns`, `ip`, ...).
    ///
    /// The ACME directory (RFC 8555 §7.1.1) has no field advertising
    /// identifier types, so [`capabilities`](CaBackend::capabilities) cannot
    /// discover them. Without a declaration the pipeline treats the CA as
    /// DNS-only and rejects IP-identifier orders (RFC 8738) as a policy
    /// violation before any order is created — deployments targeting an
    /// IP-capable CA (Pebble, or public CAs with RFC 8738 support) declare
    /// the capability here so the pre-order gate passes.
    pub fn with_identifier_types(mut self, identifier_types: Vec<String>) -> Self {
        self.identifier_types = identifier_types;
        self
    }

    /// Attaches the validation pipeline's account-JWK handle. After a
    /// successful [`roll_account_key`](CaBackend::roll_account_key) the
    /// backend publishes the new key's JWK through it, so every key
    /// authorization computed afterwards uses the new thumbprint.
    pub fn attach_jwk_handle(&self, handle: AccountJwkHandle) {
        *self
            .jwk_handle
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
    }

    /// Publishes `jwk` as the current account JWK on the attached handle
    /// (no-op without one). Called after the rollover's in-memory switch,
    /// outside both the `key_pair` and `sessions` locks; the std critical
    /// section never awaits.
    fn publish_account_jwk(&self, jwk: Jwk) {
        if let Some(handle) = self
            .jwk_handle
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            handle.set(jwk);
        }
    }

    fn account_repo_id(&self) -> String {
        AccountRecord::compute_id(&self.tenant, &self.ca_id)
    }

    /// The current account key. The read lock is held only for the clone
    /// (never across another lock or await), so rollover can swap the key
    /// under the write lock without deadlocking session creation.
    async fn current_key(&self) -> Arc<KeyPair> {
        Arc::clone(&*self.key_pair.read().await)
    }

    /// The session bound to an account URL.
    async fn session_for(&self, account_url: &str) -> Result<Arc<AcmeSession>> {
        {
            let sessions = self.sessions.read().await;
            if let Some((_, session)) = sessions.iter().find(|(url, _)| url == account_url) {
                return Ok(Arc::clone(session));
            }
        }
        // Clone the key and release its lock before taking the sessions
        // write lock: the rollover switch nests both locks (key_pair, then
        // sessions), and this is the only other place either is taken.
        let key_pair = self.current_key().await;
        let session = Arc::new(AcmeSession::with_nonce_pool(
            self.ca_id.clone(),
            self.directory_url.clone(),
            SessionAuth::with_account(key_pair, account_url),
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
    async fn registration_session(&self) -> AcmeSession {
        AcmeSession::with_nonce_pool(
            self.ca_id.clone(),
            self.directory_url.clone(),
            SessionAuth::key_only(self.current_key().await),
            Arc::clone(&self.transport),
            Arc::clone(&self.nonce_pool),
        )
    }

    /// Builds the RFC 8555 §7.3.4 `externalAccountBinding` JWS for a
    /// newAccount request.
    ///
    /// The MAC key is resolved from its [`SecretRef`](crate::dns::spec::SecretRef)
    /// via the built-in env/file resolver and must be base64url-encoded (the
    /// form CAs hand out). It exists only in memory here; errors and logs
    /// mention the reference description, never the key value.
    async fn external_account_binding_jws(
        &self,
        eab: &ExternalAccountBindingRef,
        new_account_url: &str,
    ) -> Result<serde_json::Value> {
        tracing::debug!(
            ca = self.ca_id,
            eab = eab.redacted(),
            "binding external account"
        );
        let secret = self.secrets.resolve(&eab.hmac_key).await.map_err(|err| {
            AcmeError::configuration(format!(
                "cannot resolve EAB MAC key for CA {}: {err}",
                self.ca_id
            ))
        })?;
        let mac_key = URL_SAFE_NO_PAD.decode(secret.expose()).map_err(|_| {
            AcmeError::configuration(format!(
                "EAB MAC key {} is not valid base64url; CAs issue base64url-encoded MAC keys",
                eab.hmac_key.describe()
            ))
        })?;
        let account_jwk = Jwk::for_key_pair(&self.current_key().await.0)?;
        eab_binding_jws(
            &account_jwk.to_value(),
            &eab.key_id,
            new_account_url,
            &mac_key,
        )
    }
}

#[async_trait]
impl CaBackend for AcmeCaBackend {
    fn ca_id(&self) -> &CaId {
        &self.ca_id
    }

    async fn capabilities(&self) -> Result<CaCapabilities> {
        let session = self.registration_session().await;
        let directory = session.directory().await?;
        let profiles = directory
            .profiles
            .as_ref()
            .map(|map| {
                map.keys()
                    .map(|name| CaProfile {
                        name: name.clone(),
                        short_lived: name.contains("shortlived")
                            || name.contains("short-lived")
                            || name.contains("short_lived"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(CaCapabilities {
            ca_id: self.ca_id.clone(),
            directory_url: self.directory_url.clone(),
            // The ACME directory does not advertise identifier types; the
            // deployment-declared set (with_identifier_types) is authoritative
            // and stays empty (DNS-only default) when not declared.
            identifier_types: self.identifier_types.clone(),
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
        if let Some(existing) = self.repositories.accounts.get(&repo_id).await?
            && let Some(url) = existing.value.account_url
        {
            tracing::debug!(ca = self.ca_id, "reusing persisted ACME account");
            return Ok(AccountHandle {
                ca_id: self.ca_id.clone(),
                account_url: url,
                key_id: existing.value.key_ref.key_id.to_string(),
            });
        }

        let session = self.registration_session().await;
        let directory = session.directory().await?;
        let mut payload = json!({
            "termsOfServiceAgreed": account.tenant_terms_agreed(&self.tenant),
            "contact": account.contacts,
        });
        // RFC 8555 §7.3.4: when the CA requires EAB, newAccount carries a
        // detached HS256 JWS binding the account key to the CA-issued
        // external key. Without an EAB reference registration proceeds
        // unbound (CAs that do not require EAB).
        if let Some(eab) = &account.external_account_binding {
            payload["externalAccountBinding"] = self
                .external_account_binding_jws(eab, &directory.new_account)
                .await?;
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
        let key_id = account_key_id(&self.current_key().await.public_key_bytes());
        let now = self.repositories.clock.now();
        let current_key = self.current_key().await;
        self.repositories
            .accounts
            .upsert(AccountRecord {
                id: repo_id,
                tenant_id: self.tenant.clone(),
                ca_id: self.ca_id.clone(),
                directory_url: self.directory_url.clone(),
                account_url: Some(account_url.clone()),
                key_ref: KeyRef::software(
                    KeyId::new(key_id.clone())?,
                    domain_key_algorithm(&current_key)?,
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

    async fn roll_account_key(&self, account: &AccountHandle, new_key: Arc<KeyPair>) -> Result<()> {
        tracing::info!(
            ca = self.ca_id,
            account = account.account_url,
            "rolling account key (RFC 8555 §7.3.5)"
        );
        // The rollover target must be a persisted account: the stored
        // record is updated with the new key reference below, mirroring
        // `ensure_account` persistence.
        let repo_id = self.account_repo_id();
        let existing = self
            .repositories
            .accounts
            .get(&repo_id)
            .await?
            .ok_or_else(|| {
                AcmeError::account(format!(
                    "cannot roll the key of account {repo_id}: no persisted record"
                ))
            })?;

        // Both the outer JWS and the pre-switch sessions must still use the
        // old key; clone it before anything can swap it.
        let old_key = self.current_key().await;
        let session = self.session_for(&account.account_url).await?;
        let directory = session.directory().await?;
        let key_change_url = directory.key_change.clone();

        // Inner JWS (RFC 8555 §7.3.5): shared with the legacy facade so the
        // nested signature semantics have one implementation while the outer
        // request still goes through the session for nonce/error handling.
        let old_jwk = Jwk::for_key_pair(&old_key.0)?;
        // The pipeline refresh target, derived before anything can switch:
        // a JWK derivation failure must abort before the keyChange request,
        // never leave a half-refreshed pipeline behind.
        let new_account_jwk = Jwk::for_key_pair(&new_key.0)?;
        let inner_jws =
            key_change_inner_jws(&account.account_url, &key_change_url, &old_jwk, &new_key)?;

        // Outer JWS: the ordinary account-authenticated request path signs
        // it with the OLD key (kid = account URL, url = keyChange) — nonce
        // handling, badNonce recovery, Replay-Nonce capture and status
        // classification included. Its payload IS the inner JWS object
        // (verified against Let's Encrypt staging: a JSON-string wrapping
        // is rejected with "payload did not parse as JSON").
        let inner_object: serde_json::Value = serde_json::from_str(&inner_jws)
            .map_err(|e| AcmeError::protocol(format!("inner key-change JWS: {e}")))?;
        session
            .execute_jws(&key_change_url, JwsPayload::Object(inner_object))
            .await?;

        // ---- keyChange accepted: switch everything to the new key. ----
        // Durable state first: the stored record now references the new key
        // so a restart resumes with it. On persistence failure nothing
        // in-memory has switched yet — the old key keeps signing and the
        // error surfaces (no partial switch).
        let key_id = account_key_id(&new_key.public_key_bytes());
        let now = self.repositories.clock.now();
        let mut record = existing.value;
        record.key_ref = KeyRef::software(KeyId::new(key_id)?, domain_key_algorithm(&new_key)?);
        record.updated_at = now;
        self.repositories.accounts.upsert(record).await?;

        // Atomic in-memory switch: swap the signing key and evict every
        // cached session for this account URL. Cached sessions hold a clone
        // of the old key, so eviction forces the next request to build a
        // session — and sign — with the new key. Both locks are held only
        // here, nested in the documented order (key_pair first, then
        // sessions); session creation releases the key lock before locking
        // the cache.
        {
            *self.key_pair.write().await = Arc::clone(&new_key);
            let mut sessions = self.sessions.write().await;
            sessions.retain(|(url, _)| url != &account.account_url);
        }

        // Last, outside both backend locks: the pipeline's account-JWK
        // handle moves to the new thumbprint, so the next key
        // authorization (`token.thumbprint`) is computed from the key the
        // CA now holds (review P3-6).
        self.publish_account_jwk(new_account_jwk);

        tracing::info!(
            ca = self.ca_id,
            account = account.account_url,
            "account key rolled over"
        );
        Ok(())
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
        let session = self.registration_session().await;
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

    async fn current_account_jwk(&self) -> Result<Jwk> {
        Jwk::for_key_pair(&self.current_key().await.0)
    }
}

impl AccountRef {
    fn tenant_terms_agreed(&self, _tenant: &TenantId) -> bool {
        self.terms_of_service_agreed
    }
}

/// Deterministic account key id from the public key bytes.
pub fn account_key_id(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    format!("key_acct_{}", &hex::encode(hasher.finalize())[..16])
}

/// The domain key algorithm recorded for an account key in the persisted
/// [`AccountRecord`]. The key id already derives from the public key bytes
/// (type-agnostic); this mapping only fixes the informational algorithm
/// label. Metadata only, never a protocol input: JWS signing always derives
/// the algorithm from the actual key.
fn domain_key_algorithm(key: &KeyPair) -> Result<KeyAlgorithm> {
    let key_type = KeyType::for_key_pair(&key.0)?;
    Ok(match key_type {
        KeyType::Ed25519 => KeyAlgorithm::Ed25519,
        KeyType::EcdsaP256 => KeyAlgorithm::EcP256,
        KeyType::EcdsaP384 => KeyAlgorithm::EcP384,
        KeyType::EcdsaP521 => KeyAlgorithm::EcP521,
        KeyType::Rsa2048 => KeyAlgorithm::Rsa2048,
        KeyType::Rsa4096 => KeyAlgorithm::Rsa4096,
    })
}

/// Builds the RFC 8555 §7.3.4 `externalAccountBinding` JWS: the protected
/// header carries `HS256`, the CA-assigned EAB `kid` and the newAccount
/// URL; the payload is the account key's JWK (the thumbprint input); the
/// signature is HMAC-SHA256 over `<protected>.<payload>` with the CA-issued
/// MAC key. All segments are base64url, compact serialization.
fn eab_binding_jws(
    account_jwk: &serde_json::Value,
    kid: &str,
    new_account_url: &str,
    mac_key: &[u8],
) -> Result<serde_json::Value> {
    let protected = json!({
        "alg": "HS256",
        "kid": kid,
        "url": new_account_url,
    });
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(account_jwk.to_string());
    let signature = hmac_sha256(mac_key, format!("{protected_b64}.{payload_b64}").as_bytes())?;
    Ok(json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": URL_SAFE_NO_PAD.encode(signature),
    }))
}

/// Builds the inner RFC 8555 §7.3.5 keyChange JWS object.
///
/// This is shared by the production `ca_backend` path and the legacy
/// `AccountManager` facade, so the double-JWS core cannot drift between
/// stacks while the old public API remains available. Both the inner JWK and
/// the inner `alg` derive from the NEW key, whatever its type.
pub(crate) fn key_change_inner_jws(
    account_url: &str,
    key_change_url: &str,
    old_jwk: &Jwk,
    new_key: &KeyPair,
) -> Result<String> {
    let new_jwk = Jwk::for_key_pair(&new_key.0)?;
    let inner_alg = KeyType::for_key_pair(&new_key.0)?.jwa_algorithm();
    let inner_header = json!({
        "alg": inner_alg,
        "jwk": new_jwk.to_value(),
        "url": key_change_url,
    });
    let inner_payload = json!({
        "account": account_url,
        "oldKey": old_jwk.to_value(),
    });
    // RFC 8555 §7.3.5: the outer payload is the inner flattened JWS,
    // carried as a JSON string.
    JwsSigner::new(&new_key.0).sign(&inner_header, &inner_payload)
}

/// HMAC-SHA256, the only symmetric ACME signature (EAB, RFC 8555 §7.3.4).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| AcmeError::crypto(format!("EAB MAC key rejected by HMAC-SHA256: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
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
    use crate::ca_backend::transport::ScriptedResponse;

    #[test]
    fn account_key_id_is_deterministic() {
        let a = account_key_id(b"public-key-bytes");
        let b = account_key_id(b"public-key-bytes");
        let c = account_key_id(b"other");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("key_acct_"));
    }

    fn directory_body() -> serde_json::Value {
        serde_json::json!({
            "newNonce": "https://acme.example/new-nonce",
            "newAccount": "https://acme.example/new-account",
            "newOrder": "https://acme.example/new-order",
            "revokeCert": "https://acme.example/revoke-cert",
            "keyChange": "https://acme.example/key-change",
        })
    }

    fn test_backend(fake: Arc<FakeAcmeTransport>) -> AcmeCaBackend {
        let repositories = crate::repository::MemoryRepository::new().into_set();
        AcmeCaBackend::new(
            "test-ca",
            "https://acme.example/directory",
            fake,
            Arc::new(KeyPair::generate().unwrap()),
            repositories,
        )
    }

    /// Capabilities default to DNS-only: the ACME directory has no
    /// identifier-type field, so an undeclared CA must not report `ip`.
    #[tokio::test]
    async fn undeclared_capabilities_stay_dns_only() {
        let fake = Arc::new(FakeAcmeTransport::new(jiff::Timestamp::now()));
        fake.push(ScriptedResponse::json("directory", 200, directory_body()).uses(100));
        let caps = test_backend(fake).capabilities().await.unwrap();
        assert!(caps.identifier_types.is_empty());
        assert!(caps.supports_identifier_type("dns"));
        assert!(!caps.supports_identifier_type("ip"));
    }

    /// The deployment declaration (with_identifier_types) is what the
    /// capability gate (CreateOrResumeOrder) consults for RFC 8738 orders
    /// against CAs the directory cannot describe.
    #[tokio::test]
    async fn declared_identifier_types_reach_capabilities() {
        let fake = Arc::new(FakeAcmeTransport::new(jiff::Timestamp::now()));
        fake.push(ScriptedResponse::json("directory", 200, directory_body()).uses(100));
        let caps = test_backend(fake)
            .with_identifier_types(vec!["dns".to_string(), "ip".to_string()])
            .capabilities()
            .await
            .unwrap();
        assert_eq!(caps.identifier_types, vec!["dns", "ip"]);
        assert!(caps.supports_identifier_type("ip"));
        assert!(caps.supports_identifier_type("dns"));
    }
}
