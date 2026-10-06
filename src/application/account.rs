//! Application use cases for durable ACME account lifecycle changes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::account::KeyPair;
use crate::ca_backend::{AccountHandle, CaBackend};
use crate::crypto::KeyPairGenerator;
use crate::crypto::keypair::KeyType;
use crate::domain::{AccountStatus, TenantId};
use crate::error::{AcmeError, Result};
use crate::repository::{LeaseOutcome, RepositorySet};

use super::types::{ActorContext, Permission};

/// Rotates the account key currently configured for one persisted account.
///
/// The key type is deployment policy, not caller input. This prevents an API
/// client from silently weakening an account key while still allowing a
/// deployment to deliberately change its configured account key algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloverAccountKey {
    /// Authenticated caller.
    pub context: ActorContext,
    /// Composite persisted account id (`<tenant>:<ca_id>`).
    pub account_id: String,
}

/// Secret-free result of an account key rollover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeyRolloverView {
    /// Rotated persisted account id.
    pub account_id: String,
    /// CA identity owning the account.
    pub ca_id: String,
    /// New key reference, never private key material.
    pub key_id: String,
    /// Time the durable account record was updated.
    pub updated_at: Timestamp,
}

/// Mutating account-lifecycle use cases for the new control plane.
#[async_trait]
pub trait AccountApplication: Send + Sync {
    /// Executes one RFC 8555 account key rollover.
    async fn rollover_account_key(
        &self,
        command: RolloverAccountKey,
    ) -> Result<AccountKeyRolloverView>;
}

/// Repository-backed account key rollover service.
///
/// The supplied backend is the same instance used by the workflow worker.
/// That is essential: a successful rollover refreshes both the account-key
/// JWK used for challenge authorization and the sessions that sign later
/// issuance requests.
pub struct RepositoryAccountApplication {
    repositories: RepositorySet,
    backend: Arc<dyn CaBackend>,
    key_type: KeyType,
    lease_owner_prefix: String,
}

impl RepositoryAccountApplication {
    /// Creates the application service around an already assembled backend.
    pub fn new(
        repositories: RepositorySet,
        backend: Arc<dyn CaBackend>,
        key_type: KeyType,
        lease_owner_prefix: impl Into<String>,
    ) -> Self {
        Self {
            repositories,
            backend,
            key_type,
            lease_owner_prefix: lease_owner_prefix.into(),
        }
    }

    fn authorize(context: &ActorContext) -> Result<()> {
        if context.has_permission(Permission::Admin) {
            Ok(())
        } else {
            Err(AcmeError::account(
                "account key rollover requires the admin permission",
            ))
        }
    }

    fn lease_key(account_id: &str) -> String {
        format!("account-key-rollover:{account_id}")
    }

    fn lease_owner(&self) -> String {
        format!(
            "{}-{}-{:016x}",
            self.lease_owner_prefix,
            std::process::id(),
            rand::random::<u64>()
        )
    }
}

#[async_trait]
impl AccountApplication for RepositoryAccountApplication {
    async fn rollover_account_key(
        &self,
        command: RolloverAccountKey,
    ) -> Result<AccountKeyRolloverView> {
        Self::authorize(&command.context)?;
        let account_id = command.account_id.trim();
        if account_id.is_empty() {
            return Err(AcmeError::invalid_input("account_id must not be empty"));
        }

        let stored = self
            .repositories
            .accounts
            .get(account_id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("account `{account_id}` not found")))?;
        let account = stored.value;
        if account.tenant_id != command.context.tenant_id {
            // Do not disclose whether another tenant has this account.
            return Err(AcmeError::not_found(format!(
                "account `{account_id}` not found"
            )));
        }
        if account.ca_id != *self.backend.ca_id() {
            return Err(AcmeError::invalid_input(format!(
                "account `{account_id}` belongs to CA `{}`, not this worker's CA `{}`",
                account.ca_id,
                self.backend.ca_id()
            )));
        }
        if account.status != AccountStatus::Active {
            return Err(AcmeError::account(format!(
                "account `{account_id}` is not active"
            )));
        }
        let account_url = account.account_url.clone().ok_or_else(|| {
            AcmeError::account(format!(
                "account `{account_id}` is not registered at the CA"
            ))
        })?;

        // Leases fence concurrent API requests and separate process workers.
        // The lease is intentionally the repository primitive, rather than a
        // process-local mutex, because keyChange changes remote CA state.
        let lease_key = Self::lease_key(account_id);
        let owner = self.lease_owner();
        let grant = match self
            .repositories
            .leases
            .acquire(&lease_key, &owner, Duration::from_secs(300))
            .await?
        {
            LeaseOutcome::Granted(grant) => grant,
            LeaseOutcome::HeldByOther { .. } => {
                return Err(AcmeError::conflict(
                    "an account key rollover is already in progress",
                ));
            }
        };

        let result = async {
            // Generate before the irreversible remote request. No private key
            // crosses the API boundary or appears in the returned view.
            let new_key = Arc::new(KeyPair(
                KeyPairGenerator::new(self.key_type)
                    .generate()
                    .map_err(|err| AcmeError::crypto(format!("generate account key: {err}")))?,
            ));
            self.backend
                .roll_account_key(
                    &AccountHandle {
                        ca_id: account.ca_id.clone(),
                        account_url,
                        key_id: account.key_ref.key_id.to_string(),
                    },
                    new_key,
                )
                .await?;

            let updated = self
                .repositories
                .accounts
                .get(account_id)
                .await?
                .ok_or_else(|| AcmeError::storage("rolled-over account record is missing"))?
                .value;
            self.repositories
                .outbox
                .append(
                    "account.key_rolled",
                    serde_json::json!({
                        "account_id": updated.id,
                        "tenant_id": updated.tenant_id.to_string(),
                        "ca_id": updated.ca_id,
                        "key_id": updated.key_ref.key_id.to_string(),
                        "actor": command.context.subject,
                    }),
                    None,
                )
                .await?;
            Ok(AccountKeyRolloverView {
                account_id: updated.id,
                ca_id: updated.ca_id,
                key_id: updated.key_ref.key_id.to_string(),
                updated_at: updated.updated_at,
            })
        }
        .await;

        if let Err(error) = self
            .repositories
            .leases
            .release(&lease_key, &owner, grant.fencing_token)
            .await
        {
            tracing::warn!(error = %error, "failed to release account key rollover lease");
        }
        result
    }
}

/// Stable default tenant used by the built-in single-account worker.
#[doc(hidden)]
pub fn default_account_id(ca_id: &str) -> String {
    crate::domain::AccountRecord::compute_id(&TenantId::default_tenant(), ca_id)
}
