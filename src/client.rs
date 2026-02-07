/// High-level ACME client for certificate issuance
use crate::account::{AccountManager, KeyPair};
use crate::challenge::ChallengeSolverRegistry;
use crate::error::Result;
use crate::order::{CsrGenerator, NewOrderRequest, OrderManager};
use crate::protocol::{DirectoryManager, NonceManager, NoncePool};
use crate::types::{ChallengeType, Contact, Identifier};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Configuration for ACME client
#[derive(Clone)]
pub struct AcmeConfig {
    /// ACME directory URL
    pub directory_url: String,
    /// Contact information
    pub contacts: Vec<Contact>,
    /// Terms of service agreed
    pub terms_of_service_agreed: bool,
}

impl AcmeConfig {
    /// Create new configuration with directory URL
    pub fn new(directory_url: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
            contacts: Vec::new(),
            terms_of_service_agreed: false,
        }
    }

    /// Add contact
    pub fn with_contact(mut self, contact: Contact) -> Self {
        self.contacts.push(contact);
        self
    }

    /// Set terms of service agreed
    pub fn with_tos_agreed(mut self, agreed: bool) -> Self {
        self.terms_of_service_agreed = agreed;
        self
    }

    /// Let's Encrypt staging directory
    pub fn lets_encrypt_staging() -> Self {
        Self::new("https://acme-staging-v02.api.letsencrypt.org/directory")
    }

    /// Let's Encrypt production directory
    pub fn lets_encrypt() -> Self {
        Self::new("https://acme-v02.api.letsencrypt.org/directory")
    }
}

/// High-level ACME client
#[derive(Clone)]
pub struct AcmeClient {
    config: AcmeConfig,
    http_client: reqwest::Client,
    key_pair: Arc<KeyPair>,
    account_id: Option<String>,
    nonce_pool: Option<Arc<NoncePool>>,
}

impl AcmeClient {
    /// Create a new ACME client
    pub fn new(config: AcmeConfig) -> Result<Self> {
        let http_client = reqwest::Client::new();
        let key_pair = Arc::new(KeyPair::generate()?);

        Ok(Self {
            config,
            http_client,
            key_pair,
            account_id: None,
            nonce_pool: None,
        })
    }

    /// Create client with existing key pair
    pub fn with_key_pair(config: AcmeConfig, key_pair: KeyPair) -> Self {
        let http_client = reqwest::Client::new();

        Self {
            config,
            http_client,
            key_pair: Arc::new(key_pair),
            account_id: None,
            nonce_pool: None,
        }
    }

    /// Register or retrieve existing account
    pub async fn register_account(&mut self) -> Result<String> {
        let dir_mgr = DirectoryManager::new(&self.config.directory_url, self.http_client.clone());
        let directory = dir_mgr.get().await?;

        let nonce_mgr = NonceManager::new(&directory.new_nonce, self.http_client.clone());

        let account_mgr =
            AccountManager::new(&self.key_pair, &nonce_mgr, &dir_mgr, &self.http_client)?;

        let account = account_mgr
            .register(
                self.config.contacts.clone(),
                self.config.terms_of_service_agreed,
            )
            .await?;

        self.account_id = Some(account.id.clone());
        tracing::info!("Account registered: {}", account.id);

        Ok(account.id)
    }

    /// Issue a certificate for domains
    pub async fn issue_certificate(
        &mut self,
        domains: Vec<String>,
        solver_registry: &mut ChallengeSolverRegistry,
    ) -> Result<CertificateBundle> {
        // Ensure account is registered
        if self.account_id.is_none() {
            self.register_account().await?;
        }

        let account_id = self.account_id.as_ref().unwrap().clone();

        // Create managers
        let dir_mgr = DirectoryManager::new(&self.config.directory_url, self.http_client.clone());
        let nonce_mgr =
            NonceManager::new(&dir_mgr.get().await?.new_nonce, self.http_client.clone());
        let account_mgr =
            AccountManager::new(&self.key_pair, &nonce_mgr, &dir_mgr, &self.http_client)?;
        let order_mgr = OrderManager::new(
            &account_mgr,
            &dir_mgr,
            &nonce_mgr,
            &self.http_client,
            account_id.clone(),
        );

        // Create order
        let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::dns(d)).collect();
        let order_req = NewOrderRequest {
            identifiers,
            not_before: None,
            not_after: None,
        };

        let (order_url, mut order) = order_mgr.create_order(&order_req).await?;
        tracing::info!("Order created: {}", order_url);

        // Process authorizations
        for auth_url in &order.authorizations {
            let auth = order_mgr.get_authorization(auth_url).await?;
            tracing::info!("Processing authorization for: {:?}", auth.identifier);

            // Find suitable challenge
            let challenge = auth
                .challenges
                .iter()
                .find(|c| {
                    c.challenge_type
                        .parse::<ChallengeType>()
                        .map(|ct| solver_registry.get(ct).is_some())
                        .unwrap_or(false)
                })
                .ok_or_else(|| {
                    crate::error::AcmeError::challenge(
                        "unknown".to_string(),
                        "No suitable challenge solver found".to_string(),
                    )
                })?;

            // Get solver
            let challenge_type: ChallengeType = challenge.challenge_type.parse().map_err(|_| {
                crate::error::AcmeError::challenge(
                    challenge.challenge_type.clone(),
                    "Unsupported challenge type".to_string(),
                )
            })?;

            let solver = solver_registry.get_mut(challenge_type).ok_or_else(|| {
                crate::error::AcmeError::challenge(
                    challenge.challenge_type.clone(),
                    "Solver not found".to_string(),
                )
            })?;

            // Compute key authorization
            let key_auth = account_mgr.compute_key_authorization(&challenge.token)?;

            // Prepare challenge
            solver
                .prepare(challenge, &auth.identifier, &key_auth)
                .await?;

            // Present challenge
            solver.present().await?;

            // Respond to ACME server
            order_mgr.respond_to_challenge(&challenge.url).await?;

            tracing::info!("Challenge completed for: {:?}", auth.identifier);
        }

        // Poll order until ready
        order = order_mgr
            .poll_order(&order_url, 30, Duration::from_secs(2))
            .await?;

        if order.status != "ready" {
            return Err(crate::error::AcmeError::order(
                "Order not ready after authorization".to_string(),
                order.status,
            ));
        }

        // Generate CSR
        let csr_gen = CsrGenerator::new(domains.clone());
        let (csr_der, private_key_pem) = csr_gen.generate()?;

        // Finalize order
        let _order = order_mgr.finalize_order(&order.finalize, &csr_der).await?;

        // Poll until valid
        let order = order_mgr
            .poll_order(&order_url, 30, Duration::from_secs(2))
            .await?;

        if order.status != "valid" {
            return Err(crate::error::AcmeError::order(
                "Order not valid after finalization".to_string(),
                order.status,
            ));
        }

        // Download certificate
        let certificate_url = order.certificate.ok_or_else(|| {
            crate::error::AcmeError::certificate("No certificate URL in order".to_string())
        })?;

        let cert_pem = order_mgr.download_certificate(&certificate_url).await?;

        // Verify certificate chain
        if let Ok(chain) = crate::certificate::CertificateChain::from_pem(cert_pem.as_bytes()) {
            if let Err(e) = chain.verify() {
                tracing::warn!("Certificate chain verification failed: {}", e);
            } else {
                tracing::info!("Certificate chain verified successfully");
            }
        }

        Ok(CertificateBundle {
            certificate_pem: cert_pem,
            private_key_pem,
            domains,
        })
    }

    /// Enable and initialize nonce pool for better performance
    pub async fn enable_nonce_pool(&mut self, min_size: usize, max_size: usize) -> Result<()> {
        let dir_mgr = DirectoryManager::new(&self.config.directory_url, self.http_client.clone());
        let directory = dir_mgr.get().await?;
        let nonce_manager = NonceManager::new(&directory.new_nonce, self.http_client.clone());
        let pool = NoncePool::new(nonce_manager, min_size, max_size);
        pool.refill().await?;
        self.nonce_pool = Some(Arc::new(pool));
        Ok(())
    }

    async fn get_nonce(&self) -> Result<String> {
        if let Some(pool) = &self.nonce_pool {
            pool.get_nonce().await
        } else {
            let dir_mgr =
                DirectoryManager::new(&self.config.directory_url, self.http_client.clone());
            let directory = dir_mgr.get().await?;
            let nonce_manager = NonceManager::new(&directory.new_nonce, self.http_client.clone());
            nonce_manager.get_nonce().await
        }
    }

    /// Get account ID
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// Get key pair
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

/// Certificate bundle containing certificate and private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateBundle {
    /// Certificate chain in PEM format
    pub certificate_pem: String,
    /// Private key in PEM format
    pub private_key_pem: String,
    /// Domains covered by the certificate
    pub domains: Vec<String>,
}

impl CertificateBundle {
    /// Save certificate and key to files
    pub fn save_to_files(&self, cert_path: &str, key_path: &str) -> Result<()> {
        std::fs::write(cert_path, &self.certificate_pem)?;
        std::fs::write(key_path, &self.private_key_pem)?;
        Ok(())
    }

    /// Get certificate chain as bytes
    pub fn certificate_der(&self) -> Result<Vec<Vec<u8>>> {
        crate::order::parse_certificate_chain(&self.certificate_pem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_config_creation() {
        let config = AcmeConfig::lets_encrypt_staging()
            .with_contact(Contact::email("test@example.com"))
            .with_tos_agreed(true);

        assert!(config.terms_of_service_agreed);
        assert_eq!(config.contacts.len(), 1);
    }

    #[test]
    fn test_acme_client_creation() {
        let config = AcmeConfig::lets_encrypt_staging();
        let client = AcmeClient::new(config);
        assert!(client.is_ok());
    }
}
