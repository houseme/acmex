/// High-level ACME client for certificate issuance and account management.
use crate::account::{AccountManager, KeyPair};
use crate::challenge::ChallengeSolverRegistry;
use crate::error::Result;
use crate::order::{CsrGenerator, NewOrderRequest, OrderManager};
use crate::protocol::{DirectoryManager, NonceManager, NoncePool};
use crate::types::{ChallengeType, Contact, Identifier};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the ACME client.
#[derive(Clone)]
pub struct AcmeConfig {
    /// The URL of the ACME directory.
    pub directory_url: String,
    /// Contact information (e.g., email addresses) for the account.
    pub contacts: Vec<Contact>,
    /// Whether the terms of service have been agreed to.
    pub terms_of_service_agreed: bool,
}

impl AcmeConfig {
    /// Creates a new configuration with the specified directory URL.
    pub fn new(directory_url: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
            contacts: Vec::new(),
            terms_of_service_agreed: false,
        }
    }

    /// Adds a contact to the configuration.
    pub fn with_contact(mut self, contact: Contact) -> Self {
        self.contacts.push(contact);
        self
    }

    /// Sets whether the terms of service are agreed to.
    pub fn with_tos_agreed(mut self, agreed: bool) -> Self {
        self.terms_of_service_agreed = agreed;
        self
    }

    /// Returns a configuration for the Let's Encrypt staging directory.
    pub fn lets_encrypt_staging() -> Self {
        Self::new("https://acme-staging-v02.api.letsencrypt.org/directory")
    }

    /// Returns a configuration for the Let's Encrypt production directory.
    pub fn lets_encrypt() -> Self {
        Self::new("https://acme-v02.api.letsencrypt.org/directory")
    }
}

/// The primary high-level ACME client.
/// This client manages account registration, order creation, and certificate issuance.
#[derive(Clone)]
pub struct AcmeClient {
    /// The client configuration.
    config: AcmeConfig,
    /// The internal HTTP client.
    http_client: reqwest::Client,
    /// The account key pair.
    key_pair: Arc<KeyPair>,
    /// The registered account ID, if any.
    account_id: Option<String>,
    /// An optional pool for managing nonces.
    nonce_pool: Option<Arc<NoncePool>>,
}

impl AcmeClient {
    /// Creates a new ACME client with the given configuration.
    /// Generates a new key pair for the account.
    pub fn new(config: AcmeConfig) -> Result<Self> {
        tracing::debug!("Creating new AcmeClient with directory: {}", config.directory_url);
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

    /// Creates an ACME client with an existing key pair.
    pub fn with_key_pair(config: AcmeConfig, key_pair: KeyPair) -> Self {
        tracing::debug!("Creating AcmeClient with existing key pair");
        let http_client = reqwest::Client::new();

        Self {
            config,
            http_client,
            key_pair: Arc::new(key_pair),
            account_id: None,
            nonce_pool: None,
        }
    }

    /// Registers a new account or retrieves an existing one using the configured key pair.
    pub async fn register_account(&mut self) -> Result<String> {
        tracing::info!("Registering account with ACME server: {}", self.config.directory_url);
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
        tracing::info!("Account successfully registered: {}", account.id);

        Ok(account.id)
    }

    /// Creates a new certificate order for the specified domains.
    /// Automatically registers the account if it hasn't been registered yet.
    pub async fn create_order(&mut self, domains: Vec<String>) -> Result<crate::order::Order> {
        tracing::info!("Creating order for domains: {:?}", domains);
        // Ensure account is registered
        if self.account_id.is_none() {
            self.register_account().await?;
        }

        let account_id = self.account_id.as_ref().unwrap().clone();

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
            account_id,
        );

        let identifiers: Vec<Identifier> = domains.iter().map(Identifier::dns).collect();
        let order_req = NewOrderRequest {
            identifiers,
            not_before: None,
            not_after: None,
        };

        let (url, order) = order_mgr.create_order(&order_req).await?;
        tracing::info!("Order created successfully at URL: {}", url);
        Ok(order)
    }

    /// Issues a certificate for the specified domains using the provided challenge solvers.
    /// This is a high-level method that handles the entire ACME flow:
    /// 1. Account registration (if needed)
    /// 2. Order creation
    /// 3. Authorization and challenge fulfillment
    /// 4. Order finalization (CSR submission)
    /// 5. Certificate download
    pub async fn issue_certificate(
        &mut self,
        domains: Vec<String>,
        solver_registry: &mut ChallengeSolverRegistry,
    ) -> Result<CertificateBundle> {
        tracing::info!("Starting certificate issuance for domains: {:?}", domains);
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
        let identifiers: Vec<Identifier> = domains.iter().map(Identifier::dns).collect();
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
            tracing::debug!("Preparing challenge: {}", challenge.challenge_type);
            solver
                .prepare(challenge, &auth.identifier, &key_auth)
                .await?;

            // Present challenge
            tracing::debug!("Presenting challenge: {}", challenge.challenge_type);
            solver.present().await?;

            // Respond to ACME server
            tracing::debug!("Responding to challenge at URL: {}", challenge.url);
            order_mgr.respond_to_challenge(&challenge.url).await?;

            tracing::info!("Challenge completed for: {:?}", auth.identifier);
        }

        // Poll order until ready
        tracing::info!("Polling order status until ready...");
        order = order_mgr
            .poll_order(&order_url, 30, Duration::from_secs(2))
            .await?;

        if order.status != "ready" {
            tracing::error!("Order failed to reach 'ready' status. Current status: {}", order.status);
            return Err(crate::error::AcmeError::order(
                "Order not ready after authorization".to_string(),
                order.status,
            ));
        }

        // Generate CSR
        tracing::info!("Generating CSR for domains: {:?}", domains);
        let csr_gen = CsrGenerator::new(domains.clone());
        let (csr_der, private_key_pem) = csr_gen.generate()?;

        // Finalize order
        tracing::info!("Finalizing order at URL: {}", order.finalize);
        let _order = order_mgr.finalize_order(&order.finalize, &csr_der).await?;

        // Poll until valid
        tracing::info!("Polling order status until valid...");
        let order = order_mgr
            .poll_order(&order_url, 30, Duration::from_secs(2))
            .await?;

        if order.status != "valid" {
            tracing::error!("Order failed to reach 'valid' status. Current status: {}", order.status);
            return Err(crate::error::AcmeError::order(
                "Order not valid after finalization".to_string(),
                order.status,
            ));
        }

        // Download certificate
        let certificate_url = order.certificate.ok_or_else(|| {
            tracing::error!("Order is valid but no certificate URL was provided");
            crate::error::AcmeError::certificate("No certificate URL in order".to_string())
        })?;

        tracing::info!("Downloading certificate from: {}", certificate_url);
        let cert_pem = order_mgr.download_certificate(&certificate_url).await?;

        // Verify certificate chain
        if let Ok(chain) = crate::certificate::CertificateChain::from_pem(cert_pem.as_bytes()) {
            if let Err(e) = chain.verify() {
                tracing::warn!("Certificate chain verification failed: {}", e);
            } else {
                tracing::info!("Certificate chain verified successfully");
            }
        }

        tracing::info!("Certificate issuance completed successfully");
        Ok(CertificateBundle {
            certificate_pem: cert_pem,
            private_key_pem,
            domains,
        })
    }

    /// Enables and initializes a nonce pool for better performance.
    /// This pre-fetches nonces to minimize round-trips during ACME operations.
    pub async fn enable_nonce_pool(&mut self, min_size: usize, max_size: usize) -> Result<()> {
        tracing::info!("Enabling nonce pool (min: {}, max: {})", min_size, max_size);
        let dir_mgr = DirectoryManager::new(&self.config.directory_url, self.http_client.clone());
        let directory = dir_mgr.get().await?;
        let nonce_manager = NonceManager::new(&directory.new_nonce, self.http_client.clone());
        let pool = NoncePool::new(nonce_manager, min_size, max_size);
        pool.refill().await?;
        self.nonce_pool = Some(Arc::new(pool));
        Ok(())
    }

    /// Internal helper to get a nonce, either from the pool or directly from the server.
    #[allow(dead_code)]
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

    /// Returns the registered account ID, if any.
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// Returns a reference to the account key pair.
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

/// A bundle containing the issued certificate chain and the corresponding private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateBundle {
    /// The certificate chain in PEM format.
    pub certificate_pem: String,
    /// The private key in PEM format.
    pub private_key_pem: String,
    /// The list of domains covered by this certificate.
    pub domains: Vec<String>,
}

impl CertificateBundle {
    /// Saves the certificate and private key to the specified file paths.
    pub fn save_to_files(&self, cert_path: &str, key_path: &str) -> Result<()> {
        tracing::info!("Saving certificate to {} and key to {}", cert_path, key_path);
        std::fs::write(cert_path, &self.certificate_pem)?;
        std::fs::write(key_path, &self.private_key_pem)?;
        Ok(())
    }

    /// Parses the PEM certificate chain and returns it as a list of DER-encoded certificates.
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
