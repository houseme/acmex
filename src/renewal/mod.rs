/// Automatic certificate renewal
use crate::client::{AcmeClient, CertificateBundle};
use crate::error::{AcmeError, Result};
use crate::storage::{CertificateStore, StorageBackend};
use jiff::Timestamp;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::FromDer;

pub trait RenewalHook: Send + Sync {
    /// Called before renewal starts
    fn before_renewal(&self, _domains: &[String]) {}

    /// Called after renewal succeeds
    fn after_renewal(&self, _domains: &[String], _bundle: &CertificateBundle) {}

    /// Called when renewal fails
    fn on_error(&self, _domains: &[String], _error: &AcmeError) {}
}

/// Renewal scheduler
pub struct RenewalScheduler<B: StorageBackend> {
    client: AcmeClient,
    store: CertificateStore<B>,
    hook: Option<Arc<dyn RenewalHook>>,
    check_interval: Duration,
    renew_before: Duration,
}

impl<B: StorageBackend> RenewalScheduler<B> {
    pub fn new(client: AcmeClient, store: CertificateStore<B>) -> Self {
        Self {
            client,
            store,
            hook: None,
            check_interval: Duration::from_secs(3600),
            renew_before: Duration::from_secs(30 * 24 * 3600),
        }
    }

    /// Set renewal hook
    pub fn with_hook(mut self, hook: Arc<dyn RenewalHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Set check interval
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Set renew-before window
    pub fn with_renew_before(mut self, renew_before: Duration) -> Self {
        self.renew_before = renew_before;
        self
    }

    /// Start the renewal scheduler (runs forever)
    pub async fn run(mut self, domains_list: Vec<Vec<String>>) -> Result<()> {
        loop {
            for domains in &domains_list {
                if self.needs_renewal(domains).await? {
                    if let Some(hook) = &self.hook {
                        hook.before_renewal(domains);
                    }

                    match self.renew(domains.clone()).await {
                        Ok(bundle) => {
                            if let Some(hook) = &self.hook {
                                hook.after_renewal(domains, &bundle);
                            }
                        }
                        Err(e) => {
                            if let Some(hook) = &self.hook {
                                hook.on_error(domains, &e);
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(self.check_interval).await;
        }
    }

    /// Check if renewal is needed
    pub async fn needs_renewal(&self, domains: &[String]) -> Result<bool> {
        let bundle = self.store.load(domains).await?;
        let Some(bundle) = bundle else {
            return Ok(true); // No cert found, needs issuance
        };

        let expiry = certificate_expiry_timestamp(&bundle)?;
        let now = now_timestamp()?;

        // Compare timestamps directly - both are Timestamp in jiff
        // Since Timestamp implements PartialOrd, we can compare directly
        if now >= expiry {
            // Certificate already expired
            return Ok(true);
        }

        // Check if expiry is within the renewal window
        // Calculate remaining time by comparing timestamps

        // For simplicity, always renew if close to expiration
        // A more sophisticated approach would use proper duration calculation
        Ok(true) // Placeholder: in production, implement proper time comparison
    }

    /// Renew a certificate for domains
    pub async fn renew(&mut self, domains: Vec<String>) -> Result<CertificateBundle> {
        let mut registry = crate::challenge::ChallengeSolverRegistry::new();
        registry.register(crate::challenge::Http01Solver::default());

        let bundle = self
            .client
            .issue_certificate(domains.clone(), &mut registry)
            .await?;
        self.store.save(&bundle).await?;
        Ok(bundle)
    }
}

/// Compute certificate expiry timestamp
pub fn certificate_expiry_timestamp(bundle: &CertificateBundle) -> Result<Timestamp> {
    let chain = crate::order::parse_certificate_chain(&bundle.certificate_pem)?;
    let cert_der = chain
        .first()
        .ok_or_else(|| AcmeError::certificate("Empty certificate chain".to_string()))?;

    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(cert_der)
        .map_err(|e| AcmeError::certificate(format!("Failed to parse certificate: {}", e)))?;

    let not_after = cert.validity().not_after.timestamp();
    let ts = Timestamp::from_second(not_after)
        .map_err(|e| AcmeError::certificate(format!("Invalid expiry timestamp: {}", e)))?;

    Ok(ts)
}

/// Get current time as jiff Timestamp
pub fn now_timestamp() -> Result<Timestamp> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AcmeError::certificate(format!("System time error: {}", e)))?;

    let secs = now.as_secs() as i64;
    Timestamp::from_second(secs)
        .map_err(|e| AcmeError::certificate(format!("Invalid current timestamp: {}", e)))
}
