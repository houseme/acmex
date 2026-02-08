/// Automatic certificate renewal logic.
/// This module provides the `SimpleRenewalScheduler` and `RenewalHook` trait
/// to automate the process of checking and renewing certificates before they expire.
use crate::client::{AcmeClient, CertificateBundle};
use crate::error::{AcmeError, Result};
use crate::storage::{CertificateStore, StorageBackend};
use jiff::Timestamp;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::FromDer;

/// A trait for defining custom hooks that are triggered during the renewal process.
pub trait RenewalHook: Send + Sync {
    /// Called immediately before a renewal attempt starts.
    fn before_renewal(&self, _domains: &[String]) {}

    /// Called after a certificate has been successfully renewed.
    fn after_renewal(&self, _domains: &[String], _bundle: &CertificateBundle) {}

    /// Called if a renewal attempt fails.
    fn on_error(&self, _domains: &[String], _error: &AcmeError) {}
}

/// A simple scheduler that periodically checks certificates and renews them if they are close to expiry.
pub struct SimpleRenewalScheduler<B: StorageBackend> {
    /// The ACME client used for issuance.
    client: AcmeClient,
    /// The store where certificates are persisted.
    store: CertificateStore<B>,
    /// Optional hooks for custom logic.
    hook: Option<Arc<dyn RenewalHook>>,
    /// How often to check the certificates.
    check_interval: Duration,
    /// The time window before expiry during which a certificate should be renewed.
    renew_before: Duration,
}

impl<B: StorageBackend> SimpleRenewalScheduler<B> {
    /// Creates a new `SimpleRenewalScheduler` with default settings.
    /// Default check interval: 1 hour. Default renew-before window: 30 days.
    pub fn new(client: AcmeClient, store: CertificateStore<B>) -> Self {
        Self {
            client,
            store,
            hook: None,
            check_interval: Duration::from_secs(3600),
            renew_before: Duration::from_secs(30 * 24 * 3600),
        }
    }

    /// Sets a custom `RenewalHook`.
    pub fn with_hook(mut self, hook: Arc<dyn RenewalHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Sets the interval at which certificates are checked for expiry.
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Sets the time window before expiry to trigger renewal.
    pub fn with_renew_before(mut self, renew_before: Duration) -> Self {
        self.renew_before = renew_before;
        self
    }

    /// Starts the renewal scheduler loop. This method runs indefinitely.
    pub async fn run(mut self, domains_list: Vec<Vec<String>>) -> Result<()> {
        tracing::info!("Starting SimpleRenewalScheduler loop with {} domain sets", domains_list.len());
        loop {
            for domains in &domains_list {
                tracing::debug!("Checking renewal status for domains: {:?}", domains);
                match self.needs_renewal(domains).await {
                    Ok(true) => {
                        tracing::info!("Renewal required for domains: {:?}", domains);
                        if let Some(hook) = &self.hook {
                            hook.before_renewal(domains);
                        }

                        match self.renew(domains.clone()).await {
                            Ok(bundle) => {
                                tracing::info!("Successfully renewed certificate for domains: {:?}", domains);
                                if let Some(hook) = &self.hook {
                                    hook.after_renewal(domains, &bundle);
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to renew certificate for {:?}: {}", domains, e);
                                if let Some(hook) = &self.hook {
                                    hook.on_error(domains, &e);
                                }
                            }
                        }
                    }
                    Ok(false) => {
                        tracing::debug!("Certificate for {:?} is still valid and not within renewal window", domains);
                    }
                    Err(e) => {
                        tracing::error!("Error checking renewal status for {:?}: {}", domains, e);
                    }
                }
            }

            tracing::debug!("Renewal scheduler sleeping for {:?}", self.check_interval);
            tokio::time::sleep(self.check_interval).await;
        }
    }

    /// Determines if a certificate for the given domains needs renewal.
    pub async fn needs_renewal(&self, domains: &[String]) -> Result<bool> {
        let bundle = self.store.load(domains).await?;
        let Some(bundle) = bundle else {
            tracing::info!("No existing certificate found for {:?}, triggering initial issuance", domains);
            return Ok(true);
        };

        let expiry = certificate_expiry_timestamp(&bundle)?;
        let now = now_timestamp()?;

        // If expired or expiring soon
        if now >= expiry {
            tracing::warn!("Certificate for {:?} has already expired (Expiry: {})", domains, expiry);
            return Ok(true);
        }

        let renew_before_secs = self.renew_before.as_secs() as i64;
        let threshold_secs = expiry.as_second() - renew_before_secs;
        let threshold = Timestamp::from_second(threshold_secs)
            .map_err(|e| AcmeError::certificate(format!("Invalid threshold timestamp: {}", e)))?;

        let needs_renew = now >= threshold;
        if needs_renew {
            tracing::info!("Certificate for {:?} is within the renewal window (Threshold: {}, Expiry: {})", domains, threshold, expiry);
        }

        Ok(needs_renew)
    }

    /// Performs the actual certificate renewal by requesting a new one from the ACME server.
    pub async fn renew(&mut self, domains: Vec<String>) -> Result<CertificateBundle> {
        tracing::info!("Initiating renewal process for domains: {:?}", domains);
        let mut registry = crate::challenge::ChallengeSolverRegistry::new();
        // Default to HTTP-01 for simple scheduler; advanced scheduler can be more flexible
        registry.register(crate::challenge::Http01Solver::default());

        let bundle = self
            .client
            .issue_certificate(domains.clone(), &mut registry)
            .await?;

        tracing::debug!("Saving renewed certificate bundle to storage");
        self.store.save(&bundle).await?;
        Ok(bundle)
    }
}

/// Extracts the expiration timestamp from a `CertificateBundle`.
pub fn certificate_expiry_timestamp(bundle: &CertificateBundle) -> Result<Timestamp> {
    let chain = crate::order::parse_certificate_chain(&bundle.certificate_pem)?;
    let cert_der = chain
        .first()
        .ok_or_else(|| {
            tracing::error!("Certificate bundle contains an empty chain");
            AcmeError::certificate("Empty certificate chain".to_string())
        })?;

    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(cert_der)
        .map_err(|e| {
            tracing::error!("Failed to parse X.509 certificate DER: {}", e);
            AcmeError::certificate(format!("Failed to parse certificate: {}", e))
        })?;

    let not_after = cert.validity().not_after.timestamp();
    let ts = Timestamp::from_second(not_after)
        .map_err(|e| AcmeError::certificate(format!("Invalid expiry timestamp: {}", e)))?;

    Ok(ts)
}

/// Returns the current system time as a `jiff::Timestamp`.
pub fn now_timestamp() -> Result<Timestamp> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AcmeError::certificate(format!("System time error: {}", e)))?;

    let secs = now.as_secs() as i64;
    Timestamp::from_second(secs)
        .map_err(|e| AcmeError::certificate(format!("Invalid current timestamp: {}", e)))
}
