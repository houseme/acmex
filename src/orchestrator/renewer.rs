use super::Orchestrator;
use crate::config::Config;
use crate::error::Result;
use crate::storage::{CertificateStore, StorageBackend};
use async_trait::async_trait;
use tracing::info;
use x509_parser::prelude::*;

/// Orchestrator for certificate renewal
pub struct CertificateRenewer<B: StorageBackend> {
    store: CertificateStore<B>,
    renew_before_days: u64,
}

impl<B: StorageBackend> CertificateRenewer<B> {
    /// Create a new renewer
    pub fn new(store: CertificateStore<B>, renew_before_days: u64) -> Self {
        Self {
            store,
            renew_before_days,
        }
    }

    /// Check if a certificate needs renewal
    fn needs_renewal(&self, cert_der: &[u8]) -> bool {
        if let Ok((_, x509)) = parse_x509_certificate(cert_der) {
            let now = jiff::Zoned::now();
            let not_after = x509.validity().not_after;
            let expiry_ts = not_after.timestamp();
            let now_ts = now.timestamp().as_second();

            let days_left = (expiry_ts - now_ts) / (24 * 3600);
            return days_left <= self.renew_before_days as i64;
        }
        false
    }
}

#[async_trait]
impl<B: StorageBackend + 'static> Orchestrator for CertificateRenewer<B> {
    async fn execute(&self, _config: &Config) -> Result<()> {
        info!("Starting certificate renewal orchestration...");

        // 1. Get all certificates from store
        let cert_keys = self.store.backend().list("cert:").await?;

        for key in cert_keys {
            if let Some(cert_data) = self.store.backend().load(&key).await? {
                if self.needs_renewal(&cert_data) {
                    info!("Certificate {} needs renewal, triggering process...", key);

                    // In a real implementation, we would extract domains from the certificate
                    // and use the CertificateProvisioner to renew them.
                    // For now, we log the intent.

                    // Example logic:
                    // let domains = extract_domains(&cert_data)?;
                    // let provisioner = CertificateProvisioner::new(domains);
                    // provisioner.execute(config).await?;
                }
            }
        }

        Ok(())
    }
}
