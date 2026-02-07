use super::Orchestrator;
use crate::challenge::{ChallengeSolverRegistry, Http01Solver, TlsAlpn01Solver};
/// Certificate provisioner orchestration
use crate::client::{AcmeClient, AcmeConfig};
use crate::config::Config;
use crate::error::Result;
use crate::types::Contact;
use async_trait::async_trait;

/// Orchestrator for provisioning certificates
pub struct CertificateProvisioner {
    domains: Vec<String>,
}

#[async_trait]
impl Orchestrator for CertificateProvisioner {
    async fn execute(&self, config: &Config) -> Result<()> {
        let mut retry_count = 0;
        let max_retries = 3;
        let mut last_error = None;

        while retry_count <= max_retries {
            if retry_count > 0 {
                let delay = std::time::Duration::from_secs(2u64.pow(retry_count));
                tracing::info!(
                    "Retrying provisioning in {:?} (attempt {}/{})",
                    delay,
                    retry_count,
                    max_retries
                );
                tokio::time::sleep(delay).await;
            }

            match self.provision(config).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    tracing::warn!("Provisioning attempt {} failed: {}", retry_count, e);
                    last_error = Some(e);
                    retry_count += 1;
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            crate::error::AcmeError::Protocol("Provisioning failed".to_string())
        }))
    }
}

impl CertificateProvisioner {
    /// Create a new provisioner
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains }
    }

    async fn provision(&self, config: &Config) -> Result<()> {
        tracing::info!(
            "Starting certificate provisioning for domains: {:?}",
            self.domains
        );

        // 1. Configure ACME client
        let mut acme_config =
            AcmeConfig::new(&config.acme.directory).with_tos_agreed(config.acme.tos_agreed);

        for contact in &config.acme.contact {
            if contact.starts_with("mailto:") {
                acme_config = acme_config.with_contact(Contact::email(&contact[7..]));
            } else {
                acme_config = acme_config.with_contact(Contact::url(contact));
            }
        }

        let mut client = AcmeClient::new(acme_config)?;

        // 2. Register account
        client.register_account().await?;

        // 3. Configure challenge solvers
        let mut registry = ChallengeSolverRegistry::new();

        match config.challenge.challenge_type.as_str() {
            "http-01" => {
                if let Some(ref http_config) = config.challenge.http01 {
                    let addr = http_config.listen_addr.parse().map_err(|e| {
                        crate::error::AcmeError::configuration(format!(
                            "Invalid HTTP listen address: {}",
                            e
                        ))
                    })?;
                    registry.register(Http01Solver::new(addr));
                } else {
                    registry.register(Http01Solver::default());
                }
            }
            "tls-alpn-01" => {
                // We don't have a specific config struct for TLS-ALPN-01 yet in Config,
                // so we'll use a default or reuse HTTP config if appropriate (it's not really, but for now...)
                // Or better, just use default port 443
                registry.register(TlsAlpn01Solver::default());
            }
            "dns-01" => {
                // In a real implementation, we would configure the specific DNS provider here
                // For now, we'll use the mock provider if configured, or fail
                if let Some(ref _dns_config) = config.challenge.dns01 {
                    // This is where we would initialize the specific DNS provider based on config
                    // For this example, we'll assume a mock provider is acceptable for testing
                    // or that the user has configured a specific provider
                    tracing::warn!(
                        "DNS-01 provider configuration not fully implemented in provisioner"
                    );
                }
            }
            _ => {
                return Err(crate::error::AcmeError::configuration(format!(
                    "Unsupported challenge type: {}",
                    config.challenge.challenge_type
                )));
            }
        }

        // 4. Issue certificate
        let _bundle = client
            .issue_certificate(self.domains.clone(), &mut registry)
            .await?;

        // 5. Save certificate
        // This would use the configured storage backend
        // For now, we'll just log success
        tracing::info!(
            "Certificate issued successfully for domains: {:?}",
            self.domains
        );

        Ok(())
    }
}
