/// Certificate provisioner orchestration.
/// This module coordinates the entire process of account registration,
/// challenge fulfillment, and certificate issuance.
use super::Orchestrator;
use crate::challenge::{ChallengeSolverRegistry, Http01Solver, TlsAlpn01Solver};
use crate::client::{AcmeClient, AcmeConfig};
use crate::config::Config;
use crate::error::{AcmeError, Result};
use crate::storage::{CertificateStore, FileStorage, MemoryStorage, StorageBackend};
use crate::types::Contact;
use async_trait::async_trait;
use std::sync::Arc;

/// Orchestrator for provisioning certificates with automatic retries.
pub struct CertificateProvisioner {
    /// The list of domains for which to provision a certificate.
    domains: Vec<String>,
}

#[async_trait]
impl Orchestrator for CertificateProvisioner {
    /// Executes the provisioning workflow with an exponential backoff retry strategy.
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
                Ok(_) => {
                    tracing::info!("Provisioning completed successfully");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Provisioning attempt {} failed: {}", retry_count, e);
                    last_error = Some(e);
                    retry_count += 1;
                }
            }
        }

        let final_err = last_error.unwrap_or_else(|| {
            AcmeError::protocol("Provisioning failed after maximum retries".to_string())
        });
        tracing::error!("Provisioning failed permanently: {}", final_err);
        Err(final_err)
    }
}

impl CertificateProvisioner {
    /// Creates a new `CertificateProvisioner` for the specified domains.
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains }
    }

    /// Internal method that performs the actual provisioning steps.
    async fn provision(&self, config: &Config) -> Result<()> {
        tracing::info!(
            "Starting certificate provisioning for domains: {:?}",
            self.domains
        );

        // 1. Configure ACME client
        tracing::debug!(
            "Configuring ACME client for directory: {}",
            config.acme.directory
        );
        let mut acme_config =
            AcmeConfig::new(&config.acme.directory).with_tos_agreed(config.acme.tos_agreed);

        for contact in &config.acme.contact {
            if contact.strip_prefix("mailto:").is_some() {
                let contact_mail = &contact[7..];
                acme_config = acme_config.with_contact(Contact::email(contact_mail));
            } else {
                acme_config = acme_config.with_contact(Contact::url(contact));
            }
        }

        let mut client = AcmeClient::new(acme_config)?;

        // 2. Register account
        tracing::info!("Registering/retrieving ACME account");
        client.register_account().await?;

        // 3. Configure challenge solvers
        let mut registry = ChallengeSolverRegistry::new();
        tracing::debug!(
            "Setting up challenge solver for type: {}",
            config.challenge.challenge_type
        );

        match config.challenge.challenge_type.as_str() {
            "http-01" => {
                let addr = if let Some(ref http_config) = config.challenge.http01 {
                    http_config.listen_addr.parse().map_err(|e| {
                        AcmeError::configuration(format!("Invalid HTTP listen address: {}", e))
                    })?
                } else {
                    "0.0.0.0:80".parse().unwrap()
                };
                tracing::debug!("Using HTTP-01 solver on address: {}", addr);
                registry.register(Http01Solver::new(addr));
            }
            "tls-alpn-01" => {
                tracing::debug!("Using default TLS-ALPN-01 solver on port 443");
                registry.register(TlsAlpn01Solver::default());
            }
            "dns-01" => {
                if let Some(ref dns_config) = config.challenge.dns01 {
                    tracing::info!(
                        "Configuring DNS-01 solver with provider: {:?}",
                        dns_config.provider
                    );
                    // Note: In a full implementation, we would use a factory to create the provider
                    // based on the provider name in the config.
                    // For now, we assume the provider is correctly registered in the registry.
                    // registry.register(Dns01Solver::new(Arc::new(provider)));
                } else {
                    return Err(AcmeError::configuration(
                        "DNS-01 selected but no DNS config found".to_string(),
                    ));
                }
            }
            _ => {
                tracing::error!(
                    "Unsupported challenge type: {}",
                    config.challenge.challenge_type
                );
                return Err(AcmeError::configuration(format!(
                    "Unsupported challenge type: {}",
                    config.challenge.challenge_type
                )));
            }
        }

        // 4. Issue certificate
        tracing::info!("Requesting certificate issuance from ACME server");
        let bundle = client
            .issue_certificate(self.domains.clone(), &mut registry)
            .await?;

        // 5. Save certificate using the configured storage backend
        tracing::info!("Certificate issued successfully. Saving to storage...");
        let store = CertificateStore::new(legacy_storage_backend_from_config(config)?);
        store.save(&bundle).await?;

        tracing::info!(
            "Certificate provisioning completed for domains: {:?}",
            self.domains
        );

        Ok(())
    }
}

fn legacy_storage_backend_from_config(config: &Config) -> Result<Arc<dyn StorageBackend>> {
    match config.storage.backend.as_str() {
        "memory" => Ok(Arc::new(MemoryStorage::new())),
        "file" => {
            let path = config
                .storage
                .file
                .as_ref()
                .map(|file| file.path.as_str())
                .unwrap_or(".acmex");
            Ok(Arc::new(FileStorage::new(path)))
        }
        "redis" => {
            #[cfg(feature = "redis")]
            {
                let redis = config.storage.redis.as_ref().ok_or_else(|| {
                    AcmeError::configuration("Redis storage selected but [storage.redis] missing")
                })?;
                Ok(Arc::new(crate::storage::RedisStorage::new(&redis.url)?))
            }
            #[cfg(not(feature = "redis"))]
            {
                Err(AcmeError::configuration(
                    "Redis storage selected but the redis feature is not enabled",
                ))
            }
        }
        "encrypted" => Err(AcmeError::configuration(
            "legacy CertificateProvisioner does not support encrypted storage; use the durable v0.9 workflow worker for SecretRef-backed storage",
        )),
        other => Err(AcmeError::configuration(format!(
            "unsupported storage backend `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::CertificateBundle;

    #[tokio::test]
    async fn provisioner_persists_legacy_bundle_to_configured_file_storage() {
        let root =
            std::env::temp_dir().join(format!("acmex-provisioner-store-{}", std::process::id()));
        let mut config = Config::default();
        config.storage.backend = "file".to_string();
        config.storage.file = Some(crate::config::FileStorageConfig {
            path: root.to_string_lossy().into_owned(),
        });
        let store = CertificateStore::new(legacy_storage_backend_from_config(&config).unwrap());
        let bundle = CertificateBundle {
            certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                .to_string(),
            private_key_pem: "test-key-material".to_string(),
            domains: vec!["b.example.com".to_string(), "a.example.com".to_string()],
        };

        store.save(&bundle).await.unwrap();
        let loaded = store
            .load(&["a.example.com".to_string(), "b.example.com".to_string()])
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.domains, bundle.domains);
        assert_eq!(loaded.certificate_pem, bundle.certificate_pem);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn provisioner_rejects_unsupported_storage_without_dropping_bundle() {
        let mut config = Config::default();
        config.storage.backend = "encrypted".to_string();

        let err = match legacy_storage_backend_from_config(&config) {
            Ok(_) => panic!("encrypted legacy storage must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("does not support encrypted storage")
        );
    }
}
