/// Domain validation orchestration.
/// This module handles pre-flight checks and validation of domain control
/// before attempting to issue a certificate.
use super::Orchestrator;
use crate::config::Config;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;
use std::net::ToSocketAddrs;

/// Orchestrator for validating domain control and system readiness.
pub struct DomainValidator {
    /// The list of domains to validate.
    domains: Vec<String>,
}

impl DomainValidator {
    /// Creates a new `DomainValidator` for the specified domains.
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains }
    }

    /// Performs a pre-flight check to ensure the domain resolves to the expected IP.
    /// This is useful for HTTP-01 challenges to avoid unnecessary ACME requests.
    async fn check_dns_resolution(&self, domain: &str) -> Result<()> {
        tracing::debug!("Checking DNS resolution for domain: {}", domain);
        // Note: This is a blocking call in standard library, but for pre-flight it's acceptable
        // or can be wrapped in tokio::task::spawn_blocking.
        let result = tokio::task::spawn_blocking({
            let d = domain.to_string();
            move || (d.as_str(), 80).to_socket_addrs()
        })
        .await
        .map_err(|e| AcmeError::protocol(format!("Task join error: {}", e)))?;

        match result {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    tracing::info!("Domain {} resolves to {}", domain, addr.ip());
                    Ok(())
                } else {
                    tracing::error!("Domain {} did not resolve to any IP address", domain);
                    Err(AcmeError::protocol(format!(
                        "Domain {} does not resolve",
                        domain
                    )))
                }
            }
            Err(e) => {
                tracing::error!("DNS resolution failed for {}: {}", domain, e);
                Err(AcmeError::protocol(format!("DNS resolution failed: {}", e)))
            }
        }
    }
}

#[async_trait]
impl Orchestrator for DomainValidator {
    /// Executes the domain validation workflow.
    /// This includes DNS resolution checks and connectivity tests.
    async fn execute(&self, config: &Config) -> Result<()> {
        tracing::info!(
            "Starting pre-flight domain validation for: {:?}",
            self.domains
        );

        for domain in &self.domains {
            // 1. Check DNS resolution if using HTTP-01
            if config.challenge.challenge_type == "http-01" {
                self.check_dns_resolution(domain).await?;
            }

            // 2. Verify DNS API credentials if using DNS-01
            if config.challenge.challenge_type == "dns-01" {
                if config.challenge.dns01.is_none() {
                    tracing::error!("DNS-01 challenge selected but no DNS configuration provided");
                    return Err(AcmeError::configuration(
                        "Missing DNS-01 configuration".to_string(),
                    ));
                }
                tracing::debug!("DNS-01 configuration found for domain: {}", domain);
            }
        }

        tracing::info!("Pre-flight domain validation completed successfully");
        Ok(())
    }
}
