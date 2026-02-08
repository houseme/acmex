/// AWS Route53 DNS provider implementation.
/// This provider uses the AWS SDK for Rust to manage DNS records in Route53.
use crate::DnsProvider;
use crate::error::{AcmeError, Result};
use async_trait::async_trait;

#[cfg(feature = "dns-route53")]
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};

/// Configuration for the Route53 DNS provider.
#[derive(Debug, Clone)]
pub struct Route53Config {
    /// The ID of the hosted zone where the DNS records will be managed.
    pub hosted_zone_id: String,
}

/// Route53 DNS provider for handling DNS-01 challenges.
pub struct Route53DnsProvider {
    /// Provider configuration.
    #[allow(dead_code)]
    config: Route53Config,
    /// AWS Route53 client (only available when the `dns-route53` feature is enabled).
    #[cfg(feature = "dns-route53")]
    client: aws_sdk_route53::Client,
}

impl Route53DnsProvider {
    /// Creates a new `Route53DnsProvider` instance.
    /// This method initializes the AWS SDK client using default credentials.
    #[cfg(feature = "dns-route53")]
    pub async fn new(config: Route53Config) -> Self {
        tracing::debug!(
            "Initializing Route53DnsProvider for Hosted Zone: {}",
            config.hosted_zone_id
        );
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_route53::Client::new(&sdk_config);
        Self { config, client }
    }

    /// Creates a new `Route53DnsProvider` instance when the feature is disabled.
    #[cfg(not(feature = "dns-route53"))]
    pub fn new(config: Route53Config) -> Self {
        tracing::warn!("Route53DnsProvider initialized but 'dns-route53' feature is disabled");
        Self { config }
    }
}

#[async_trait]
impl DnsProvider for Route53DnsProvider {
    /// Creates or updates a TXT record in AWS Route53.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        tracing::info!("Creating Route53 TXT record for domain: {}", domain);
        #[cfg(feature = "dns-route53")]
        {
            let name = if domain.ends_with('.') {
                domain.to_string()
            } else {
                format!("{}.", domain)
            };

            let change = Change::builder()
                .action(ChangeAction::Upsert)
                .resource_record_set(
                    ResourceRecordSet::builder()
                        .name(&name)
                        .r#type(RrType::Txt)
                        .ttl(300)
                        .resource_records(
                            ResourceRecord::builder()
                                .value(format!("\"{}\"", value))
                                .build()
                                .map_err(|e| {
                                    tracing::error!(
                                        "Failed to build Route53 resource record: {}",
                                        e
                                    );
                                    AcmeError::configuration(format!("Route53 build error: {}", e))
                                })?,
                        )
                        .build()
                        .map_err(|e| {
                            tracing::error!("Failed to build Route53 record set: {}", e);
                            AcmeError::configuration(format!("Route53 build error: {}", e))
                        })?,
                )
                .build()
                .map_err(|e| {
                    tracing::error!("Failed to build Route53 change: {}", e);
                    AcmeError::configuration(format!("Route53 build error: {}", e))
                })?;

            let batch = ChangeBatch::builder()
                .changes(change)
                .build()
                .map_err(|e| {
                    tracing::error!("Failed to build Route53 change batch: {}", e);
                    AcmeError::configuration(format!("Route53 build error: {}", e))
                })?;

            self.client
                .change_resource_record_sets()
                .hosted_zone_id(&self.config.hosted_zone_id)
                .change_batch(batch)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("AWS SDK error during Route53 record creation: {}", e);
                    AcmeError::transport(format!("Route53 error: {}", e))
                })?;

            tracing::info!(
                "Successfully submitted Route53 record change for {}",
                domain
            );
            // Return the value as the record_id so we can find it for deletion
            Ok(value.to_string())
        }
        #[cfg(not(feature = "dns-route53"))]
        {
            let _ = (domain, value, &self.config);
            tracing::error!("Attempted to use Route53 without 'dns-route53' feature enabled");
            Err(AcmeError::configuration(
                "Route53 feature not enabled".to_string(),
            ))
        }
    }

    /// Deletes a TXT record from AWS Route53.
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        tracing::info!("Deleting Route53 TXT record for domain: {}", domain);
        #[cfg(feature = "dns-route53")]
        {
            let name = if domain.ends_with('.') {
                domain.to_string()
            } else {
                format!("{}.", domain)
            };

            let change = Change::builder()
                .action(ChangeAction::Delete)
                .resource_record_set(
                    ResourceRecordSet::builder()
                        .name(name)
                        .r#type(RrType::Txt)
                        .ttl(300)
                        .resource_records(
                            ResourceRecord::builder()
                                .value(format!("\"{}\"", record_id))
                                .build()
                                .map_err(|e| {
                                    AcmeError::configuration(format!("Route53 build error: {}", e))
                                })?,
                        )
                        .build()
                        .map_err(|e| {
                            AcmeError::configuration(format!("Route53 build error: {}", e))
                        })?,
                )
                .build()
                .map_err(|e| AcmeError::configuration(format!("Route53 build error: {}", e)))?;

            let batch = ChangeBatch::builder()
                .changes(change)
                .build()
                .map_err(|e| AcmeError::configuration(format!("Route53 build error: {}", e)))?;

            self.client
                .change_resource_record_sets()
                .hosted_zone_id(&self.config.hosted_zone_id)
                .change_batch(batch)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("AWS SDK error during Route53 record deletion: {}", e);
                    AcmeError::transport(format!("Route53 deletion error: {}", e))
                })?;

            tracing::info!(
                "Successfully submitted Route53 record deletion for {}",
                domain
            );
            Ok(())
        }
        #[cfg(not(feature = "dns-route53"))]
        {
            let _ = (domain, record_id, &self.config);
            tracing::error!("Attempted to use Route53 without 'dns-route53' feature enabled");
            Err(AcmeError::configuration(
                "Route53 feature not enabled".to_string(),
            ))
        }
    }

    /// Verifies the record propagation. Route53 changes are asynchronous,
    /// so this currently returns true to allow the ACME server to perform the final check.
    async fn verify_record(&self, _domain: &str, _value: &str) -> Result<bool> {
        tracing::debug!("Route53 record verification skipped (handled by ACME server)");
        Ok(true)
    }
}
