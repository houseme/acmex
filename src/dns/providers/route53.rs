use crate::DnsProvider;
use crate::error::{AcmeError, Result};
/// Route53 DNS provider
use async_trait::async_trait;
#[cfg(feature = "dns-route53")]
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, RrType, ResourceRecord, ResourceRecordSet,
};

/// Route53 DNS provider configuration
#[derive(Debug, Clone)]
pub struct Route53Config {
    pub hosted_zone_id: String,
}

/// Route53 DNS provider
pub struct Route53DnsProvider {
    #[allow(dead_code)]
    config: Route53Config,
    #[cfg(feature = "dns-route53")]
    client: aws_sdk_route53::Client,
}

impl Route53DnsProvider {
    #[cfg(feature = "dns-route53")]
    pub async fn new(config: Route53Config) -> Self {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_route53::Client::new(&sdk_config);
        Self { config, client }
    }

    #[cfg(not(feature = "dns-route53"))]
    pub fn new(config: Route53Config) -> Self {
        Self { config }
    }
}

#[async_trait]
impl DnsProvider for Route53DnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
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
                                .build()?,
                        )
                        .build()?,
                )
                .build()?;

            let batch = ChangeBatch::builder().changes(change).build()?;

            self.client
                .change_resource_record_sets()
                .hosted_zone_id(&self.config.hosted_zone_id)
                .change_batch(batch)
                .send()
                .await
                .map_err(|e| AcmeError::transport(format!("Route53 error: {}", e)))?;

            // Return the value as the record_id so we can find it for deletion
            Ok(value.to_string())
        }
        #[cfg(not(feature = "dns-route53"))]
        {
            let _ = (domain, value, &self.config);
            Err(AcmeError::configuration(
                "Route53 feature not enabled".to_string(),
            ))
        }
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        #[cfg(feature = "dns-route53")]
        {
            let name = if domain.ends_with('.') {
                domain.to_string()
            } else {
                format!("{}.", domain)
            };

            // To delete, we need the exact record set.
            // We'll use the record_id (which is the value) to construct the deletion change.
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
                                .build()?,
                        )
                        .build()?,
                )
                .build()?;

            let batch = ChangeBatch::builder().changes(change).build()?;

            self.client
                .change_resource_record_sets()
                .hosted_zone_id(&self.config.hosted_zone_id)
                .change_batch(batch)
                .send()
                .await
                .map_err(|e| AcmeError::transport(format!("Route53 deletion error: {}", e)))?;

            Ok(())
        }
        #[cfg(not(feature = "dns-route53"))]
        {
            let _ = (domain, record_id, &self.config);
            Err(AcmeError::configuration(
                "Route53 feature not enabled".to_string(),
            ))
        }
    }

    async fn verify_record(&self, _domain: &str, _value: &str) -> Result<bool> {
        Ok(true)
    }
}
