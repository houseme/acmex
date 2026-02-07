/// Route53 DNS provider (stub)
use async_trait::async_trait;

use crate::challenge::DnsProvider;
use crate::error::{AcmeError, Result};

/// Route53 DNS provider configuration
#[derive(Debug, Clone)]
pub struct Route53Config {
    pub hosted_zone_id: String,
}

/// Route53 DNS provider
pub struct Route53DnsProvider {
    config: Route53Config,
}

impl Route53DnsProvider {
    pub fn new(config: Route53Config) -> Self {
        Self { config }
    }
}

#[async_trait]
impl DnsProvider for Route53DnsProvider {
    async fn create_txt_record(&self, _domain: &str, _value: &str) -> Result<String> {
        Err(AcmeError::configuration(
            "Route53 provider requires SigV4 signing. Implement via aws-sdk-route53".to_string(),
        ))
    }

    async fn delete_txt_record(&self, _domain: &str, _record_id: &str) -> Result<()> {
        Err(AcmeError::configuration(
            "Route53 provider requires SigV4 signing. Implement via aws-sdk-route53".to_string(),
        ))
    }

    async fn verify_record(&self, _domain: &str, _value: &str) -> Result<bool> {
        Err(AcmeError::configuration(
            "Route53 provider requires SigV4 signing. Implement via aws-sdk-route53".to_string(),
        ))
    }
}
