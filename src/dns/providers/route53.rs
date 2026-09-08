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

    /// Verifies record propagation by querying the hosted zone: the TXT
    /// record must exist and carry the expected value. Route53 only lists
    /// applied changes, so a listed, matching record is effectively INSYNC.
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool> {
        tracing::debug!("Verifying Route53 TXT record for domain: {}", domain);
        #[cfg(feature = "dns-route53")]
        {
            let name = if domain.ends_with('.') {
                domain.to_string()
            } else {
                format!("{}.", domain)
            };

            let response = self
                .client
                .list_resource_record_sets()
                .hosted_zone_id(&self.config.hosted_zone_id)
                .start_record_name(&name)
                .start_record_type(RrType::Txt)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("AWS SDK error during Route53 record verification: {}", e);
                    AcmeError::transport(format!("Route53 verification error: {}", e))
                })?;

            // Records are returned in lexicographic order starting at the
            // queried name; a missing record simply ends the matching run.
            for record_set in response.resource_record_sets() {
                if !names_match(record_set.name(), &name) || record_set.r#type() != &RrType::Txt {
                    continue;
                }
                for record in record_set.resource_records() {
                    if txt_value_matches(record.value(), value) {
                        tracing::debug!("Route53 TXT record for {} verified", domain);
                        return Ok(true);
                    }
                }
            }
            tracing::debug!(
                "Route53 TXT record for {} not found or value mismatch",
                domain
            );
            Ok(false)
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
}

/// Case-insensitive DNS name comparison with trailing-dot normalization.
#[cfg(feature = "dns-route53")]
fn names_match(returned: &str, expected: &str) -> bool {
    let normalize = |name: &str| name.trim_end_matches('.').to_ascii_lowercase();
    normalize(returned) == normalize(expected)
}

/// Compares a Route53 TXT record value (quoted, possibly split into multiple
/// character-string chunks) with the expected challenge value.
#[cfg(feature = "dns-route53")]
fn txt_value_matches(record_value: &str, expected: &str) -> bool {
    let joined: String = record_value
        .split('"')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, chunk)| chunk)
        .collect();
    joined == expected
}

#[cfg(all(test, feature = "dns-route53"))]
mod tests {
    use super::*;
    use aws_sdk_route53::config::{BehaviorVersion, Credentials, Region};

    const RECORD_SETS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>_acme-challenge.example.com.</Name>
      <Type>TXT</Type>
      <TTL>300</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>"challenge-token-value"</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>example.com.</Name>
      <Type>NS</Type>
      <TTL>172800</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>ns-1.awsdns-00.net.</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>split.example.com.</Name>
      <Type>TXT</Type>
      <TTL>300</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>"part1" "part2"</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#;

    const ERROR_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Error>
    <Type>Sender</Type>
    <Code>NoSuchHostedZone</Code>
    <Message>The specified hosted zone does not exist.</Message>
  </Error>
  <RequestId>req-1</RequestId>
</ErrorResponse>"#;

    /// Builds the provider against a local fake AWS endpoint; the AWS
    /// signature headers are irrelevant to the fake and use static
    /// test-only credentials.
    async fn provider_against(endpoint: &str) -> Route53DnsProvider {
        let config = aws_sdk_route53::config::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "route53-unit-test",
            ))
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .build();
        Route53DnsProvider {
            config: Route53Config {
                hosted_zone_id: "Z1234567890".to_string(),
            },
            client: aws_sdk_route53::Client::from_conf(config),
        }
    }

    #[tokio::test]
    async fn verify_record_matches_txt_value_against_the_zone() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", "/2013-04-01/hostedzone/Z1234567890/rrset")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "text/xml")
            .with_body(RECORD_SETS_XML)
            .create_async()
            .await;
        let provider = provider_against(&server.url()).await;

        // Exact value match on the queried name.
        let verified = provider
            .verify_record("_acme-challenge.example.com", "challenge-token-value")
            .await
            .unwrap();
        assert!(verified, "matching TXT value must verify");

        // A different value on the same name must not pass.
        let mismatch = provider
            .verify_record("_acme-challenge.example.com", "other-token")
            .await
            .unwrap();
        assert!(!mismatch, "value mismatch must not verify");

        // Split TXT character-string chunks are concatenated before compare.
        let joined = provider
            .verify_record("split.example.com", "part1part2")
            .await
            .unwrap();
        assert!(joined, "split character strings must join for compare");

        // A name absent from the response must not verify.
        let absent = provider
            .verify_record("missing.example.com", "challenge-token-value")
            .await
            .unwrap();
        assert!(!absent, "absent names must not verify");
    }

    #[tokio::test]
    async fn verify_record_classifies_api_failures_as_errors() {
        let mut server = mockito::Server::new_async().await;
        let _error_mock = server
            .mock("GET", "/2013-04-01/hostedzone/Z1234567890/rrset")
            .match_query(mockito::Matcher::Any)
            .with_status(403)
            .with_header("content-type", "text/xml")
            .with_body(ERROR_XML)
            .create_async()
            .await;
        let provider = provider_against(&server.url()).await;

        let outcome = provider
            .verify_record("_acme-challenge.example.com", "challenge-token-value")
            .await;
        assert!(
            outcome.is_err(),
            "API failures must surface as classified errors, not Ok(false)"
        );
    }

    #[test]
    fn txt_value_comparison_concatenates_quoted_chunks() {
        assert!(txt_value_matches("\"abc\"", "abc"));
        assert!(txt_value_matches("\"ab\" \"cd\"", "abcd"));
        assert!(!txt_value_matches("\"abc\"", "abcd"));
        assert!(!txt_value_matches("\"abc\" \"de\"", "abcde f"));
    }
}
