//! DNS provider factory: providers are assembled from configuration.
//!
//! Feature flags gate which provider *types* can be created; asking for a
//! type that is not compiled in is an explicit configuration error — the
//! factory never silently substitutes another provider.
//!
//! Credential conventions:
//! - the primary credential is the spec's `credential` [`SecretRef`];
//! - providers needing more than one secret take the additional ones from
//!   `extra` entries whose value is itself a secret *reference* string
//!   (`env:NAME`, `file:/path`, `vault:…`, `provider:…`). Literal secrets in
//!   `extra` are rejected.
//! - non-secret settings (region, hosted zone, project id, …) are plain
//!   `extra` entries.

//!
//! # Example
//!
//! ```no_run
//! use acmex::dns::factory::{DefaultDnsProviderFactory, DnsProviderFactory};
//! use acmex::dns::spec::{DnsProviderSpec, EnvFileSecretResolver, SecretRef};
//! use std::collections::HashMap;
//!
//! # async fn example() -> acmex::Result<()> {
//! let spec = DnsProviderSpec {
//!     id: "cf-prod".to_string(),
//!     provider_type: "cloudflare".to_string(),
//!     credential: Some(SecretRef::parse("env:CF_DNS_TOKEN")?),
//!     zones: vec!["example.com".to_string()],
//!     zone_suffixes: Vec::new(),
//!     endpoint: None,
//!     timeout_secs: 30,
//!     extra: HashMap::new(),
//! };
//! let provider = DefaultDnsProviderFactory
//!     .create(&spec, &EnvFileSecretResolver)
//!     .await?; // Err(Configuration) when the feature/credentials are absent
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{AcmeError, Result};

use super::record::{
    DnsRecordLocator, DnsRecordProvider, PresentTxt, RecordCleanupOutcome, TxtRecord,
};
use super::spec::{DnsProviderSpec, SecretRef, SecretResolver};

/// Creates providers from specs.
#[async_trait]
pub trait DnsProviderFactory: Send + Sync {
    /// Builds a provider instance. Credential resolution happens here.
    async fn create(
        &self,
        spec: &DnsProviderSpec,
        secrets: &dyn SecretResolver,
    ) -> Result<Arc<dyn DnsRecordProvider>>;
}

/// The default factory: `fake` always available; cloud providers behind
/// their feature flags via the legacy-adapter.
#[derive(Default)]
pub struct DefaultDnsProviderFactory;

impl DefaultDnsProviderFactory {
    /// Provider types this build can actually create. Callers (and tests)
    /// use this to interpret factory errors without knowing feature flags.
    pub fn supported_types() -> &'static [&'static str] {
        &[
            "fake",
            "memory",
            #[cfg(feature = "dns-cloudflare")]
            "cloudflare",
            #[cfg(feature = "dns-route53")]
            "route53",
            #[cfg(feature = "dns-digitalocean")]
            "digitalocean",
            #[cfg(feature = "dns-linode")]
            "linode",
            #[cfg(feature = "dns-azure")]
            "azure",
            #[cfg(feature = "dns-google")]
            "google",
            #[cfg(feature = "dns-alibaba")]
            "alibaba",
            #[cfg(feature = "dns-godaddy")]
            "godaddy",
            #[cfg(feature = "dns-tencent")]
            "tencent",
            #[cfg(feature = "dns-huawei")]
            "huawei",
            #[cfg(feature = "dns-cloudns")]
            "cloudns",
        ]
    }

    /// Every provider type AcmeX recognizes, including ones whose cargo
    /// feature is disabled in this build.
    pub fn known_types() -> &'static [&'static str] {
        &[
            "fake",
            "memory",
            "cloudflare",
            "route53",
            "digitalocean",
            "linode",
            "azure",
            "google",
            "alibaba",
            "godaddy",
            "tencent",
            "huawei",
            "cloudns",
        ]
    }

    /// A non-secret `extra` entry.
    // These helpers are only reachable from provider branches, so builds
    // with no provider feature compiled in legitimately never call them.
    #[allow(dead_code)]
    fn require_extra<'a>(spec: &'a DnsProviderSpec, key: &str) -> Result<&'a str> {
        spec.extra.get(key).map(String::as_str).ok_or_else(|| {
            AcmeError::Configuration(format!(
                "provider `{}` ({}) needs `extra.{key}`",
                spec.id, spec.provider_type
            ))
        })
    }

    /// Resolves a secret-valued `extra` entry; the value must be a secret
    /// reference (`env:`/`file:`/`vault:`/`provider:`), never a literal.
    #[allow(dead_code)]
    async fn resolve_extra_secret(
        spec: &DnsProviderSpec,
        secrets: &dyn SecretResolver,
        key: &str,
    ) -> Result<String> {
        let raw = Self::require_extra(spec, key)?;
        let reference = SecretRef::parse(raw).map_err(|_| {
            AcmeError::Configuration(format!(
                "provider `{}` extra.{key} must be a secret reference (env:/file:/vault:/provider:), not a literal value",
                spec.id
            ))
        })?;
        resolved_secret(spec, secrets, &reference).await
    }
}

/// Resolves the spec's primary credential to a UTF-8 string.
#[allow(dead_code)]
async fn resolved_secret(
    spec: &DnsProviderSpec,
    secrets: &dyn SecretResolver,
    reference: &SecretRef,
) -> Result<String> {
    let value = secrets.resolve(reference).await?;
    value.expose_utf8().map(str::to_string).ok_or_else(|| {
        AcmeError::Configuration(format!(
            "provider `{}` credential {} is not valid UTF-8",
            spec.id,
            reference.describe()
        ))
    })
}

/// Resolves the primary credential or fails with a stable message.
#[allow(dead_code)]
async fn require_primary_credential(
    spec: &DnsProviderSpec,
    secrets: &dyn SecretResolver,
) -> Result<String> {
    let reference = spec.credential.as_ref().ok_or_else(|| {
        AcmeError::Configuration(format!(
            "provider `{}` ({}) needs a credential reference",
            spec.id, spec.provider_type
        ))
    })?;
    resolved_secret(spec, secrets, reference).await
}

#[async_trait]
impl DnsProviderFactory for DefaultDnsProviderFactory {
    // `secrets` is only consumed by provider-specific branches.
    #[allow(unused_variables)]
    async fn create(
        &self,
        spec: &DnsProviderSpec,
        secrets: &dyn SecretResolver,
    ) -> Result<Arc<dyn DnsRecordProvider>> {
        match spec.provider_type.as_str() {
            "fake" | "memory" => Ok(Arc::new(super::record::FakeDnsRecordProvider::new(
                spec.id.clone(),
            ))),
            #[cfg(feature = "dns-cloudflare")]
            "cloudflare" => {
                let token = require_primary_credential(spec, secrets).await?;
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::CloudFlareDnsProvider::new(
                        crate::dns::providers::cloudflare::CloudFlareConfig {
                            api_token: token,
                            zone_id: spec.extra.get("zone_id").cloned().unwrap_or_default(),
                        },
                    )),
                )))
            }
            #[cfg(feature = "dns-route53")]
            "route53" => {
                // AWS credentials come from the SDK default chain (env,
                // shared config, instance role); the hosted zone is explicit.
                let hosted_zone_id = Self::require_extra(spec, "hosted_zone_id")?.to_string();
                let provider = crate::dns::providers::Route53DnsProvider::new(
                    crate::dns::providers::route53::Route53Config { hosted_zone_id },
                )
                .await;
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(provider),
                )))
            }
            #[cfg(feature = "dns-digitalocean")]
            "digitalocean" => {
                let token = require_primary_credential(spec, secrets).await?;
                let domain = Self::require_extra(spec, "domain")?.to_string();
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::DigitalOceanDnsProvider::new(
                        crate::dns::providers::digitalocean::DigitalOceanConfig {
                            api_token: token,
                            domain,
                        },
                    )),
                )))
            }
            #[cfg(feature = "dns-linode")]
            "linode" => {
                let token = require_primary_credential(spec, secrets).await?;
                let domain_id = Self::require_extra(spec, "domain_id")?
                    .parse::<u64>()
                    .map_err(|_| {
                        AcmeError::Configuration(format!(
                            "provider `{}` extra.domain_id must be a numeric Linode domain id",
                            spec.id
                        ))
                    })?;
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::LinodeDnsProvider::new(
                        crate::dns::providers::linode::LinodeConfig {
                            api_token: token,
                            domain_id,
                        },
                    )),
                )))
            }
            #[cfg(feature = "dns-azure")]
            "azure" => {
                let client_secret = require_primary_credential(spec, secrets).await?;
                let subscription_id = Self::require_extra(spec, "subscription_id")?.to_string();
                let resource_group = Self::require_extra(spec, "resource_group")?.to_string();
                let client_id = Self::require_extra(spec, "client_id")?.to_string();
                let tenant_id = Self::require_extra(spec, "tenant_id")?.to_string();
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::AzureDnsProvider::new(
                        subscription_id,
                        resource_group,
                        client_id,
                        client_secret,
                        tenant_id,
                    )),
                )))
            }
            #[cfg(feature = "dns-google")]
            "google" => {
                let project_id = Self::require_extra(spec, "project_id")?.to_string();
                let mut provider = crate::dns::providers::GoogleCloudDnsProvider::new(project_id);
                if let Some(path) = spec.extra.get("service_account_json") {
                    provider = provider.with_service_account(path.clone());
                }
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(provider),
                )))
            }
            #[cfg(feature = "dns-alibaba")]
            "alibaba" => {
                let access_key_id = require_primary_credential(spec, secrets).await?;
                let access_key_secret =
                    Self::resolve_extra_secret(spec, secrets, "access_key_secret").await?;
                let region = Self::require_extra(spec, "region")?.to_string();
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::AlibabaCloudDnsProvider::new(
                        access_key_id,
                        access_key_secret,
                        region,
                    )),
                )))
            }
            #[cfg(feature = "dns-godaddy")]
            "godaddy" => {
                let api_key = require_primary_credential(spec, secrets).await?;
                let api_secret = Self::resolve_extra_secret(spec, secrets, "api_secret").await?;
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::GodaddyDnsProvider::new(
                        api_key, api_secret,
                    )),
                )))
            }
            #[cfg(feature = "dns-tencent")]
            "tencent" => {
                let secret_id = require_primary_credential(spec, secrets).await?;
                let secret_key = Self::resolve_extra_secret(spec, secrets, "secret_key").await?;
                let region = Self::require_extra(spec, "region")?.to_string();
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::TencentCloudDnsProvider::new(
                        secret_id, secret_key, region,
                    )),
                )))
            }
            #[cfg(feature = "dns-huawei")]
            "huawei" => {
                let access_key = require_primary_credential(spec, secrets).await?;
                let secret_key = Self::resolve_extra_secret(spec, secrets, "secret_key").await?;
                let project_id = Self::require_extra(spec, "project_id")?.to_string();
                let region = Self::require_extra(spec, "region")?.to_string();
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::HuaweiCloudDnsProvider::new(
                        access_key, secret_key, project_id, region,
                    )),
                )))
            }
            #[cfg(feature = "dns-cloudns")]
            "cloudns" => {
                let auth_id = require_primary_credential(spec, secrets).await?;
                let auth_password =
                    Self::resolve_extra_secret(spec, secrets, "auth_password").await?;
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::ClouDnsProvider::new(
                        auth_id,
                        auth_password,
                    )),
                )))
            }
            other => {
                let known = Self::known_types();
                let supported = Self::supported_types();
                if known.contains(&other) && !supported.contains(&other) {
                    Err(AcmeError::Configuration(format!(
                        "provider type `{other}` requires its cargo feature to be enabled (`dns-{other}`)"
                    )))
                } else if known.contains(&other) {
                    Err(AcmeError::Configuration(format!(
                        "provider type `{other}` is recognized but this build has no factory branch; this is a bug"
                    )))
                } else {
                    Err(AcmeError::Configuration(format!(
                        "unknown DNS provider type `{other}` (supported in this build: {supported:?})"
                    )))
                }
            }
        }
    }
}

/// Adapts a legacy `DnsProvider` (create/delete/verify by domain) to the
/// record port. The legacy API's create returns a record id which becomes
/// part of the locator — cleanup deletes exactly that id.
pub struct LegacyProviderAdapter {
    provider_id: String,
    inner: Box<dyn crate::challenge::DnsProvider>,
}

impl LegacyProviderAdapter {
    /// Wraps a legacy provider.
    pub fn new(
        provider_id: impl Into<String>,
        inner: Box<dyn crate::challenge::DnsProvider>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            inner,
        }
    }
}

#[async_trait]
impl DnsRecordProvider for LegacyProviderAdapter {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    async fn present_txt(&self, request: PresentTxt) -> Result<DnsRecordLocator> {
        let record_id = self
            .inner
            .create_txt_record(&request.record_name, &request.value)
            .await?;
        Ok(DnsRecordLocator {
            provider_id: self.provider_id.clone(),
            zone: request.zone,
            record_name: request.record_name,
            record_id: Some(record_id),
            value_hash: super::record::txt_value_hash(&request.value),
        })
    }

    async fn get_txt(&self, locator: &DnsRecordLocator) -> Result<Option<TxtRecord>> {
        // The legacy port has no read; approximate with verify over an
        // empty value so callers still get a shape (values unknown).
        let _ = self.inner.verify_record(&locator.record_name, "").await;
        Ok(None)
    }

    async fn cleanup_txt(&self, locator: &DnsRecordLocator) -> Result<RecordCleanupOutcome> {
        match locator.record_id.as_deref() {
            Some(record_id) => {
                self.inner
                    .delete_txt_record(&locator.record_name, record_id)
                    .await?;
                Ok(RecordCleanupOutcome::Removed)
            }
            None => Ok(RecordCleanupOutcome::AlreadyAbsent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::spec::EnvFileSecretResolver;
    use super::*;

    fn spec(provider_type: &str) -> DnsProviderSpec {
        DnsProviderSpec {
            id: "test".to_string(),
            provider_type: provider_type.to_string(),
            credential: None,
            zones: vec![],
            zone_suffixes: vec![],
            endpoint: None,
            timeout_secs: 30,
            extra: Default::default(),
        }
    }

    #[test]
    fn known_types_are_a_superset_of_supported_types() {
        for supported in DefaultDnsProviderFactory::supported_types() {
            assert!(
                DefaultDnsProviderFactory::known_types().contains(supported),
                "supported type `{supported}` must be known"
            );
        }
    }

    #[tokio::test]
    async fn unknown_type_names_the_supported_set() {
        let factory = DefaultDnsProviderFactory;
        let err = match factory
            .create(&spec("not-a-provider"), &EnvFileSecretResolver)
            .await
        {
            Ok(_) => panic!("unknown provider type must not be created"),
            Err(err) => err,
        };
        let text = err.to_string();
        assert!(text.contains("unknown DNS provider type"), "{text}");
        assert!(text.contains("fake"), "{text}");
    }

    #[tokio::test]
    async fn known_types_are_created_or_report_the_feature_never_unknown() {
        let factory = DefaultDnsProviderFactory;
        let secrets = EnvFileSecretResolver;
        for known in DefaultDnsProviderFactory::known_types() {
            let err = match factory.create(&spec(known), &secrets).await {
                Ok(provider) => {
                    assert!(
                        DefaultDnsProviderFactory::supported_types().contains(known),
                        "creating `{known}` succeeded so it must be listed as supported"
                    );
                    assert_eq!(provider.provider_id(), "test");
                    continue;
                }
                Err(err) => err,
            };
            let text = err.to_string();
            let feature_gated = text.contains("requires its cargo feature");
            let missing_inputs = text.contains("needs a credential reference")
                || text.contains("needs `extra.")
                || text.contains("must be a secret reference");
            assert!(
                feature_gated || missing_inputs,
                "type `{known}` must be creatable, feature-gated or fail on missing inputs; got: {text}"
            );
        }
    }

    #[tokio::test]
    async fn literal_secrets_in_extra_are_rejected() {
        let factory = DefaultDnsProviderFactory;
        let mut credential_path = std::env::temp_dir();
        credential_path.push("acmex-factory-test-godaddy-key");
        std::fs::write(&credential_path, "test-api-key\n").unwrap();
        let mut godaddy = spec("godaddy");
        godaddy.credential = Some(SecretRef::File {
            path: credential_path.clone(),
        });
        godaddy
            .extra
            .insert("api_secret".to_string(), "plain-literal".to_string());
        let err = match factory.create(&godaddy, &EnvFileSecretResolver).await {
            Ok(_) => panic!("a literal secret in extra must never be accepted"),
            Err(err) => err,
        };
        let _ = std::fs::remove_file(&credential_path);
        let text = err.to_string();
        if DefaultDnsProviderFactory::supported_types().contains(&"godaddy") {
            // The primary credential resolved fine, so the literal in extra
            // is what must be rejected here.
            assert!(text.contains("must be a secret reference"), "{text}");
        } else {
            // Feature-off builds report the gate first — never a silent pass.
            assert!(text.contains("requires its cargo feature"), "{text}");
        }
    }
}
