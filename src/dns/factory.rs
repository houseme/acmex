//! DNS provider factory: providers are assembled from configuration.
//!
//! Feature flags gate which provider *types* can be created; asking for a
//! type that is not compiled in is an explicit configuration error — the
//! factory never silently substitutes another provider.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{AcmeError, Result};

use super::record::{
    DnsRecordLocator, DnsRecordProvider, PresentTxt, RecordCleanupOutcome, TxtRecord,
};
use super::spec::{DnsProviderSpec, SecretResolver};

/// Creates providers from specs.
#[async_trait]
pub trait DnsProviderFactory: Send + Sync {
    /// Builds a provider instance. Credential resolution happens here.
    fn create(
        &self,
        spec: &DnsProviderSpec,
        secrets: &dyn SecretResolver,
    ) -> Result<Arc<dyn DnsRecordProvider>>;
}

/// The default factory: `fake` always available; cloud providers behind
/// their feature flags via the legacy-adapter.
#[derive(Default)]
pub struct DefaultDnsProviderFactory;

#[async_trait]
impl DnsProviderFactory for DefaultDnsProviderFactory {
    fn create(
        &self,
        spec: &DnsProviderSpec,
        _secrets: &dyn SecretResolver,
    ) -> Result<Arc<dyn DnsRecordProvider>> {
        match spec.provider_type.as_str() {
            "fake" | "memory" => Ok(Arc::new(super::record::FakeDnsRecordProvider::new(
                spec.id.clone(),
            ))),
            #[cfg(feature = "dns-cloudflare")]
            "cloudflare" => {
                let credential = spec.credential.as_ref().ok_or_else(|| {
                    AcmeError::Configuration(format!(
                        "provider `{}` needs a credential reference",
                        spec.id
                    ))
                })?;
                let token = _secrets.resolve(credential)?;
                let token = token.expose_utf8().ok_or_else(|| {
                    AcmeError::Configuration("credential is not valid UTF-8".to_string())
                })?;
                Ok(Arc::new(LegacyProviderAdapter::new(
                    spec.id.clone(),
                    Box::new(crate::dns::providers::CloudFlareDnsProvider::new(
                        crate::dns::providers::cloudflare::CloudFlareConfig {
                            api_token: token.to_string(),
                            zone_id: spec.extra.get("zone_id").cloned().unwrap_or_default(),
                        },
                    )),
                )))
            }
            other => {
                let known_types = [
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
                ];
                if known_types.contains(&other) {
                    Err(AcmeError::Configuration(format!(
                        "provider type `{other}` requires its cargo feature to be enabled"
                    )))
                } else {
                    Err(AcmeError::Configuration(format!(
                        "unknown DNS provider type `{other}`"
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
