//! Provider routing: which provider instance owns a zone.
//!
//! Routing priority (never random):
//! 1. intent selector (explicit provider id);
//! 2. exact zone apex match;
//! 3. longest suffix match;
//! 4. a unique default (single configured provider);
//! 5. ambiguous or empty → explicit configuration error.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{AcmeError, Result};

use super::factory::DnsProviderFactory;
use super::record::DnsRecordProvider;
use super::spec::{DnsProviderSpec, SecretResolver};
use super::zone::normalize_name;

/// Routes zones to provider instances.
pub struct ProviderRouter {
    providers: HashMap<String, Arc<dyn DnsRecordProvider>>,
    specs: Vec<DnsProviderSpec>,
}

/// Builds and holds providers from specs.
pub struct ProviderRouterBuilder {
    factory: Box<dyn DnsProviderFactory>,
    secrets: Box<dyn SecretResolver>,
    specs: Vec<DnsProviderSpec>,
}

impl ProviderRouterBuilder {
    /// Uses the default factory.
    pub fn new(secrets: Box<dyn SecretResolver>) -> Self {
        Self {
            factory: Box::new(super::factory::DefaultDnsProviderFactory),
            secrets,
            specs: Vec::new(),
        }
    }

    /// Uses a custom factory.
    pub fn with_factory(
        factory: Box<dyn DnsProviderFactory>,
        secrets: Box<dyn SecretResolver>,
    ) -> Self {
        Self {
            factory,
            secrets,
            specs: Vec::new(),
        }
    }

    /// Adds a provider spec.
    pub fn provider(mut self, spec: DnsProviderSpec) -> Self {
        self.specs.push(spec);
        self
    }

    /// Adds many provider specs.
    pub fn with_specs(mut self, specs: Vec<DnsProviderSpec>) -> Self {
        self.specs.extend(specs);
        self
    }

    /// Instantiates all providers and builds the router.
    pub fn build(self) -> Result<ProviderRouter> {
        let mut providers = HashMap::new();
        for spec in &self.specs {
            let provider = self.factory.create(spec, self.secrets.as_ref())?;
            providers.insert(spec.id.clone(), provider);
        }
        Ok(ProviderRouter {
            providers,
            specs: self.specs,
        })
    }
}

impl ProviderRouter {
    /// Routes a zone to its provider.
    pub fn route(
        &self,
        zone_apex: &str,
        selector: Option<&str>,
    ) -> Result<Arc<dyn DnsRecordProvider>> {
        let zone = normalize_name(zone_apex);

        // 1. Explicit selector.
        if let Some(id) = selector {
            return self.providers.get(id).cloned().ok_or_else(|| {
                AcmeError::Configuration(format!(
                    "validation policy selects DNS provider `{id}` which is not configured"
                ))
            });
        }

        // 2. Exact apex match.
        let exact: Vec<_> = self
            .specs
            .iter()
            .filter(|spec| spec.zones.iter().any(|z| normalize_name(z) == zone))
            .collect();
        if exact.len() == 1 {
            return Ok(self.providers[&exact[0].id].clone());
        }
        if exact.len() > 1 {
            return Err(AcmeError::Configuration(format!(
                "multiple providers claim zone `{zone}` exactly: {}",
                exact
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        // 3. Longest suffix match.
        let suffix_hits: Vec<(usize, &DnsProviderSpec)> = self
            .specs
            .iter()
            .filter_map(|spec| {
                spec.zone_suffixes
                    .iter()
                    .map(|s| normalize_name(s))
                    // A suffix selector matches when the apex *is* the
                    // selector or lies beneath it.
                    .filter(|s| zone == *s || zone.ends_with(&format!(".{s}")))
                    .map(|s| s.len())
                    .max()
                    .map(|len| (len, spec))
            })
            .collect();
        if suffix_hits.len() == 1 {
            return Ok(self.providers[&suffix_hits[0].1.id].clone());
        }
        if suffix_hits.len() > 1 {
            let longest = suffix_hits.iter().map(|(l, _)| *l).max().unwrap_or(0);
            let tied: Vec<&str> = suffix_hits
                .iter()
                .filter(|(l, _)| *l == longest)
                .map(|(_, s)| s.id.as_str())
                .collect();
            if tied.len() == 1 {
                return Ok(self.providers[&suffix_hits
                    .iter()
                    .find(|(l, _)| *l == longest)
                    .unwrap()
                    .1
                    .id]
                    .clone());
            }
            return Err(AcmeError::Configuration(format!(
                "ambiguous providers for zone `{zone}`: {}",
                tied.join(", ")
            )));
        }

        // 4. Unique default.
        if self.specs.len() == 1 {
            return Ok(self.providers[&self.specs[0].id].clone());
        }
        Err(AcmeError::Configuration(format!(
            "no DNS provider configured for zone `{zone}` ({} provider(s) configured)",
            self.specs.len()
        )))
    }

    /// The configured provider ids.
    pub fn provider_ids(&self) -> Vec<String> {
        self.specs.iter().map(|s| s.id.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::spec::EnvFileSecretResolver;

    fn spec(id: &str, provider_type: &str, zones: &[&str], suffixes: &[&str]) -> DnsProviderSpec {
        DnsProviderSpec {
            id: id.to_string(),
            provider_type: provider_type.to_string(),
            credential: None,
            zones: zones.iter().map(|z| z.to_string()).collect(),
            zone_suffixes: suffixes.iter().map(|z| z.to_string()).collect(),
            endpoint: None,
            timeout_secs: 30,
            extra: Default::default(),
        }
    }

    fn router(specs: Vec<DnsProviderSpec>) -> ProviderRouter {
        ProviderRouterBuilder::new(Box::new(EnvFileSecretResolver))
            .with_specs(specs)
            .build()
            .unwrap()
    }

    #[test]
    fn selector_wins() {
        let router = router(vec![
            spec("a", "fake", &["example.com"], &[]),
            spec("b", "fake", &["example.com"], &[]),
        ]);
        let picked = router.route("example.com", Some("b")).unwrap();
        assert_eq!(picked.provider_id(), "b");
    }

    #[test]
    fn ambiguous_exact_zones_error() {
        let router = router(vec![
            spec("a", "fake", &["example.com"], &[]),
            spec("b", "fake", &["example.com"], &[]),
        ]);
        let err = router
            .route("example.com", None)
            .err()
            .expect("ambiguous routing must fail");
        assert!(err.to_string().contains("multiple providers"));
    }

    #[test]
    fn longest_suffix_wins() {
        let router = router(vec![
            spec("generic", "fake", &[], &["example.org"]),
            spec("internal", "fake", &[], &["internal.example.org"]),
        ]);
        let picked = router.route("host.internal.example.org", None).unwrap();
        assert_eq!(picked.provider_id(), "internal");
    }

    #[test]
    fn single_provider_is_default() {
        let router = router(vec![spec("only", "fake", &["other.com"], &[])]);
        let picked = router.route("unrelated.net", None).unwrap();
        assert_eq!(picked.provider_id(), "only");
    }

    #[test]
    fn no_match_with_multiple_providers_errors() {
        let router = router(vec![
            spec("a", "fake", &["example.com"], &[]),
            spec("b", "fake", &["example.net"], &[]),
        ]);
        let err = router
            .route("example.org", None)
            .err()
            .expect("no-provider routing must fail");
        assert!(err.to_string().contains("no DNS provider"));
    }

    #[test]
    fn unknown_selector_errors() {
        let router = router(vec![spec("a", "fake", &["example.com"], &[])]);
        assert!(router.route("example.com", Some("ghost")).is_err());
    }
}
