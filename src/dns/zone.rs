//! Zone resolution: SOA walk-up, CNAME following and NS delegation.
//!
//! Zone discovery must never guess by "last two labels" — public suffixes
//! (`co.uk`), delegated sub-zones and `_acme-challenge` CNAME/NS delegation
//! all break that assumption. The algorithm:
//!
//! 1. normalize `_acme-challenge.<base-domain>`;
//! 2. follow CNAMEs (bounded depth, cycle detection);
//! 3. detect NS delegation below the final name;
//! 4. walk up labels querying SOA until an apex answers;
//! 5. resolve the apex's authoritative NS addresses.
//!
//! `FakeZoneResolver` scripts resolutions for tests; `HickoryZoneResolver`
//! performs live queries.

use std::collections::HashSet;
use std::net::IpAddr;

use async_trait::async_trait;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use serde::{Deserialize, Serialize};

use crate::domain::DnsIdentifier;
use crate::error::{AcmeError, Result};

/// Maximum CNAME chain depth before giving up.
pub const MAX_CNAME_DEPTH: usize = 8;

/// The result of resolving a challenge name to its authoritative zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneResolution {
    /// The name resolution started from.
    pub source_name: String,
    /// The name after following CNAMEs (equals source when none).
    pub final_name: String,
    /// CNAME chain entries (`from -> to`).
    #[serde(default)]
    pub cname_chain: Vec<CnameHop>,
    /// The authoritative zone apex found via SOA walk-up.
    pub zone_apex: String,
    /// Authoritative nameserver names for the apex.
    pub authoritative_ns: Vec<String>,
    /// NS delegation detected on the challenge name itself.
    #[serde(default)]
    pub delegated: bool,
}

/// One CNAME hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnameHop {
    /// Source name.
    pub from: String,
    /// Target name.
    pub to: String,
}

/// Computes the `_acme-challenge` record name for a DNS identifier
/// (wildcards use the base name, RFC 8555 §7.4).
pub fn challenge_record_name(identifier: &DnsIdentifier) -> String {
    format!("_acme-challenge.{}", identifier.base_name())
}

/// Normalizes any DNS name (lower-case, no trailing dot).
pub fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The zone-resolution port.
#[async_trait]
pub trait ZoneResolver: Send + Sync {
    /// Resolves a challenge record name to its zone.
    async fn resolve(&self, record_name: &str) -> Result<ZoneResolution>;
}

/// A scripted resolver for tests.
#[derive(Default)]
pub struct FakeZoneResolver {
    /// SOA owners: name -> zone apex (exact match on walk-up).
    pub soa: std::collections::HashMap<String, String>,
    /// CNAME entries: name -> target.
    pub cnames: std::collections::HashMap<String, String>,
    /// NS entries: zone apex -> nameserver names.
    pub ns: std::collections::HashMap<String, Vec<String>>,
    /// NS addresses: nameserver name -> IP.
    pub ns_addrs: std::collections::HashMap<String, Vec<IpAddr>>,
}

impl FakeZoneResolver {
    /// An empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a zone: apex, its nameservers and their addresses.
    pub fn zone(&mut self, apex: &str, nameservers: &[(&str, IpAddr)]) -> &mut Self {
        let apex = normalize_name(apex);
        self.soa.insert(apex.clone(), apex.clone());
        self.ns.insert(
            apex.clone(),
            nameservers.iter().map(|(n, _)| normalize_name(n)).collect(),
        );
        for (name, addr) in nameservers {
            self.ns_addrs
                .entry(normalize_name(name))
                .or_default()
                .push(*addr);
        }
        self
    }

    /// Adds a CNAME delegation hop (`_acme-challenge.example.com` ->
    /// `_acme-challenge.acme.example.net`).
    pub fn cname(&mut self, from: &str, to: &str) -> &mut Self {
        self.cnames.insert(normalize_name(from), normalize_name(to));
        self
    }

    /// Adds an NS delegation for a subzone.
    pub fn delegation(
        &mut self,
        name: &str,
        apex: &str,
        nameservers: &[(&str, IpAddr)],
    ) -> &mut Self {
        let name = normalize_name(name);
        self.ns.insert(
            name.clone(),
            nameservers.iter().map(|(n, _)| normalize_name(n)).collect(),
        );
        self.zone(apex, nameservers);
        // A delegated name has its own SOA.
        self.soa.insert(name.clone(), name);
        self
    }

    /// Walks up labels querying the scripted SOA map.
    pub fn walk_soa(&self, name: &str) -> Option<String> {
        let normalized = normalize_name(name);
        let mut current = normalized.as_str();
        loop {
            if self.soa.contains_key(current) {
                return Some(current.to_string());
            }
            match current.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => current = rest,
                _ => return None,
            }
        }
    }
}

#[async_trait]
impl ZoneResolver for FakeZoneResolver {
    async fn resolve(&self, record_name: &str) -> Result<ZoneResolution> {
        let source = normalize_name(record_name);
        let mut final_name = source.clone();
        let mut cname_chain = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // CNAME following with cycle detection.
        loop {
            if !seen.insert(final_name.clone()) {
                return Err(AcmeError::protocol(format!(
                    "CNAME cycle detected at {final_name}"
                )));
            }
            if cname_chain.len() >= MAX_CNAME_DEPTH {
                return Err(AcmeError::protocol(format!(
                    "CNAME chain exceeds {MAX_CNAME_DEPTH} hops at {final_name}"
                )));
            }
            match self.cnames.get(&final_name) {
                Some(target) => {
                    cname_chain.push(CnameHop {
                        from: final_name.clone(),
                        to: target.clone(),
                    });
                    final_name = target.clone();
                }
                None => break,
            }
        }

        // NS delegation on the challenge name itself.
        let delegated = self.ns.contains_key(&final_name);

        // SOA walk-up from the final name (or its parent when delegated:
        // the delegation point owns the SOA).
        let walk_start = if delegated {
            final_name
                .split_once('.')
                .map(|(_, rest)| rest.to_string())
                .unwrap_or(final_name.clone())
        } else {
            final_name.clone()
        };
        let zone_apex = self
            .walk_soa(&walk_start)
            .ok_or_else(|| AcmeError::protocol(format!("no SOA found for {walk_start}")))?;

        let authoritative_ns = self
            .ns
            .get(if delegated { &final_name } else { &zone_apex })
            .cloned()
            .unwrap_or_default();

        Ok(ZoneResolution {
            source_name: source,
            final_name,
            cname_chain,
            zone_apex,
            authoritative_ns,
            delegated,
        })
    }
}

/// Live resolver over hickory.
pub struct HickoryZoneResolver {
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryZoneResolver {
    /// Creates a resolver using the system configuration.
    pub fn from_system() -> Result<Self> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| AcmeError::protocol(format!("failed to init resolver: {e}")))?
            .build()
            .map_err(|e| AcmeError::protocol(format!("failed to build resolver: {e}")))?;
        Ok(Self { resolver })
    }
}

impl HickoryZoneResolver {
    fn name(name: &str) -> Result<Name> {
        Name::from_utf8(name)
            .map_err(|e| AcmeError::InvalidInput(format!("invalid DNS name {name:?}: {e}")))
    }

    async fn query(&self, name: &str, record_type: RecordType) -> Result<Option<Vec<RData>>> {
        let lookup = self.resolver.lookup(Self::name(name)?, record_type).await;
        match lookup {
            Ok(lookup) => Ok(Some(
                lookup.answers().iter().map(|r| r.data.clone()).collect(),
            )),
            Err(err) if err.is_no_records_found() => Ok(None),
            Err(err) => Err(AcmeError::protocol(format!(
                "DNS query for {name} ({record_type:?}) failed: {err}"
            ))),
        }
    }
}

#[async_trait]
impl ZoneResolver for HickoryZoneResolver {
    async fn resolve(&self, record_name: &str) -> Result<ZoneResolution> {
        let source = normalize_name(record_name);
        let mut final_name = source.clone();
        let mut cname_chain = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        loop {
            if !seen.insert(final_name.clone()) {
                return Err(AcmeError::protocol(format!(
                    "CNAME cycle detected at {final_name}"
                )));
            }
            if cname_chain.len() >= MAX_CNAME_DEPTH {
                return Err(AcmeError::protocol(format!(
                    "CNAME chain exceeds {MAX_CNAME_DEPTH} hops at {final_name}"
                )));
            }
            let records = self.query(&final_name, RecordType::CNAME).await?;
            match records.as_deref().and_then(|records| records.first()) {
                Some(RData::CNAME(cname)) => {
                    let target = cname.0.to_string().to_ascii_lowercase();
                    let target = target.trim_end_matches('.').to_string();
                    cname_chain.push(CnameHop {
                        from: final_name.clone(),
                        to: target.clone(),
                    });
                    final_name = target;
                }
                _ => break,
            }
        }

        // NS delegation on the challenge name.
        let ns_records = self.query(&final_name, RecordType::NS).await?;
        let delegated = matches!(ns_records, Some(records) if !records.is_empty()
            && final_name != normalize_name(final_name.split_once('.').map(|x| x.1).unwrap_or(&final_name)));

        // SOA walk-up.
        let mut current = final_name.clone();
        let zone_apex = loop {
            let soa = self.query(&current, RecordType::SOA).await?;
            if soa.is_some_and(|records| !records.is_empty()) {
                break current;
            }
            match current.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => current = rest.to_string(),
                _ => {
                    return Err(AcmeError::protocol(format!(
                        "no SOA found while walking up from {final_name}"
                    )));
                }
            }
        };

        let ns_owner = if delegated { &final_name } else { &zone_apex };
        let authoritative_ns = self
            .query(ns_owner, RecordType::NS)
            .await?
            .map(|records| {
                records
                    .iter()
                    .filter_map(|r| match r {
                        RData::NS(ns) => {
                            Some(ns.0.to_string().trim_end_matches('.').to_ascii_lowercase())
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(ZoneResolution {
            source_name: source,
            final_name,
            cname_chain,
            zone_apex,
            authoritative_ns,
            delegated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> FakeZoneResolver {
        let mut resolver = FakeZoneResolver::new();
        resolver.zone(
            "example.com",
            &[("ns1.example.com", "192.0.2.53".parse().unwrap())],
        );
        resolver
    }

    #[tokio::test]
    async fn plain_zone_resolution() {
        let resolver = fake();
        let resolution = resolver
            .resolve("_acme-challenge.example.com")
            .await
            .unwrap();
        assert_eq!(resolution.zone_apex, "example.com");
        assert_eq!(
            resolution.authoritative_ns,
            vec!["ns1.example.com".to_string()]
        );
        assert!(!resolution.delegated);
        assert!(resolution.cname_chain.is_empty());
    }

    #[tokio::test]
    async fn deep_subdomain_walks_up_to_apex() {
        let mut resolver = fake();
        resolver.zone(
            "example.com",
            &[("ns1.example.com", "192.0.2.53".parse().unwrap())],
        );
        let resolution = resolver
            .resolve("_acme-challenge.a.b.c.example.com")
            .await
            .unwrap();
        assert_eq!(resolution.zone_apex, "example.com");
    }

    #[tokio::test]
    async fn independent_subzone_is_found_not_the_parent() {
        let mut resolver = fake();
        resolver.zone(
            "sub.example.com",
            &[("ns1.sub.example.com", "192.0.2.54".parse().unwrap())],
        );
        let resolution = resolver
            .resolve("_acme-challenge.sub.example.com")
            .await
            .unwrap();
        assert_eq!(resolution.zone_apex, "sub.example.com");
    }

    #[tokio::test]
    async fn cname_delegation_is_followed() {
        let mut resolver = fake();
        resolver.zone(
            "acme-validator.example.net",
            &[("ns1.example.net", "192.0.2.55".parse().unwrap())],
        );
        resolver.cname(
            "_acme-challenge.example.com",
            "_acme-challenge.acme-validator.example.net",
        );
        let resolution = resolver
            .resolve("_acme-challenge.example.com")
            .await
            .unwrap();
        assert_eq!(
            resolution.final_name,
            "_acme-challenge.acme-validator.example.net"
        );
        assert_eq!(resolution.zone_apex, "acme-validator.example.net");
        assert_eq!(resolution.cname_chain.len(), 1);
    }

    #[tokio::test]
    async fn cname_cycle_is_detected() {
        let mut resolver = fake();
        resolver.zone(
            "example.com",
            &[("ns1.example.com", "192.0.2.53".parse().unwrap())],
        );
        resolver.cname("a.example.com", "b.example.com");
        resolver.cname("b.example.com", "a.example.com");
        let err = resolver.resolve("a.example.com").await.unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[tokio::test]
    async fn ns_delegation_is_detected() {
        let mut resolver = fake();
        resolver.delegation(
            "_acme-challenge.example.com",
            "example.com",
            &[("ns1.validator.example.org", "192.0.2.56".parse().unwrap())],
        );
        // Remove the plain zone SOA so walk-up from the parent finds example.com.
        let resolution = resolver
            .resolve("_acme-challenge.example.com")
            .await
            .unwrap();
        assert!(resolution.delegated);
        assert_eq!(
            resolution.authoritative_ns,
            vec!["ns1.validator.example.org".to_string()]
        );
    }

    #[test]
    fn challenge_name_generation() {
        let plain = DnsIdentifier::parse("example.com").unwrap();
        assert_eq!(challenge_record_name(&plain), "_acme-challenge.example.com");
        let wildcard = DnsIdentifier::parse("*.example.com").unwrap();
        assert_eq!(
            challenge_record_name(&wildcard),
            "_acme-challenge.example.com",
            "wildcards validate the base domain"
        );
    }

    #[test]
    fn names_normalize() {
        assert_eq!(normalize_name("WWW.Example.COM."), "www.example.com");
        assert_eq!(normalize_name(" example.com"), "example.com");
    }
}
