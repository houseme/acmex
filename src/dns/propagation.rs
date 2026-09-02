//! Propagation observation: is the TXT value externally visible?
//!
//! Observation queries (a) the authoritative nameservers of the zone and
//! (b) a configured set of recursive resolvers, and applies quorum policy.
//! Reports store only value *hashes* — challenge values never reach logs.
//!
//! `FakePropagationObserver` scripts outcomes for tests; the hickory-based
//! observer performs live queries (authoritative NS first, then recursive).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use serde::{Deserialize, Serialize};

use crate::domain::Quorum;
use crate::error::{AcmeError, Result};

use super::record::txt_value_hash;
use hickory_resolver::proto::rr::{RData, RecordType};

use super::zone::ZoneResolver;

/// What to look for.
///
/// Carries the expected value **hash** (not the raw challenge value), so
/// observation plumbing never moves secrets around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTxt {
    /// Provider id that created the record, used for provider-level policy.
    pub provider_id: Option<String>,
    /// The record name being observed.
    pub record_name: String,
    /// SHA-256 of the expected TXT value.
    pub value_hash: String,
}

/// One query outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryOutcome {
    /// Who was asked (server address or label).
    pub server: String,
    /// Whether the server served the expected value.
    pub matched: bool,
    /// Response classification (no raw values).
    #[serde(rename = "response")]
    pub response_kind: ResponseKind,
    /// Observed TTL, when the record was seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,
    /// Safe resolver error text, when the query failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Classified response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    /// Server answered and the value matched.
    Matched,
    /// Server answered but the value was absent.
    NoData,
    /// Name does not exist.
    NxDomain,
    /// Server failure.
    ServFail,
    /// Query timed out.
    Timeout,
}

/// The observation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropagationReport {
    /// The record name observed.
    pub record_name: String,
    /// Hash of the expected value (log-safe).
    pub value_hash: String,
    /// Authoritative server outcomes.
    pub authoritative: Vec<QueryOutcome>,
    /// Recursive resolver outcomes.
    pub recursive: Vec<QueryOutcome>,
    /// Whether authoritative quorum was satisfied.
    pub authoritative_quorum_reached: bool,
    /// Whether recursive quorum was satisfied, or skipped by empty resolver opt-out.
    pub recursive_quorum_reached: bool,
    /// Whether the quorum policy was satisfied.
    pub quorum_reached: bool,
}

impl PropagationReport {
    /// Hash of the expected value.
    pub fn matched_authoritative(&self) -> usize {
        self.authoritative.iter().filter(|o| o.matched).count()
    }

    /// Matched recursive answers.
    pub fn matched_recursive(&self) -> usize {
        self.recursive.iter().filter(|o| o.matched).count()
    }
}

/// Applies the quorum policy to matched counts.
pub fn quorum_satisfied(matched: usize, total: usize, quorum: Quorum) -> bool {
    if total == 0 {
        return false;
    }
    match quorum {
        Quorum::All => matched == total,
        Quorum::AtLeast(n) => matched >= n,
    }
}

/// The observation port.
#[async_trait]
pub trait DnsPropagationObserver: Send + Sync {
    /// Observes propagation; never modifies anything.
    async fn observe(&self, expected: &ExpectedTxt) -> Result<PropagationReport>;

    /// Suggested delay before re-observing a non-propagated record.
    fn poll_interval(&self, _provider_id: Option<&str>) -> Duration {
        Duration::from_secs(5)
    }
}

/// Scripted observer for tests.
pub struct FakePropagationObserver {
    /// Authoritative outcomes replayed in order.
    authoritative: std::sync::Mutex<Vec<QueryOutcome>>,
    recursive: std::sync::Mutex<Vec<QueryOutcome>>,
    policy: PropagationPolicyV2,
}

impl Default for FakePropagationObserver {
    fn default() -> Self {
        Self {
            authoritative: std::sync::Mutex::new(Vec::new()),
            recursive: std::sync::Mutex::new(Vec::new()),
            policy: PropagationPolicyV2::default(),
        }
    }
}

impl FakePropagationObserver {
    /// An observer that reports everything matched.
    pub fn all_matched() -> Self {
        Self {
            authoritative: std::sync::Mutex::new(vec![QueryOutcome {
                server: "auth-1".to_string(),
                matched: true,
                response_kind: ResponseKind::Matched,
                ttl_secs: Some(60),
                error: None,
            }]),
            recursive: std::sync::Mutex::new(vec![QueryOutcome {
                server: "recursor-1".to_string(),
                matched: true,
                response_kind: ResponseKind::Matched,
                ttl_secs: Some(60),
                error: None,
            }]),
            policy: PropagationPolicyV2::from_parts(
                Quorum::All,
                vec!["recursor-1".to_string()],
                Quorum::AtLeast(1),
            ),
        }
    }

    /// An observer using scripted outcomes and an explicit policy.
    pub fn with_policy(policy: PropagationPolicyV2) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Sets the scripted authoritative outcomes.
    pub fn set_authoritative(&self, outcomes: Vec<QueryOutcome>) {
        *self.authoritative.lock().unwrap() = outcomes;
    }

    /// Sets the scripted recursive outcomes.
    pub fn set_recursive(&self, outcomes: Vec<QueryOutcome>) {
        *self.recursive.lock().unwrap() = outcomes;
    }
}

#[async_trait]
impl DnsPropagationObserver for FakePropagationObserver {
    async fn observe(&self, expected: &ExpectedTxt) -> Result<PropagationReport> {
        let authoritative = self.authoritative.lock().unwrap().clone();
        let recursive = self.recursive.lock().unwrap().clone();
        let auth_ok = quorum_satisfied(
            authoritative.iter().filter(|o| o.matched).count(),
            authoritative.len(),
            self.policy.authoritative_quorum,
        );
        let rec_ok = if self.policy.recursive_resolvers.is_empty() {
            true
        } else {
            quorum_satisfied(
                recursive.iter().filter(|o| o.matched).count(),
                recursive.len(),
                self.policy.recursive_quorum,
            )
        };
        Ok(PropagationReport {
            record_name: expected.record_name.clone(),
            value_hash: expected.value_hash.clone(),
            authoritative,
            recursive,
            authoritative_quorum_reached: auth_ok,
            recursive_quorum_reached: rec_ok,
            quorum_reached: auth_ok && rec_ok,
        })
    }

    fn poll_interval(&self, _provider_id: Option<&str>) -> Duration {
        self.policy.poll_interval
    }
}

/// Propagation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropagationPolicyV2 {
    /// Quorum over authoritative nameservers.
    pub authoritative_quorum: Quorum,
    /// Configured recursive resolvers (address[:port]).
    pub recursive_resolvers: Vec<String>,
    /// How many recursive resolvers must observe the value.
    pub recursive_quorum: Quorum,
    /// Overall wait budget before propagation is reported as slow.
    pub max_wait: Duration,
    /// Re-observation interval while waiting for propagation.
    pub poll_interval: Duration,
    /// Single DNS query timeout.
    pub query_timeout: Duration,
}

impl Default for PropagationPolicyV2 {
    fn default() -> Self {
        Self {
            authoritative_quorum: Quorum::All,
            recursive_resolvers: Vec::new(),
            recursive_quorum: Quorum::AtLeast(1),
            max_wait: Duration::from_secs(300),
            poll_interval: Duration::from_secs(5),
            query_timeout: Duration::from_secs(3),
        }
    }
}

impl PropagationPolicyV2 {
    /// Builds a policy from explicit quorum and resolver values.
    ///
    /// The configuration layer maps its `[dns.propagation]`
    /// settings onto these primitives; taking plain policy values (instead
    /// of a config type) keeps this module config-agnostic.
    pub fn from_parts(
        authoritative_quorum: Quorum,
        recursive_resolvers: Vec<String>,
        recursive_quorum: Quorum,
    ) -> Self {
        Self {
            authoritative_quorum,
            recursive_resolvers,
            recursive_quorum,
            ..Self::default()
        }
    }

    /// Builds a policy from all knobs exposed by `[dns.propagation]`.
    pub fn from_config(
        authoritative_quorum: Quorum,
        recursive_resolvers: Vec<String>,
        recursive_quorum: Quorum,
        max_wait: Duration,
        poll_interval: Duration,
        query_timeout: Duration,
    ) -> Self {
        Self {
            authoritative_quorum,
            recursive_resolvers,
            recursive_quorum,
            max_wait,
            poll_interval,
            query_timeout,
        }
    }
}

struct ResolverEndpoint {
    label: String,
    resolver: hickory_resolver::TokioResolver,
}

/// Live observer over a zone resolver + system/recursive resolvers.
pub struct HickoryPropagationObserver {
    zone_resolver: Arc<dyn ZoneResolver>,
    policy: PropagationPolicyV2,
    recursive: Vec<ResolverEndpoint>,
    provider_policies: std::collections::HashMap<String, PropagationPolicyV2>,
    provider_recursive: std::collections::HashMap<String, Vec<ResolverEndpoint>>,
}

impl HickoryPropagationObserver {
    /// Creates an observer with the given policy.
    pub fn new(zone_resolver: Arc<dyn ZoneResolver>, policy: PropagationPolicyV2) -> Result<Self> {
        Self::with_provider_policies(zone_resolver, policy, std::collections::HashMap::new())
    }

    /// Creates an observer with a global policy and provider-level overrides.
    pub fn with_provider_policies(
        zone_resolver: Arc<dyn ZoneResolver>,
        policy: PropagationPolicyV2,
        provider_policies: std::collections::HashMap<String, PropagationPolicyV2>,
    ) -> Result<Self> {
        let recursive = Self::resolver_endpoints(&policy)?;
        let provider_recursive = provider_policies
            .iter()
            .map(|(provider_id, policy)| {
                Self::resolver_endpoints(policy).map(|endpoints| (provider_id.clone(), endpoints))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        Ok(Self {
            zone_resolver,
            policy,
            recursive,
            provider_policies,
            provider_recursive,
        })
    }

    fn resolver_endpoints(policy: &PropagationPolicyV2) -> Result<Vec<ResolverEndpoint>> {
        policy
            .recursive_resolvers
            .iter()
            .map(|configured| {
                let addr = parse_resolver_addr(configured)?;
                resolver_endpoint(configured.clone(), addr)
            })
            .collect()
    }

    fn policy_for(&self, provider_id: Option<&str>) -> &PropagationPolicyV2 {
        provider_id
            .and_then(|id| self.provider_policies.get(id))
            .unwrap_or(&self.policy)
    }

    fn recursive_for(&self, provider_id: Option<&str>) -> &[ResolverEndpoint] {
        provider_id
            .and_then(|id| self.provider_recursive.get(id))
            .map(Vec::as_slice)
            .unwrap_or(&self.recursive)
    }

    async fn query_txt_with(
        resolver: hickory_resolver::TokioResolver,
        server_label: String,
        name: String,
        expected_hash: String,
        query_timeout: Duration,
    ) -> QueryOutcome {
        let lookup =
            tokio::time::timeout(query_timeout, resolver.lookup(name, RecordType::TXT)).await;
        match lookup {
            Ok(Ok(lookup)) => {
                let matched = lookup.answers().iter().any(|record| {
                    Some(record.data.clone())
                        .and_then(|data| match data {
                            RData::TXT(txt) => {
                                let joined: String = txt
                                    .txt_data
                                    .iter()
                                    .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                                    .collect();
                                Some(txt_value_hash(&joined) == expected_hash)
                            }
                            _ => None,
                        })
                        .unwrap_or(false)
                });
                let ttl = lookup.answers().first().map(|r| r.ttl);
                QueryOutcome {
                    server: server_label,
                    matched,
                    response_kind: if matched {
                        ResponseKind::Matched
                    } else {
                        ResponseKind::NoData
                    },
                    ttl_secs: ttl,
                    error: None,
                }
            }
            Ok(Err(err)) => {
                let response_kind = if err.is_no_records_found() {
                    ResponseKind::NoData
                } else if err.to_string().to_lowercase().contains("timeout") {
                    ResponseKind::Timeout
                } else {
                    ResponseKind::ServFail
                };
                QueryOutcome {
                    server: server_label,
                    matched: false,
                    response_kind,
                    ttl_secs: None,
                    error: Some(err.to_string()),
                }
            }
            Err(_) => QueryOutcome {
                server: server_label,
                matched: false,
                response_kind: ResponseKind::Timeout,
                ttl_secs: None,
                error: Some(format!(
                    "query timed out after {}s",
                    query_timeout.as_secs()
                )),
            },
        }
    }
}

fn parse_resolver_addr(configured: &str) -> Result<SocketAddr> {
    if let Ok(addr) = configured.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = configured.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(AcmeError::configuration(format!(
        "dns.propagation.recursive_resolvers entry `{configured}` is not a valid ip[:port] address"
    )))
}

fn resolver_endpoint(label: String, addr: SocketAddr) -> Result<ResolverEndpoint> {
    let mut udp = ConnectionConfig::udp();
    udp.port = addr.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = addr.port();
    let config = ResolverConfig::from_parts(
        None,
        Vec::new(),
        vec![NameServerConfig::new(addr.ip(), true, vec![udp, tcp])],
    );
    let resolver = hickory_resolver::TokioResolver::builder_with_config(
        config,
        TokioRuntimeProvider::default(),
    )
    .build()
    .map_err(|e| AcmeError::protocol(format!("failed to build resolver for `{label}`: {e}")))?;
    Ok(ResolverEndpoint { label, resolver })
}

#[async_trait]
impl DnsPropagationObserver for HickoryPropagationObserver {
    async fn observe(&self, expected: &ExpectedTxt) -> Result<PropagationReport> {
        let resolution = self.zone_resolver.resolve(&expected.record_name).await?;
        let expected_hash = expected.value_hash.clone();
        let provider_id = expected.provider_id.as_deref();
        let policy = self.policy_for(provider_id);

        let mut authoritative_tasks = Vec::new();
        for ns in &resolution.authoritative_ns {
            let addrs = resolution
                .authoritative_addrs
                .get(ns)
                .cloned()
                .unwrap_or_default();
            if addrs.is_empty() {
                let ns = ns.clone();
                authoritative_tasks.push(tokio::spawn(async move {
                    QueryOutcome {
                        server: ns,
                        matched: false,
                        response_kind: ResponseKind::ServFail,
                        ttl_secs: None,
                        error: Some("authoritative nameserver address unavailable".to_string()),
                    }
                }));
                continue;
            }
            for addr in addrs {
                let endpoint =
                    resolver_endpoint(format!("{ns}@{addr}:53"), SocketAddr::new(addr, 53))?;
                authoritative_tasks.push(tokio::spawn(Self::query_txt_with(
                    endpoint.resolver,
                    endpoint.label,
                    resolution.final_name.clone(),
                    expected_hash.clone(),
                    policy.query_timeout,
                )));
            }
        }

        let mut recursive_tasks = Vec::new();
        for endpoint in self.recursive_for(provider_id) {
            recursive_tasks.push(tokio::spawn(Self::query_txt_with(
                endpoint.resolver.clone(),
                endpoint.label.clone(),
                resolution.final_name.clone(),
                expected_hash.clone(),
                policy.query_timeout,
            )));
        }

        let mut authoritative = Vec::with_capacity(authoritative_tasks.len());
        for task in authoritative_tasks {
            authoritative.push(task.await.map_err(|err| {
                AcmeError::protocol(format!("authoritative TXT query task failed: {err}"))
            })?);
        }

        let mut recursive = Vec::with_capacity(recursive_tasks.len());
        for task in recursive_tasks {
            recursive.push(task.await.map_err(|err| {
                AcmeError::protocol(format!("recursive TXT query task failed: {err}"))
            })?);
        }

        let auth_matched = authoritative.iter().filter(|o| o.matched).count();
        let rec_matched = recursive.iter().filter(|o| o.matched).count();
        let auth_ok = quorum_satisfied(
            auth_matched,
            authoritative.len(),
            policy.authoritative_quorum,
        );
        let rec_ok = if policy.recursive_resolvers.is_empty() {
            true
        } else {
            quorum_satisfied(rec_matched, recursive.len(), policy.recursive_quorum)
        };

        Ok(PropagationReport {
            record_name: expected.record_name.clone(),
            value_hash: expected_hash,
            authoritative,
            recursive,
            authoritative_quorum_reached: auth_ok,
            recursive_quorum_reached: rec_ok,
            quorum_reached: auth_ok && rec_ok,
        })
    }

    fn poll_interval(&self, provider_id: Option<&str>) -> Duration {
        self.policy_for(provider_id).poll_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_math() {
        assert!(quorum_satisfied(2, 2, Quorum::All));
        assert!(!quorum_satisfied(1, 2, Quorum::All));
        assert!(quorum_satisfied(1, 3, Quorum::AtLeast(1)));
        assert!(!quorum_satisfied(0, 3, Quorum::AtLeast(1)));
        assert!(!quorum_satisfied(2, 2, Quorum::AtLeast(3)));
        assert!(!quorum_satisfied(2, 0, Quorum::All));
    }

    #[tokio::test]
    async fn fake_observer_quorum() {
        let observer = FakePropagationObserver::all_matched();
        let report = observer
            .observe(&ExpectedTxt {
                provider_id: None,
                record_name: "_acme-challenge.example.com".to_string(),
                value_hash: txt_value_hash("secret-value"),
            })
            .await
            .unwrap();
        assert!(report.quorum_reached);
        assert_eq!(report.matched_authoritative(), 1);
        // Only hashes appear in the report.
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("secret-value"));
    }

    #[tokio::test]
    async fn partial_authoritative_fails_quorum() {
        let observer = FakePropagationObserver::all_matched();
        observer.set_authoritative(vec![
            QueryOutcome {
                server: "ns1".to_string(),
                matched: true,
                response_kind: ResponseKind::Matched,
                ttl_secs: None,
                error: None,
            },
            QueryOutcome {
                server: "ns2".to_string(),
                matched: false,
                response_kind: ResponseKind::NoData,
                ttl_secs: None,
                error: None,
            },
        ]);
        let report = observer
            .observe(&ExpectedTxt {
                provider_id: None,
                record_name: "_acme-challenge.example.com".to_string(),
                value_hash: txt_value_hash("v"),
            })
            .await
            .unwrap();
        assert!(
            !report.quorum_reached,
            "all-authoritative policy fails on partial spread"
        );
    }

    #[tokio::test]
    async fn empty_recursive_resolvers_explicitly_skip_recursive_quorum() {
        let observer = FakePropagationObserver::with_policy(PropagationPolicyV2::default());
        observer.set_authoritative(vec![QueryOutcome {
            server: "ns1".to_string(),
            matched: true,
            response_kind: ResponseKind::Matched,
            ttl_secs: Some(60),
            error: None,
        }]);
        let report = observer
            .observe(&ExpectedTxt {
                provider_id: None,
                record_name: "_acme-challenge.example.com".to_string(),
                value_hash: txt_value_hash("v"),
            })
            .await
            .unwrap();

        assert!(report.authoritative_quorum_reached);
        assert!(report.recursive_quorum_reached);
        assert!(report.quorum_reached);
        assert!(report.recursive.is_empty());
    }
}
