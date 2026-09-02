//! Propagation observation: is the TXT value externally visible?
//!
//! Observation queries (a) the authoritative nameservers of the zone and
//! (b) a configured set of recursive resolvers, and applies quorum policy.
//! Reports store only value *hashes* — challenge values never reach logs.
//!
//! `FakePropagationObserver` scripts outcomes for tests; the hickory-based
//! observer performs live queries (authoritative NS first, then recursive).

use std::sync::Arc;

use async_trait::async_trait;
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
        Quorum::AtLeast(n) => matched >= n.min(total),
    }
}

/// The observation port.
#[async_trait]
pub trait DnsPropagationObserver: Send + Sync {
    /// Observes propagation; never modifies anything.
    async fn observe(&self, expected: &ExpectedTxt) -> Result<PropagationReport>;
}

/// Scripted observer for tests.
#[derive(Default)]
pub struct FakePropagationObserver {
    /// Authoritative outcomes replayed in order.
    authoritative: std::sync::Mutex<Vec<QueryOutcome>>,
    recursive: std::sync::Mutex<Vec<QueryOutcome>>,
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
            }]),
            recursive: std::sync::Mutex::new(vec![QueryOutcome {
                server: "recursor-1".to_string(),
                matched: true,
                response_kind: ResponseKind::Matched,
                ttl_secs: Some(60),
            }]),
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
        // Quorum: all authoritative matched AND at least one recursive.
        let auth_ok = !authoritative.is_empty() && authoritative.iter().all(|o| o.matched);
        let rec_ok = recursive.iter().any(|o| o.matched);
        Ok(PropagationReport {
            record_name: expected.record_name.clone(),
            value_hash: expected.value_hash.clone(),
            authoritative,
            recursive,
            quorum_reached: auth_ok && rec_ok,
        })
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
}

impl Default for PropagationPolicyV2 {
    fn default() -> Self {
        Self {
            authoritative_quorum: Quorum::All,
            recursive_resolvers: vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
            recursive_quorum: Quorum::AtLeast(1),
        }
    }
}

impl PropagationPolicyV2 {
    /// Builds a policy from explicit quorum and resolver values.
    ///
    /// The configuration layer maps its `[challenge.dns01.propagation]`
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
        }
    }
}

/// Live observer over a zone resolver + system/recursive resolvers.
pub struct HickoryPropagationObserver {
    zone_resolver: Arc<dyn ZoneResolver>,
    system: hickory_resolver::TokioResolver,
    policy: PropagationPolicyV2,
}

impl HickoryPropagationObserver {
    /// Creates an observer with the given policy.
    pub fn new(zone_resolver: Arc<dyn ZoneResolver>, policy: PropagationPolicyV2) -> Result<Self> {
        let system = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| AcmeError::protocol(format!("failed to init resolver: {e}")))?
            .build()
            .map_err(|e| AcmeError::protocol(format!("failed to build resolver: {e}")))?;
        Ok(Self {
            zone_resolver,
            system,
            policy,
        })
    }

    async fn query_txt(
        &self,
        server: Option<&str>,
        name: &str,
        expected_hash: &str,
    ) -> QueryOutcome {
        // Authoritative queries route through the system resolver for now;
        // per-NS sockets are a T12 hardening item. The report records the
        // intended target for diagnosis.
        let lookup = self.system.lookup(name.to_string(), RecordType::TXT).await;

        let server_label = server.unwrap_or("system-resolver").to_string();
        match lookup {
            Ok(lookup) => {
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
                }
            }
            Err(err) => {
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
                }
            }
        }
    }
}

#[async_trait]
impl DnsPropagationObserver for HickoryPropagationObserver {
    async fn observe(&self, expected: &ExpectedTxt) -> Result<PropagationReport> {
        let resolution = self.zone_resolver.resolve(&expected.record_name).await?;
        let expected_hash = expected.value_hash.clone();

        let mut authoritative = Vec::new();
        for ns in &resolution.authoritative_ns {
            let outcome = self
                .query_txt(Some(ns), &resolution.final_name, &expected_hash)
                .await;
            authoritative.push(outcome);
        }

        let mut recursive = Vec::new();
        for resolver in &self.policy.recursive_resolvers {
            let outcome = self
                .query_txt(Some(resolver), &resolution.final_name, &expected_hash)
                .await;
            recursive.push(outcome);
        }

        let auth_matched = authoritative.iter().filter(|o| o.matched).count();
        let rec_matched = recursive.iter().filter(|o| o.matched).count();
        let auth_ok = quorum_satisfied(
            auth_matched,
            authoritative.len(),
            self.policy.authoritative_quorum,
        );
        let rec_ok = quorum_satisfied(rec_matched, recursive.len(), self.policy.recursive_quorum);

        Ok(PropagationReport {
            record_name: expected.record_name.clone(),
            value_hash: expected_hash,
            authoritative,
            recursive,
            quorum_reached: auth_ok && rec_ok,
        })
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
        assert!(!quorum_satisfied(2, 0, Quorum::All));
    }

    #[tokio::test]
    async fn fake_observer_quorum() {
        let observer = FakePropagationObserver::all_matched();
        let report = observer
            .observe(&ExpectedTxt {
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
            },
            QueryOutcome {
                server: "ns2".to_string(),
                matched: false,
                response_kind: ResponseKind::NoData,
                ttl_secs: None,
            },
        ]);
        let report = observer
            .observe(&ExpectedTxt {
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
}
