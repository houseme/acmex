//! DNS-01 presenter over the factory/zone/observer/router stack.
//!
//! `prepare` resolves the zone (SOA walk-up + delegation), routes to the
//! owning provider, presents the TXT and returns a lease whose locator
//! names the exact record; `observe` consults the propagation observer;
//! `cleanup` removes exactly this lease's value.

use std::sync::Arc;

use async_trait::async_trait;

use jiff::Timestamp;

use crate::challenge::presenter::{
    CleanupOutcome, Observation, PrepareChallenge, dns01_validation_value,
};
use crate::challenge::{ChallengePresenter, ChallengeSession};
use crate::domain::challenge::{ChallengeLease, ChallengeLeaseLocator, ChallengeLeaseState};
use crate::error::Result;
use crate::types::ChallengeType;

use super::propagation::{DnsPropagationObserver, ExpectedTxt};
use super::record::{DnsRecordLocator, PresentTxt, RecordCleanupOutcome};
use super::router::ProviderRouter;
use super::zone::{ZoneResolver, challenge_record_name};

/// The DNS-01 presenter.
pub struct Dns01Presenter {
    router: Arc<ProviderRouter>,
    zone_resolver: Arc<dyn ZoneResolver>,
    observer: Arc<dyn DnsPropagationObserver>,
    selector: Option<String>,
    lease_ttl_secs: i64,
}

impl Dns01Presenter {
    /// Creates the presenter.
    pub fn new(
        router: Arc<ProviderRouter>,
        zone_resolver: Arc<dyn ZoneResolver>,
        observer: Arc<dyn DnsPropagationObserver>,
    ) -> Self {
        Self {
            router,
            zone_resolver,
            observer,
            selector: None,
            lease_ttl_secs: 30 * 60,
        }
    }

    /// Pins an explicit provider selector (from the intent policy).
    pub fn with_selector(mut self, selector: Option<String>) -> Self {
        self.selector = selector;
        self
    }

    fn lease_from_locator(
        &self,
        session: &ChallengeSession,
        locator: DnsRecordLocator,
    ) -> ChallengeLease {
        let now = Timestamp::now();
        ChallengeLease {
            id: crate::domain::ChallengeLeaseId::generate(),
            operation_id: session.operation_id.clone(),
            identifier: session.identifier.clone(),
            challenge_type: ChallengeType::Dns01,
            locator: ChallengeLeaseLocator::Dns {
                provider_id: locator.provider_id,
                zone: locator.zone,
                record_name: locator.record_name,
                record_id: locator.record_id,
                value_hash: locator.value_hash,
            },
            created_at: now,
            expires_at: now
                .checked_add(jiff::Span::new().seconds(self.lease_ttl_secs))
                .unwrap_or(now),
            state: ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        }
    }
}

#[async_trait]
impl ChallengePresenter for Dns01Presenter {
    fn kind(&self) -> ChallengeType {
        ChallengeType::Dns01
    }

    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease> {
        let identifier = request
            .session
            .identifier
            .as_dns()
            .ok_or_else(|| {
                crate::error::AcmeError::InvalidInput(
                    "DNS-01 requires a DNS identifier (IP identifiers are rejected by the planner)"
                        .to_string(),
                )
            })?
            .clone();

        let record_name = challenge_record_name(&identifier);
        let resolution = self.zone_resolver.resolve(&record_name).await?;
        let provider = self
            .router
            .route(&resolution.zone_apex, self.selector.as_deref())?;

        let locator = provider
            .present_txt(PresentTxt {
                zone: resolution.zone_apex.clone(),
                record_name: record_name.clone(),
                value: dns01_validation_value(&request.key_authorization),
                idempotency_key: request.session.id.clone(),
            })
            .await?;

        Ok(self.lease_from_locator(&request.session, locator))
    }

    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation> {
        let ChallengeLeaseLocator::Dns {
            record_name,
            value_hash,
            ..
        } = &lease.locator
        else {
            return Ok(Observation::Propagated);
        };
        // The lease carries only the value hash; observation compares
        // hashes, so challenge values never move through observation.
        let report = self
            .observer
            .observe(&ExpectedTxt {
                record_name: record_name.clone(),
                value_hash: value_hash.clone(),
            })
            .await?;
        if report.quorum_reached {
            Ok(Observation::Propagated)
        } else {
            Ok(Observation::NotYet {
                retry_after: std::time::Duration::from_secs(5),
            })
        }
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome> {
        let ChallengeLeaseLocator::Dns {
            provider_id,
            zone,
            record_name,
            record_id,
            value_hash,
        } = &lease.locator
        else {
            return Ok(CleanupOutcome::AlreadyAbsent);
        };
        let provider = self.router.route(zone, Some(provider_id))?;
        let outcome = provider
            .cleanup_txt(&DnsRecordLocator {
                provider_id: provider_id.clone(),
                zone: zone.clone(),
                record_name: record_name.clone(),
                record_id: record_id.clone(),
                value_hash: value_hash.clone(),
            })
            .await?;
        Ok(match outcome {
            RecordCleanupOutcome::Removed => CleanupOutcome::Cleaned,
            RecordCleanupOutcome::AlreadyAbsent => CleanupOutcome::AlreadyAbsent,
        })
    }
}
