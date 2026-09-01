use crate::error::Result;
use crate::order::Challenge;
use crate::types::{ChallengeType, Identifier};
/// Challenge solver trait and registry
use async_trait::async_trait;

// Re-export challenge types
pub mod cleanup;
pub mod dns01;
pub mod dns_cache;
pub mod edge;
pub mod http01;
pub mod http01_presenter;
pub mod presenter;
pub mod session;
pub mod steps;
pub mod tls_alpn01;

pub use cleanup::{ChallengeCleanupScanner, ScanOutcome};
pub use dns_cache::{CachingDnsResolver, DnsCache};
pub use dns01::{Dns01Solver, DnsProvider, MockDnsProvider};
pub use edge::{
    FakeHttpEdge, FakeTlsEdge, HttpChallengeEdge, HttpChallengeRoute, HttpRouteLease,
    HttpRouteState, TlsChallengeEdge, TlsChallengeRoute, TlsRouteLease, TlsRouteState,
};
pub use http01::Http01Solver;
pub use http01_presenter::{Http01Presenter, TokenRegistry, http01_host_header, http01_url};
pub use presenter::{
    ChallengePresenter, CleanupOutcome, LegacySolverPresenter, MemoryPresenter,
    MemoryPresenterBehavior, Observation, PrepareChallenge, PresenterRegistry,
};
pub use session::{ChallengeSession, ChallengeSessionState};
pub use steps::{
    AcknowledgeChallengesStep, ChallengeStepDeps, CleanupChallengesStep, CreateOrderStep,
    EnsureAccountStep, LoadAuthorizationsStep, PrepareChallengesStep, WaitAuthorizationsStep,
    WaitPropagationStep, cleanup_operation_leases,
};
pub use tls_alpn01::{
    ACME_TLS_ALPN_PROTOCOL, TlsAlpn01Presenter, TlsAlpn01Solver, ValidationCertificate,
    build_tls_alpn_validation_cert, ip_validation_sni, tls_alpn_validation_sni,
};

/// Trait for implementing different challenge types
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// Get the challenge type this solver handles
    fn challenge_type(&self) -> ChallengeType;

    /// Prepare the challenge (e.g., set up DNS records or HTTP server)
    async fn prepare(
        &mut self,
        challenge: &Challenge,
        identifier: &Identifier,
        key_authorization: &str,
    ) -> Result<()>;

    /// Present the challenge to the ACME server (usually just marking as ready)
    async fn present(&self) -> Result<()>;

    /// Verify that the challenge has been completed
    async fn verify(&self) -> Result<bool>;

    /// Clean up after the challenge (e.g., remove DNS records or stop HTTP server)
    async fn cleanup(&mut self) -> Result<()>;
}

/// Registry for managing multiple challenge solvers
pub struct ChallengeSolverRegistry {
    solvers: std::collections::HashMap<ChallengeType, Box<dyn ChallengeSolver>>,
}

impl ChallengeSolverRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            solvers: std::collections::HashMap::new(),
        }
    }

    /// Register a new challenge solver
    pub fn register<S: ChallengeSolver + 'static>(&mut self, solver: S) {
        self.solvers
            .insert(solver.challenge_type(), Box::new(solver));
    }

    /// Get a solver for the given challenge type
    pub fn get(&self, challenge_type: ChallengeType) -> Option<&dyn ChallengeSolver> {
        self.solvers.get(&challenge_type).map(|s| s.as_ref())
    }

    /// Get a mutable solver for the given challenge type
    pub fn get_mut(
        &mut self,
        challenge_type: ChallengeType,
    ) -> Option<&mut (dyn ChallengeSolver + '_)> {
        if let Some(solver) = self.solvers.get_mut(&challenge_type) {
            Some(solver.as_mut())
        } else {
            None
        }
    }

    /// Get all registered challenge types
    pub fn supported_types(&self) -> Vec<ChallengeType> {
        self.solvers.keys().copied().collect()
    }
}

impl Default for ChallengeSolverRegistry {
    fn default() -> Self {
        Self::new()
    }
}
