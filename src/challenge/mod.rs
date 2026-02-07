use crate::error::Result;
use crate::order::Challenge;
use crate::types::ChallengeType;
/// Challenge solver trait and registry
use async_trait::async_trait;

/// Trait for implementing different challenge types
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// Get the challenge type this solver handles
    fn challenge_type(&self) -> ChallengeType;

    /// Prepare the challenge (e.g., set up DNS records or HTTP server)
    async fn prepare(&mut self, challenge: &Challenge, key_authorization: &str) -> Result<()>;

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
