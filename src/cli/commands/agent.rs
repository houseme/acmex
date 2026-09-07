//! `acmex agent` command family: the reference remote delivery agent
//! (server side of `HttpAgentSink`), for live evidence runs and
//! production-style single-process deployments.

use std::net::SocketAddr;

use crate::delivery::agent_server::{self, AgentServerConfig, DEFAULT_AGENT_LISTEN_ADDR};
use crate::error::{AcmeError, Result};

/// Handles `acmex agent serve`: binds the reference agent and blocks until
/// SIGINT/SIGTERM, then shuts down gracefully. The token is resolved from a
/// SecretRef (`env:`/`file:` only) and never logged or echoed.
pub async fn handle_agent_serve(listen: String, token_ref: String) -> Result<()> {
    let addr: SocketAddr = listen.parse().map_err(|error| {
        AcmeError::configuration(format!(
            "invalid --listen address {listen:?} (example: {DEFAULT_AGENT_LISTEN_ADDR}): {error}"
        ))
    })?;
    let reference = agent_server::parse_agent_token_ref(&token_ref).map_err(|error| {
        AcmeError::configuration(format!(
            "invalid --token-ref: {error} (example: env:ACMEX_AGENT_TOKEN)"
        ))
    })?;
    let config = AgentServerConfig::from_secret_ref(addr, &reference)
        .await
        .map_err(AcmeError::from)?;
    tracing::info!(
        "serving reference delivery agent on {} (token: {})",
        config.listen,
        reference.describe()
    );
    agent_server::serve_agent(config)
        .await
        .map_err(AcmeError::from)
}
