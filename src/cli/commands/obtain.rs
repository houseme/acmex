/// Obtain new certificate command implementation.
/// This module handles the 'obtain' CLI command, coordinating with the
/// orchestrator and the new multi-CA configuration system.
use std::time::Duration;

use crate::application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, CreateCertificateIntent,
    IssueCertificate,
};
use crate::config::{AcmeSettings, Config};
use crate::error::{AcmeError, Result};

/// Arguments for [`handle_obtain`] (mirrors `cli::args::ObtainArgs`).
#[derive(Debug, Clone)]
pub struct ObtainCommand {
    /// Domains (SANs) to request.
    pub domains: Vec<String>,
    /// Contact email for the ACME account.
    pub email: String,
    /// Challenge type: http-01, dns-01 or tls-alpn-01.
    pub challenge_type: String,
    /// Legacy output path (unused: material goes to sinks).
    pub _cert_path: String,
    /// Legacy output path (unused: material goes to sinks).
    pub _key_path: String,
    /// Target the production environment instead of staging.
    pub prod: bool,
    /// Optional DNS provider id for dns-01.
    pub dns_provider: Option<String>,
    /// Drive the engine in-process and wait for the terminal state.
    pub wait: bool,
}

/// How long `--wait` polls the embedded engine before giving up.
const WAIT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Handles the 'obtain' command to request a new certificate.
///
/// This implementation leverages the `CAConfig` system to automatically
/// resolve the correct ACME directory URL based on the provided parameters.
///
/// Two modes:
///
/// * **fire-and-forget (default)** — creates the intent and the issue
///   operation in the durable repository, prints their ids and exits. A
///   running worker (`acmex serve`, `acmex daemon`) executes the flow.
/// * **`--wait`** — additionally assembles the production workflow engine
///   in-process (`server::worker::build_engine_from_config`) and drives the
///   operation to a terminal state, so a one-shot invocation actually
///   requests the certificate end to end.
pub async fn handle_obtain(args: ObtainCommand) -> Result<()> {
    let ObtainCommand {
        domains,
        email,
        challenge_type,
        _cert_path: _,
        _key_path: _,
        prod,
        dns_provider,
        wait,
    } = args;
    // 1. Validate basic inputs
    if domains.is_empty() {
        return Err(AcmeError::invalid_input("No domains specified"));
    }

    if email.is_empty() {
        return Err(AcmeError::invalid_input("No email specified"));
    }

    tracing::info!(
        "Starting certificate acquisition for domains: {:?}",
        domains
    );
    println!("📋 Requesting certificate for: {:?}", domains);

    // 2. Build configuration using the new multi-CA mechanism
    let mut config = Config::new();
    config.acme = AcmeSettings {
        ca: "letsencrypt".to_string(), // Default to Let's Encrypt
        ca_environment: if prod {
            "production".to_string()
        } else {
            "staging".to_string()
        },
        contact: vec![format!("mailto:{}", email)],
        tos_agreed: true,
        ..Default::default()
    };

    // Configure challenge settings
    config.challenge.challenge_type = challenge_type.clone();
    if let Some(provider) = dns_provider
        && let Some(ref mut dns_config) = config.challenge.dns01
    {
        dns_config.provider = Some(provider);
    }

    // 3. Resolve the ACME directory URL via the CAConfig system
    let ca_config = config.acme.to_ca_config()?;
    let acme_url = ca_config
        .directory_url()
        .map_err(AcmeError::configuration)?;
    config.acme.directory = acme_url.clone();

    println!("   CA: {}", ca_config.ca);
    println!("   Environment: {:?}", ca_config.environment);
    println!("   ACME Directory: {}", acme_url);

    println!("\n⏳ Creating certificate intent and issue operation...");
    let (service, repositories) = ApplicationServiceBuilder::from_config(&config)
        .await?
        .build()?;
    let idempotency_seed = domains.join(",");
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: domains.clone(),
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: Default::default(),
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            idempotency_key: format!("cli-obtain-intent-{idempotency_seed}"),
        })
        .await?;
    let operation = service
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id.clone(),
            idempotency_key: format!("cli-obtain-issue-{}", intent.id),
        })
        .await?;

    println!("✓ Intent: {}", intent.id);
    println!("✓ Issue operation: {}", operation.id);

    if wait {
        println!("\n⏳ Driving the workflow engine in-process (this talks to the real CA)...");
        let settings = crate::server::worker::WorkflowWorkerSettings {
            // HTTP-01 needs a reachable listener; DNS-01 needs provider
            // credentials from the environment. Anything missing fails with
            // an explicit classified error rather than pretending.
            http01_listen: config
                .challenge
                .http01
                .as_ref()
                .map(|http| http.listen_addr.clone()),
            ..Default::default()
        };
        let metrics = std::sync::Arc::new(crate::metrics::MetricsRegistry::new());
        let engine = crate::server::worker::build_engine_from_config(
            &config,
            repositories,
            metrics,
            settings,
        )
        .await?;
        let record = engine
            .run_until_terminal(&operation.id, WAIT_TIMEOUT)
            .await?;
        match record.status {
            crate::domain::OperationStatus::Succeeded => {
                println!("✅ Operation {} succeeded", operation.id);
            }
            status => {
                return Err(AcmeError::protocol(format!(
                    "operation {} ended in {}: {}",
                    operation.id,
                    status.as_str(),
                    record
                        .error
                        .as_ref()
                        .and_then(|e| e.detail.clone())
                        .unwrap_or_else(|| "no detail".to_string())
                )));
            }
        }
    } else {
        println!(
            "Operation submitted. Start a worker (`acmex serve` or `acmex daemon`) or re-run with --wait to execute it now."
        );
    }
    println!(
        "Certificate material is delivered by configured sinks or controlled export endpoints."
    );
    tracing::info!(
        intent = %intent.id,
        operation = %operation.id,
        "certificate issue operation submitted"
    );

    Ok(())
}
