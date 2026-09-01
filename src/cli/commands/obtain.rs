/// Obtain new certificate command implementation.
/// This module handles the 'obtain' CLI command, coordinating with the
/// orchestrator and the new multi-CA configuration system.
use crate::application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, CreateCertificateIntent,
    IssueCertificate,
};
use crate::config::{AcmeSettings, Config};
use crate::error::{AcmeError, Result};

/// Handles the 'obtain' command to request a new certificate.
///
/// This implementation leverages the `CAConfig` system to automatically
/// resolve the correct ACME directory URL based on the provided parameters.
pub async fn handle_obtain(
    domains: Vec<String>,
    email: String,
    challenge_type: String,
    _cert_path: String,
    _key_path: String,
    prod: bool,
    dns_provider: Option<String>,
) -> Result<()> {
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
    let (service, _repositories) = ApplicationServiceBuilder::from_config(&config)
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
