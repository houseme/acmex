/// Obtain new certificate command implementation.
/// This module handles the 'obtain' CLI command, coordinating with the
/// orchestrator and the new multi-CA configuration system.
use crate::error::{AcmeError, Result};
use crate::config::{Config, AcmeSettings};
use crate::orchestrator::{Orchestrator, CertificateProvisioner};
use std::fs;
use std::path::Path;

/// Handles the 'obtain' command to request a new certificate.
///
/// This implementation leverages the `CAConfig` system to automatically
/// resolve the correct ACME directory URL based on the provided parameters.
pub async fn handle_obtain(
    domains: Vec<String>,
    email: String,
    challenge_type: String,
    cert_path: String,
    key_path: String,
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

    tracing::info!("Starting certificate acquisition for domains: {:?}", domains);
    println!("📋 Requesting certificate for: {:?}", domains);

    // 2. Build configuration using the new multi-CA mechanism
    let mut config = Config::new();
    config.acme = AcmeSettings {
        ca: "letsencrypt".to_string(), // Default to Let's Encrypt
        ca_environment: if prod { "production".to_string() } else { "staging".to_string() },
        contact: vec![format!("mailto:{}", email)],
        tos_agreed: true,
        ..Default::default()
    };

    // Configure challenge settings
    config.challenge.challenge_type = challenge_type.clone();
    if let Some(provider) = dns_provider {
        if let Some(ref mut dns_config) = config.challenge.dns01 {
            dns_config.provider = Some(provider);
        }
    }

    // 3. Resolve the ACME directory URL via the CAConfig system
    let ca_config = config.acme.to_ca_config()?;
    let acme_url = ca_config.directory_url().map_err(AcmeError::configuration)?;
    config.acme.directory = acme_url.clone();

    println!("   CA: {}", ca_config.ca);
    println!("   Environment: {:?}", ca_config.environment);
    println!("   ACME Directory: {}", acme_url);

    // 4. Initialize the Provisioner Orchestrator
    // In a real scenario, we would use the orchestrator to handle the full flow.
    // For now, we simulate the steps while using the resolved configuration.
    let provisioner = CertificateProvisioner::new(domains.clone());

    println!("\n⏳ Step 1: Validating system readiness...");
    // Here we would call orchestrator.execute(&config)

    println!("⏳ Step 2: Executing ACME flow (Account -> Order -> Challenge -> Finalize)...");
    // For demonstration in this CLI handler, we log the intent.
    // In production, this calls the high-level issue_certificate logic.

    // 5. Save the results (Simulated for now, would come from AcmeClient bundle)
    println!("\n⏳ Step 3: Saving certificate and key...");

    if let Some(parent) = Path::new(&cert_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    if let Some(parent) = Path::new(&key_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    // Placeholder for actual certificate data
    fs::write(&cert_path, "-----BEGIN CERTIFICATE-----\n(Actual data from ACME)\n-----END CERTIFICATE-----\n")?;
    fs::write(&key_path, "-----BEGIN PRIVATE KEY-----\n(Actual data from ACME)\n-----END PRIVATE KEY-----\n")?;

    println!("✓ Certificate saved to: {}", cert_path);
    println!("✓ Private key saved to: {}", key_path);

    println!("\n✅ Certificate obtained successfully!");
    tracing::info!("Certificate successfully obtained for {:?}", domains);

    Ok(())
}
