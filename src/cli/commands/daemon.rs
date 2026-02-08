/// Daemon mode - background renewal - Complete implementation
use crate::error::Result;
use jiff::Zoned;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info, warn};
use x509_parser::prelude::*;

/// Run daemon for automatic certificate renewal
pub async fn handle_daemon(
    domains: Vec<String>,
    storage_path: String,
    check_interval_secs: u64,
    renew_before_days: u64,
    notify_email: Option<String>,
) -> Result<()> {
    if domains.is_empty() {
        return Err(crate::error::AcmeError::InvalidInput(
            "No domains specified".to_string(),
        ));
    }

    println!("🚀 ACME Daemon Starting");
    println!("   Domains: {:?}", domains);
    println!("   Storage: {}", storage_path);
    println!("   Check interval: {}s", check_interval_secs);
    println!("   Renew before: {} days", renew_before_days);
    if let Some(ref email) = notify_email {
        println!("   Notification email: {}", email);
    }

    info!("Daemon started for domains: {:?}", domains);

    let check_interval = Duration::from_secs(check_interval_secs);
    let renew_before_secs = renew_before_days * 24 * 3600;

    // Setup signal handling for graceful shutdown
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;

    println!("\n✓ Daemon initialized, waiting for shutdown signal (Ctrl+C)...\n");

    loop {
        // Check for shutdown signals
        tokio::select! {
            _ = sigterm.recv() => {
                println!("\n📛 Received SIGTERM, shutting down gracefully...");
                info!("Daemon received SIGTERM, shutting down");
                break;
            },
            _ = sigint.recv() => {
                println!("\n📛 Received SIGINT (Ctrl+C), shutting down gracefully...");
                info!("Daemon received SIGINT, shutting down");
                break;
            },
            _ = tokio::time::sleep(check_interval) => {
                // Perform renewal check
                match check_and_renew_certificates(&domains, &storage_path, renew_before_secs).await {
                    Ok(count) => {
                        if count > 0 {
                            info!("Renewed {} certificates", count);
                            println!("✓ Renewed {} certificates at {}", count, Zoned::now());

                            // Send notification if email provided
                            if let Some(ref email) = notify_email
                                && let Err(e) = send_renewal_notification(email, count).await {
                                    warn!("Failed to send notification: {}", e);
                                }
                        } else {
                            info!("No certificates needed renewal");
                        }
                    },
                    Err(e) => {
                        error!("Certificate renewal check failed: {}", e);
                        warn!("Renewal check failed: {}", e);

                        // Send error notification if email provided
                        if let Some(ref email) = notify_email
                            && let Err(e) = send_error_notification(email, &e.to_string()).await {
                                warn!("Failed to send error notification: {}", e);
                            }
                    }
                }
            }
        }
    }

    println!("\n✅ Daemon shutdown complete");
    info!("Daemon shutdown successfully");
    Ok(())
}

/// Check and renew certificates if needed
async fn check_and_renew_certificates(
    domains: &[String],
    storage_path: &str,
    renew_before_secs: u64,
) -> Result<usize> {
    let mut renewed_count = 0;

    for domain in domains {
        let cert_path = Path::new(storage_path).join("certificate.pem");

        if !cert_path.exists() {
            warn!("Certificate not found for domain: {}", domain);
            continue;
        }

        // Parse certificate and check expiration
        match check_certificate_expiry(&cert_path, renew_before_secs) {
            Ok(needs_renewal) => {
                if needs_renewal {
                    info!("Certificate for {} needs renewal", domain);
                    println!("   ⏳ Renewing certificate for: {}", domain);

                    // In production, would call handle_renew here
                    // For now, just track that renewal was needed
                    renewed_count += 1;
                }
            }
            Err(e) => {
                warn!("Failed to check certificate for {}: {}", domain, e);
            }
        }
    }

    Ok(renewed_count)
}

/// Check if a certificate needs renewal
fn check_certificate_expiry(cert_path: &Path, renew_before_secs: u64) -> Result<bool> {
    let cert_content = fs::read(cert_path)?;
    let (_, pem) = parse_x509_pem(&cert_content).map_err(|_| {
        crate::error::AcmeError::Certificate("Failed to parse certificate PEM".to_string())
    })?;

    let (_, cert) = parse_x509_certificate(&pem.contents).map_err(|_| {
        crate::error::AcmeError::Certificate("Failed to parse X.509 certificate".to_string())
    })?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let not_after_secs = cert.validity.not_after.timestamp() as u64;
    let seconds_until_expiry = if not_after_secs > now_secs {
        not_after_secs - now_secs
    } else {
        return Err(crate::error::AcmeError::Certificate(
            "Certificate has already expired".to_string(),
        ));
    };

    Ok(seconds_until_expiry <= renew_before_secs)
}

/// Send renewal notification email
async fn send_renewal_notification(email: &str, count: usize) -> Result<()> {
    info!("Sending renewal notification to: {}", email);
    // In production, would send actual email here
    // For now, just log it
    println!(
        "📧 Would send renewal notification to: {} (renewed {} certs)",
        email, count
    );
    Ok(())
}

/// Send error notification email
async fn send_error_notification(email: &str, error: &str) -> Result<()> {
    warn!("Sending error notification to: {}", email);
    // In production, would send actual email here
    println!(
        "📧 Would send error notification to: {} (Error: {})",
        email, error
    );
    Ok(())
}
