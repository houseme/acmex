/// Show certificate information - Complete implementation
use crate::error::Result;
use std::fs;
use tracing::info;
use x509_parser::prelude::*;

/// Display detailed certificate information
pub fn handle_info(cert_path: String) -> Result<()> {
    info!("Reading certificate info from: {}", cert_path);

    println!("📋 Certificate Information");
    println!("   File: {}", cert_path);

    // Check if file exists
    let metadata = fs::metadata(&cert_path).map_err(|_| {
        crate::error::AcmeError::NotFound(format!("Certificate file not found: {}", cert_path))
    })?;

    println!("   Size: {} bytes", metadata.len());

    // Read and parse certificate
    let cert_content = fs::read(&cert_path)?;
    let (_, pem) = parse_x509_pem(&cert_content).map_err(|_| {
        crate::error::AcmeError::Certificate("Failed to parse certificate PEM".to_string())
    })?;

    let (_, cert) = parse_x509_certificate(&pem.contents).map_err(|_| {
        crate::error::AcmeError::Certificate("Failed to parse X.509 certificate".to_string())
    })?;

    println!("\n🔐 Certificate Details:");
    println!("   Subject: {}", cert.subject);
    println!("   Issuer: {}", cert.issuer);
    println!("   Serial Number: {}", cert.serial);

    // Validity period
    println!("\n⏰ Validity Period:");
    println!("   Valid From: {}", cert.validity.not_before);
    println!("   Valid Until: {}", cert.validity.not_after);

    // Calculate days until expiry
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let not_after_secs = cert.validity.not_after.timestamp() as u64;

    if not_after_secs > now_secs {
        let days_until_expiry = (not_after_secs - now_secs) / (24 * 3600);
        println!("   Days Until Expiry: {} days ⏳", days_until_expiry);
    } else {
        let days_since_expiry = (now_secs - not_after_secs) / (24 * 3600);
        println!("   ⚠️  Certificate EXPIRED {} days ago", days_since_expiry);
    }

    // Extensions summary
    let extensions = cert.extensions_map().map_err(|e| {
        crate::error::AcmeError::Certificate(format!("Failed to parse extensions: {}", e))
    })?;
    let ext_count = extensions.len();
    println!("\n📄 Extensions ({}):", ext_count);
    for (oid, ext) in extensions.iter().take(10) {
        println!("   • {} (Critical: {})", oid, ext.critical);
    }
    if ext_count > 10 {
        println!("   ... and {} more extensions", ext_count - 10);
    }

    println!("\n✅ Certificate information displayed successfully");
    Ok(())
}
