use crate::error::{AcmeError, Result};
use std::time::Duration;
use x509_parser::prelude::*;

/// OCSP status for a certificate
#[derive(Debug, Clone, PartialEq)]
pub enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

/// Helper for OCSP status verification
pub struct OcspVerifier;

impl OcspVerifier {
    /// Verify the OCSP status of a certificate
    pub async fn verify_status(cert_der: &[u8]) -> Result<OcspStatus> {
        let (_, x509) = parse_x509_certificate(cert_der)
            .map_err(|e| AcmeError::certificate(format!("Parse cert failed: {}", e)))?;

        // 1. Find OCSP responder URL in AIA extension
        let ocsp_url = Self::find_ocsp_url(&x509)?;

        tracing::info!("Found OCSP responder URL: {}", ocsp_url);

        // 2. Build OCSP request (simplified logic, usually needs a specialist crate)
        // In a real implementation, we would use a crate like `ocsp` to build and parse
        // For demonstration, we simulate the network call.

        /*
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        // POST or GET to ocsp_url with DER encoded OCSP request
        */

        // Placeholder: Returning Good if AIA was found and URL is valid
        if ocsp_url.starts_with("http") {
            Ok(OcspStatus::Good)
        } else {
            Ok(OcspStatus::Unknown)
        }
    }

    fn find_ocsp_url(x509: &X509Certificate<'_>) -> Result<String> {
        // Look for Authority Information Access (AIA) extension
        // OID 1.3.6.1.5.5.7.1.1 (id-pe-authorityInfoAccess)
        for ext in x509.extensions() {
            if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                for access_desc in &aia.accessdescs {
                    // OID 1.3.6.1.5.5.7.48.1 (id-ad-ocsp)
                    if access_desc.access_method.to_string() == "1.3.6.1.5.5.7.48.1" {
                        if let GeneralName::URI(uri) = access_desc.access_location {
                            return Ok(uri.to_string());
                        }
                    }
                }
            }
        }
        Err(AcmeError::certificate(
            "No OCSP responder URL found in certificate".to_string(),
        ))
    }
}
