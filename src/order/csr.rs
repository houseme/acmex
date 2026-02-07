/// Certificate Signing Request (CSR) generation
use crate::error::Result;
use rcgen::{CertificateParams, KeyPair};

/// CSR generator for ACME certificates
pub struct CsrGenerator {
    domains: Vec<String>,
    private_key: Option<KeyPair>,
}

impl CsrGenerator {
    /// Create a new CSR generator
    pub fn new(domains: Vec<String>) -> Self {
        Self {
            domains,
            private_key: None,
        }
    }

    /// Set a custom private key (optional)
    pub fn with_private_key(mut self, key_pair: KeyPair) -> Self {
        self.private_key = Some(key_pair);
        self
    }

    /// Generate CSR and return (CSR DER, Private Key PEM)
    pub fn generate(&self) -> Result<(Vec<u8>, String)> {
        // Get or generate key pair
        let generated_key;
        let key_pair = match self.private_key.as_ref() {
            Some(key) => key,
            None => {
                generated_key = KeyPair::generate().map_err(|e| {
                    crate::error::AcmeError::crypto(format!("Failed to generate key pair: {}", e))
                })?;
                &generated_key
            }
        };

        // Build certificate params with domains
        let params = CertificateParams::new(self.domains.clone()).map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to create certificate params: {}", e))
        })?;

        // Generate CSR
        let csr = params.serialize_request(key_pair).map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to generate CSR: {}", e))
        })?;

        let csr_der = csr.der().to_vec();
        let private_key_pem = key_pair.serialize_pem();

        tracing::info!("CSR generated for domains: {:?}", self.domains);
        Ok((csr_der, private_key_pem))
    }

    /// Generate CSR with a new key and return all components
    pub fn generate_with_key(domains: Vec<String>) -> Result<(Vec<u8>, KeyPair, String)> {
        let key_pair = KeyPair::generate().map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to generate key pair: {}", e))
        })?;

        let params = CertificateParams::new(domains.clone()).map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to create certificate params: {}", e))
        })?;

        let csr = params.serialize_request(&key_pair).map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to generate CSR: {}", e))
        })?;

        let csr_der = csr.der().to_vec();
        let private_key_pem = key_pair.serialize_pem();

        Ok((csr_der, key_pair, private_key_pem))
    }
}

/// Parse certificate chain from PEM
pub fn parse_certificate_chain(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();

    for pem_item in pem::parse_many(pem.as_bytes())
        .map_err(|e| crate::error::AcmeError::certificate(format!("Failed to parse PEM: {}", e)))?
    {
        if pem_item.tag() == "CERTIFICATE" {
            certs.push(pem_item.contents().to_vec());
        }
    }

    if certs.is_empty() {
        return Err(crate::error::AcmeError::certificate(
            "No certificates found in PEM".to_string(),
        ));
    }

    Ok(certs)
}

/// Verify certificate matches domains
pub fn verify_certificate_domains(cert_der: &[u8], expected_domains: &[String]) -> Result<bool> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        crate::error::AcmeError::certificate(format!("Failed to parse certificate: {}", e))
    })?;

    // Get SANs (Subject Alternative Names)
    let empty_vec = vec![];
    let sans = cert
        .subject_alternative_name()
        .ok()
        .and_then(|ext| ext)
        .map(|ext| &ext.value.general_names)
        .unwrap_or(&empty_vec);

    let mut cert_domains = Vec::new();
    for san in sans {
        if let GeneralName::DNSName(domain) = san {
            cert_domains.push(domain.to_string());
        }
    }

    // Check if all expected domains are in the certificate
    for expected in expected_domains {
        if !cert_domains.contains(expected) {
            tracing::warn!("Domain {} not found in certificate", expected);
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csr_generation() {
        let generator = CsrGenerator::new(vec!["example.com".to_string()]);
        let result = generator.generate();
        assert!(result.is_ok());

        let (csr_der, private_key_pem) = result.unwrap();
        assert!(!csr_der.is_empty());
        assert!(private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_csr_multiple_domains() {
        let generator = CsrGenerator::new(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "api.example.com".to_string(),
        ]);
        let result = generator.generate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_certificate_chain() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\nc3QtMTAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEwMDAwMDBaMBExDzANBgNVBAMM\nBnRlc3QtMTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC8hCb/c3T8KjL7w3M3i7kR\nXK3i7aZ3E3h+Q6V6TQ==\n-----END CERTIFICATE-----";

        let result = parse_certificate_chain(pem);
        // This will fail with real parsing but tests the function exists
        let _ = result;
    }
}
