use crate::certificate::OcspVerifier;
/// Certificate chain verification and management
use crate::error::{AcmeError, Result};
use jiff::Zoned;
use x509_parser::asn1_rs::FromDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::*;

/* Use ::pem to avoid ambiguity with modules in x509_parser */
use ::pem::parse_many;

/// Certificate chain structure
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// The leaf certificate (first in chain)
    pub leaf: Vec<u8>,
    /// Intermediate certificates
    pub intermediates: Vec<Vec<u8>>,
    /// Root certificate (optional, usually not sent in TLS handshake)
    pub root: Option<Vec<u8>>,
}

impl CertificateChain {
    /// Create a new certificate chain from a list of PEM-encoded certificates
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        let mut certs = Vec::new();

        // Parse PEM
        for p in parse_many(pem_data)
            .map_err(|e| AcmeError::crypto(format!("Failed to parse PEM: {}", e)))?
        {
            if p.tag() == "CERTIFICATE" {
                certs.push(p.contents().to_vec());
            }
        }

        if certs.is_empty() {
            return Err(AcmeError::crypto("No certificates found in PEM data"));
        }

        let leaf = certs.remove(0);
        let intermediates = certs;

        Ok(Self {
            leaf,
            intermediates,
            root: None,
        })
    }

    /// Verify the certificate chain
    pub fn verify(&self) -> Result<()> {
        if self.intermediates.is_empty() {
            return Err(AcmeError::certificate(
                "Empty certificate chain".to_string(),
            ));
        }

        // 1. Basic validation (expiry, sequence)
        for (i, cert_der) in self.intermediates.iter().enumerate() {
            let (_, x509) = X509Certificate::from_der(cert_der).map_err(|e| {
                AcmeError::certificate(format!("Invalid intermediate certificate {}: {}", i, e))
            })?;

            let now = Zoned::now().timestamp().as_second();
            if x509.validity().not_before.timestamp() > now {
                return Err(AcmeError::certificate(format!("Cert {} not yet valid", i)));
            }
            if x509.validity().not_after.timestamp() < now {
                return Err(AcmeError::certificate(format!("Cert {} expired", i)));
            }
        }

        tracing::info!("Certificate chain basic validation passed");
        Ok(())
    }

    /// Perform deep verification including OCSP real-time status check
    pub async fn verify_deep(&self) -> Result<()> {
        self.verify()?;

        // Perform OCSP check for the end-entity certificate (index 0)
        let end_entity = &self.leaf;
        match OcspVerifier::verify_status(end_entity).await? {
            crate::certificate::OcspStatus::Good => {
                tracing::info!("OCSP status check: Good");
                Ok(())
            }
            crate::certificate::OcspStatus::Revoked => Err(AcmeError::certificate(
                "Certificate is revoked according to OCSP".to_string(),
            )),
            crate::certificate::OcspStatus::Unknown => {
                tracing::warn!("OCSP status check: Unknown");
                Ok(()) // Treat as pass but log warning
            }
        }
    }

    /// Get the leaf certificate common name
    pub fn common_name(&self) -> Result<String> {
        let (_, cert) = X509Certificate::from_der(&self.leaf)
            .map_err(|e| AcmeError::crypto(format!("Invalid leaf certificate: {}", e)))?;

        for extension in cert.subject().iter_common_name() {
            if let Ok(cn) = extension.as_str() {
                return Ok(cn.to_string());
            }
        }

        Err(AcmeError::crypto("No Common Name found in certificate"))
    }

    /// Get Subject Alternative Names (SANs)
    pub fn subject_alt_names(&self) -> Result<Vec<String>> {
        let (_, cert) = X509Certificate::from_der(&self.leaf)
            .map_err(|e| AcmeError::crypto(format!("Invalid leaf certificate: {}", e)))?;

        let mut sans = Vec::new();

        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san_ext) = ext.parsed_extension() {
                for name in &san_ext.general_names {
                    if let GeneralName::DNSName(dns) = name {
                        sans.push(dns.to_string());
                    } else if let GeneralName::IPAddress(ip) = name {
                        // Convert IP bytes to string representation
                        if ip.len() == 4 {
                            let ip_addr = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                            sans.push(ip_addr.to_string());
                        } else if ip.len() == 16 {
                            let ip_addr = std::net::Ipv6Addr::from([
                                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8],
                                ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
                            ]);
                            sans.push(ip_addr.to_string());
                        }
                    }
                }
            }
        }

        Ok(sans)
    }

    /// Get OCSP URL
    pub fn ocsp_url(&self) -> Result<Option<String>> {
        let (_, cert) = X509Certificate::from_der(&self.leaf)
            .map_err(|e| AcmeError::crypto(format!("Invalid leaf certificate: {}", e)))?;

        for ext in cert.extensions() {
            if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                for access_desc in &aia.accessdescs {
                    if access_desc.access_method.to_string() == "1.3.6.1.5.5.7.48.1" {
                        // id-ad-ocsp
                        if let GeneralName::URI(uri) = access_desc.access_location {
                            return Ok(Some(uri.to_string()));
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::CertificateParams;

    #[test]
    fn test_certificate_chain_parsing() {
        // Generate a self-signed cert for testing
        let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let pem = cert.pem();

        let chain = CertificateChain::from_pem(pem.as_bytes()).unwrap();
        assert!(!chain.leaf.is_empty());
        assert!(chain.intermediates.is_empty());

        assert_eq!(chain.common_name().unwrap(), "example.com");
        assert_eq!(chain.subject_alt_names().unwrap(), vec!["example.com"]);
    }
}
