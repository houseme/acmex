use crate::certificate::OcspVerifier;
/// Certificate chain verification and management
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::domain::{DnsIdentifier, Identifier};
use crate::error::{AcmeError, Result};
use jiff::Zoned;
use x509_parser::asn1_rs::FromDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::*;

/* Use ::pem to avoid ambiguity with modules in x509_parser */
use ::pem::parse_many;

/// Typed Subject Alternative Names from a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificateSubjectAltNames {
    /// DNSName SAN entries.
    pub dns_names: Vec<String>,
    /// iPAddress SAN entries.
    pub ip_addresses: Vec<IpAddr>,
}

impl CertificateSubjectAltNames {
    fn identifiers(&self) -> Vec<Identifier> {
        let mut identifiers = self
            .dns_names
            .iter()
            .map(|name| {
                Identifier::try_dns(name)
                    .unwrap_or_else(|_| Identifier::Dns(DnsIdentifier::parse_lenient(name)))
            })
            .chain(self.ip_addresses.iter().copied().map(Identifier::Ip))
            .collect::<Vec<_>>();
        identifiers.sort();
        identifiers.dedup();
        identifiers
    }
}

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
        let typed = self.typed_subject_alt_names()?;
        let mut sans = typed.dns_names;
        sans.extend(typed.ip_addresses.into_iter().map(|ip| ip.to_string()));
        Ok(sans)
    }

    /// Get typed Subject Alternative Names (SANs).
    pub fn typed_subject_alt_names(&self) -> Result<CertificateSubjectAltNames> {
        let (_, cert) = X509Certificate::from_der(&self.leaf)
            .map_err(|e| AcmeError::crypto(format!("Invalid leaf certificate: {}", e)))?;

        let mut sans = CertificateSubjectAltNames::default();

        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san_ext) = ext.parsed_extension() {
                for name in &san_ext.general_names {
                    if let GeneralName::DNSName(dns) = name {
                        sans.dns_names.push(dns.to_string());
                    } else if let GeneralName::IPAddress(ip) = name
                        && let Some(ip_addr) = decode_ip_san(ip)
                    {
                        sans.ip_addresses.push(ip_addr);
                    }
                }
            }
        }

        Ok(sans)
    }

    /// Verify the leaf certificate SAN set exactly matches typed identifiers.
    pub fn verify_identifiers_exact(&self, expected: &[Identifier]) -> Result<()> {
        let mut actual = self.typed_subject_alt_names()?.identifiers();
        let mut expected = expected.to_vec();
        actual.sort();
        actual.dedup();
        expected.sort();
        expected.dedup();
        if actual == expected {
            Ok(())
        } else {
            Err(AcmeError::certificate(format!(
                "certificate SAN mismatch: actual={actual:?}, expected={expected:?}"
            )))
        }
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

    /// The leaf certificate's `notBefore` instant.
    pub fn not_before(&self) -> Result<Zoned> {
        let (_, cert) = X509Certificate::from_der(&self.leaf)
            .map_err(|e| AcmeError::crypto(format!("Invalid leaf certificate: {}", e)))?;
        let timestamp = jiff::Timestamp::from_second(cert.validity().not_before.timestamp())
            .map_err(|e| AcmeError::crypto(format!("notBefore conversion failed: {e}")))?;
        Ok(timestamp.to_zoned(jiff::tz::TimeZone::UTC))
    }

    /// The leaf certificate's `notAfter` instant.
    pub fn not_after(&self) -> Result<Zoned> {
        let (_, cert) = X509Certificate::from_der(&self.leaf)
            .map_err(|e| AcmeError::crypto(format!("Invalid leaf certificate: {}", e)))?;
        let timestamp = jiff::Timestamp::from_second(cert.validity().not_after.timestamp())
            .map_err(|e| AcmeError::crypto(format!("notAfter conversion failed: {e}")))?;
        Ok(timestamp.to_zoned(jiff::tz::TimeZone::UTC))
    }

    /// The leaf certificate serial number, hex-encoded.
    pub fn serial_hex(&self) -> Result<String> {
        let (_, cert) = X509Certificate::from_der(&self.leaf)
            .map_err(|e| AcmeError::crypto(format!("Invalid leaf certificate: {}", e)))?;
        Ok(cert.serial.to_str_radix(16))
    }
}

fn decode_ip_san(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, SanType};

    #[test]
    fn test_certificate_chain_parsing() {
        // Generate a self-signed cert for testing
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "example.com");
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let pem = cert.pem();

        let chain = CertificateChain::from_pem(pem.as_bytes()).unwrap();
        assert!(!chain.leaf.is_empty());
        assert!(chain.intermediates.is_empty());

        assert_eq!(chain.common_name().unwrap(), "example.com");
        assert_eq!(chain.subject_alt_names().unwrap(), vec!["example.com"]);
    }

    #[test]
    fn typed_sans_preserve_ip_type_and_exact_verification() {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![
            SanType::DnsName("example.com".try_into().unwrap()),
            SanType::IpAddress("192.0.2.1".parse().unwrap()),
        ];
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let chain = CertificateChain {
            leaf: cert.der().to_vec(),
            intermediates: Vec::new(),
            root: None,
        };

        let typed = chain.typed_subject_alt_names().unwrap();
        assert_eq!(typed.dns_names, vec!["example.com"]);
        assert_eq!(
            typed.ip_addresses,
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        chain
            .verify_identifiers_exact(&[
                Identifier::try_dns("example.com").unwrap(),
                Identifier::try_ip("192.0.2.1").unwrap(),
            ])
            .unwrap();
        assert!(
            chain
                .verify_identifiers_exact(&[
                    Identifier::try_dns("example.com").unwrap(),
                    Identifier::try_dns("192.0.2.1").unwrap(),
                ])
                .is_err()
        );
    }
}
