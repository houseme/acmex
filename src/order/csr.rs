/// Certificate Signing Request (CSR) generation
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rcgen::{CertificateParams, KeyPair, SanType};
use x509_parser::prelude::*;

use crate::domain::{DnsIdentifier, Identifier};
use crate::error::{AcmeError, Result};

/// CSR generator for ACME certificates.
pub struct CsrGenerator {
    identifiers: Vec<Identifier>,
    private_key: Option<KeyPair>,
}

impl CsrGenerator {
    /// Create a new DNS-only CSR generator.
    pub fn new(domains: Vec<String>) -> Self {
        Self {
            identifiers: domains
                .into_iter()
                .map(|domain| Identifier::Dns(DnsIdentifier::parse_lenient(&domain)))
                .collect(),
            private_key: None,
        }
    }

    /// Create a CSR generator from typed ACME identifiers.
    pub fn for_identifiers(identifiers: Vec<Identifier>) -> Self {
        Self {
            identifiers,
            private_key: None,
        }
    }

    /// Set a custom private key.
    pub fn with_private_key(mut self, key_pair: KeyPair) -> Self {
        self.private_key = Some(key_pair);
        self
    }

    /// Generate CSR and return (CSR DER, Private Key PEM).
    pub fn generate(&self) -> Result<(Vec<u8>, String)> {
        let generated_key;
        let key_pair = match self.private_key.as_ref() {
            Some(key) => key,
            None => {
                generated_key = KeyPair::generate()
                    .map_err(|err| AcmeError::crypto(format!("generate CSR key: {err}")))?;
                &generated_key
            }
        };

        let params = certificate_params_for_identifiers(&self.identifiers)?;
        let csr = params
            .serialize_request(key_pair)
            .map_err(|err| AcmeError::crypto(format!("generate CSR: {err}")))?;

        tracing::info!(
            identifiers = ?self
                .identifiers
                .iter()
                .map(Identifier::acme_value)
                .collect::<Vec<_>>(),
            "CSR generated"
        );
        Ok((csr.der().to_vec(), key_pair.serialize_pem()))
    }

    /// Generate CSR with a new key and return all components.
    pub fn generate_with_key(domains: Vec<String>) -> Result<(Vec<u8>, KeyPair, String)> {
        Self::generate_for_identifiers_with_key(
            domains
                .into_iter()
                .map(|domain| Identifier::Dns(DnsIdentifier::parse_lenient(&domain)))
                .collect(),
        )
    }

    /// Generate an identifier-aware CSR with a new key and return all components.
    pub fn generate_for_identifiers_with_key(
        identifiers: Vec<Identifier>,
    ) -> Result<(Vec<u8>, KeyPair, String)> {
        let key_pair = KeyPair::generate()
            .map_err(|err| AcmeError::crypto(format!("generate CSR key: {err}")))?;
        let params = certificate_params_for_identifiers(&identifiers)?;
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|err| AcmeError::crypto(format!("generate CSR: {err}")))?;
        let private_key_pem = key_pair.serialize_pem();
        Ok((csr.der().to_vec(), key_pair, private_key_pem))
    }
}

fn certificate_params_for_identifiers(identifiers: &[Identifier]) -> Result<CertificateParams> {
    if identifiers.is_empty() {
        return Err(AcmeError::invalid_input(
            "CSR requires at least one identifier",
        ));
    }
    let mut params = CertificateParams::default();
    params.subject_alt_names = san_types_for_identifiers(identifiers)?;
    Ok(params)
}

fn san_types_for_identifiers(identifiers: &[Identifier]) -> Result<Vec<SanType>> {
    identifiers
        .iter()
        .map(|identifier| match identifier {
            Identifier::Dns(dns) => dns
                .to_wire_value()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|err| AcmeError::crypto(format!("invalid DNS SAN in CSR: {err}"))),
            Identifier::Ip(ip) => Ok(SanType::IpAddress(*ip)),
        })
        .collect()
}

/// Parse certificate chain from PEM.
pub fn parse_certificate_chain(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();

    for pem_item in ::pem::parse_many(pem.as_bytes())
        .map_err(|err| AcmeError::certificate(format!("parse PEM chain: {err}")))?
    {
        if pem_item.tag() == "CERTIFICATE" {
            certs.push(pem_item.contents().to_vec());
        }
    }

    if certs.is_empty() {
        return Err(AcmeError::certificate(
            "No certificates found in PEM".to_string(),
        ));
    }

    Ok(certs)
}

/// Verify certificate contains all expected DNS names.
pub fn verify_certificate_domains(cert_der: &[u8], expected_domains: &[String]) -> Result<bool> {
    let cert_identifiers = certificate_identifiers(cert_der)?;
    let cert_domains = cert_identifiers
        .iter()
        .filter_map(|identifier| match identifier {
            Identifier::Dns(dns) => Some(dns.to_wire_value()),
            Identifier::Ip(_) => None,
        })
        .collect::<Vec<_>>();

    Ok(expected_domains
        .iter()
        .all(|expected| cert_domains.contains(&expected.to_ascii_lowercase())))
}

/// Verify the final certificate SAN set exactly matches typed identifiers.
pub fn verify_certificate_identifiers(
    cert_der: &[u8],
    expected_identifiers: &[Identifier],
) -> Result<bool> {
    let mut actual = certificate_identifiers(cert_der)?;
    let mut expected = expected_identifiers.to_vec();
    actual.sort();
    actual.dedup();
    expected.sort();
    expected.dedup();
    Ok(actual == expected)
}

fn certificate_identifiers(cert_der: &[u8]) -> Result<Vec<Identifier>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|err| AcmeError::certificate(format!("parse certificate: {err}")))?;
    let Some(san) = cert
        .subject_alternative_name()
        .map_err(|err| AcmeError::certificate(format!("parse subjectAltName: {err}")))?
    else {
        return Ok(Vec::new());
    };

    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(domain) => Some(
                Identifier::try_dns(*domain)
                    .or_else(|_| Ok(Identifier::Dns(DnsIdentifier::parse_lenient(domain)))),
            ),
            GeneralName::IPAddress(ip) => decode_ip_san(ip).map(|ip| Ok(Identifier::Ip(ip))),
            _ => None,
        })
        .collect()
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

    #[test]
    fn test_csr_generation() {
        let generator = CsrGenerator::new(vec!["example.com".to_string()]);
        let (csr_der, private_key_pem) = generator.generate().unwrap();
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
        assert!(generator.generate().is_ok());
    }

    #[test]
    fn csr_generation_supports_dns_and_ip_sans() {
        let identifiers = vec![
            Identifier::try_dns("example.com").unwrap(),
            Identifier::try_ip("192.0.2.1").unwrap(),
            Identifier::try_ip("2001:db8::1").unwrap(),
        ];
        let (csr_der, _) = CsrGenerator::for_identifiers(identifiers)
            .generate()
            .unwrap();

        let (_, csr) = X509CertificationRequest::from_der(&csr_der).unwrap();
        let mut dns_names = Vec::new();
        let mut ip_addresses = Vec::new();
        for extension in csr.requested_extensions().unwrap() {
            if let ParsedExtension::SubjectAlternativeName(san) = extension {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(name) => dns_names.push(name.to_string()),
                        GeneralName::IPAddress(bytes) => {
                            ip_addresses.push(decode_ip_san(bytes).unwrap())
                        }
                        _ => {}
                    }
                }
            }
        }

        assert_eq!(dns_names, vec!["example.com"]);
        assert!(ip_addresses.contains(&"192.0.2.1".parse().unwrap()));
        assert!(ip_addresses.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn certificate_identifier_verification_is_exact_and_typed() {
        let identifiers = vec![
            Identifier::try_dns("example.com").unwrap(),
            Identifier::try_ip("192.0.2.1").unwrap(),
        ];
        let mut params = certificate_params_for_identifiers(&identifiers).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "example.com");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        assert!(verify_certificate_identifiers(cert.der(), &identifiers).unwrap());
        assert!(
            !verify_certificate_identifiers(
                cert.der(),
                &[Identifier::try_dns("example.com").unwrap()]
            )
            .unwrap()
        );
        assert!(
            !verify_certificate_identifiers(
                cert.der(),
                &[
                    Identifier::try_dns("example.com").unwrap(),
                    Identifier::try_dns("192.0.2.1").unwrap(),
                ]
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_certificate_chain() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\nc3QtMTAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEwMDAwMDBaMBExDzANBgNVBAMM\nBnRlc3QtMTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC8hCb/c3T8KjL7w3M3i7kR\nXK3i7aZ3E3h+Q6V6TQ==\n-----END CERTIFICATE-----";
        let _ = parse_certificate_chain(pem);
    }
}
