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

    /// Performs local chain checks only.
    ///
    /// AcmeX intentionally does not expose a production OCSP/CRL status
    /// capability yet: the previous OCSP verifier only simulated `Good`
    /// responses from a URL shape check. Callers that need revocation-state
    /// monitoring must wire a real status checker outside this method.
    pub async fn verify_deep(&self) -> Result<()> {
        self.verify()
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

    /// Verifies the leaf certificate's signature against the public key of
    /// the given issuer certificate (the DER of the next certificate in the
    /// chain).
    ///
    /// Returns `Ok(false)` when the signature provably does not verify.
    /// Unsupported signature algorithms and malformed input surface as
    /// errors so callers can tell "provably not signed" from "cannot be
    /// evaluated" (T07 strict verification).
    pub fn verify_leaf_signed_by(&self, issuer_der: &[u8]) -> Result<bool> {
        verify_cert_signature(&self.leaf, Some(issuer_der))
    }

    /// Whether the leaf is self-signed (its signature verifies with its own
    /// subject public key).
    pub fn verify_leaf_self_signed(&self) -> Result<bool> {
        verify_cert_signature(&self.leaf, None)
    }

    /// Verifies that the presented chain terminates at one of the configured
    /// trust anchors. Anchors are PEM encoded CA certificates supplied by
    /// configuration; an empty anchor set is a caller policy decision and is
    /// not treated as trusted here.
    pub fn verify_trusted_by_pem(&self, trust_anchor_pems: &[String]) -> Result<bool> {
        let mut anchors = Vec::new();
        for pem in trust_anchor_pems {
            for block in parse_many(pem.as_bytes())
                .map_err(|e| AcmeError::crypto(format!("Failed to parse trust anchor PEM: {e}")))?
            {
                if block.tag() == "CERTIFICATE" {
                    anchors.push(block.contents().to_vec());
                }
            }
        }
        self.verify_trusted_by_der(&anchors)
    }

    /// Verifies trust against DER-encoded anchor certificates.
    pub fn verify_trusted_by_der(&self, trust_anchors: &[Vec<u8>]) -> Result<bool> {
        if trust_anchors.is_empty() {
            return Ok(false);
        }

        let mut chain = Vec::with_capacity(self.intermediates.len() + 1);
        chain.push(self.leaf.clone());
        chain.extend(self.intermediates.iter().cloned());

        for pair in chain.windows(2) {
            if !verify_cert_signature(&pair[0], Some(&pair[1]))? {
                return Ok(false);
            }
        }

        let Some(last) = chain.last() else {
            return Ok(false);
        };
        for anchor in trust_anchors {
            if last == anchor {
                return verify_cert_signature(anchor, None);
            }
            if verify_cert_signature(last, Some(anchor))? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Verifies a certificate's signature with the issuer's SubjectPublicKeyInfo
/// (`None` = the certificate's own key, i.e. a self-signature check).
fn verify_cert_signature(cert_der: &[u8], issuer_der: Option<&[u8]>) -> Result<bool> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AcmeError::crypto(format!("Invalid certificate: {}", e)))?;
    let mut issuer_cert = None;
    if let Some(der) = issuer_der {
        let (_, parsed) = X509Certificate::from_der(der)
            .map_err(|e| AcmeError::certificate(format!("Invalid issuer certificate: {}", e)))?;
        issuer_cert = Some(parsed);
    }
    let issuer_key = issuer_cert.as_ref().map(|issuer| issuer.public_key());
    match cert.verify_signature(issuer_key) {
        Ok(()) => Ok(true),
        // A bad signature is a negative answer, not an error.
        Err(x509_parser::error::X509Error::SignatureVerificationError) => Ok(false),
        Err(err) => Err(AcmeError::certificate(format!(
            "signature verification failed: {err}"
        ))),
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

    /// A self-signed test CA valid across a wide window.
    fn test_ca(common_name: &str) -> rcgen::CertifiedIssuer<'_, rcgen::KeyPair> {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2027, 1, 1);
        rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap()).unwrap()
    }

    /// A leaf for `domain` signed by `issuer` with the given subject key.
    fn ca_signed_leaf_pem(
        domain: &str,
        leaf_key: &rcgen::KeyPair,
        issuer: &rcgen::CertifiedIssuer<rcgen::KeyPair>,
    ) -> String {
        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain);
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2027, 1, 1);
        params.signed_by(leaf_key, issuer).unwrap().pem()
    }

    fn der_of(pem: &str) -> Vec<u8> {
        parse_many(pem.as_bytes())
            .unwrap()
            .remove(0)
            .contents()
            .to_vec()
    }

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

    #[test]
    fn leaf_signature_verification_detects_wrong_issuer() {
        let ca = test_ca("acmex test ca");
        let other_ca = test_ca("acmex other ca");
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_pem = ca_signed_leaf_pem("example.com", &leaf_key, &ca);
        let chain = CertificateChain {
            leaf: der_of(&leaf_pem),
            intermediates: vec![ca.der().to_vec()],
            root: None,
        };

        // The leaf is signed by the included intermediate.
        assert!(
            chain
                .verify_leaf_signed_by(&chain.intermediates[0])
                .unwrap()
        );
        // ... and not by an unrelated CA.
        assert!(
            !chain
                .verify_leaf_signed_by(other_ca.der().as_ref())
                .unwrap()
        );
        // A CA-signed leaf is not self-signed.
        assert!(!chain.verify_leaf_self_signed().unwrap());
    }

    #[test]
    fn trust_anchor_verification_requires_configured_root() {
        let ca = test_ca("acmex test ca");
        let other_ca = test_ca("acmex other ca");
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_pem = ca_signed_leaf_pem("example.com", &leaf_key, &ca);
        let chain = CertificateChain {
            leaf: der_of(&leaf_pem),
            intermediates: Vec::new(),
            root: None,
        };

        assert!(
            chain
                .verify_trusted_by_der(&[ca.der().as_ref().to_vec()])
                .unwrap()
        );
        assert!(
            !chain
                .verify_trusted_by_der(&[other_ca.der().as_ref().to_vec()])
                .unwrap()
        );
        assert!(!chain.verify_trusted_by_der(&[]).unwrap());
    }

    #[test]
    fn self_signed_leaf_verifies_against_its_own_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "example.com");
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2027, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let chain = CertificateChain {
            leaf: cert.der().to_vec(),
            intermediates: Vec::new(),
            root: None,
        };
        assert!(chain.verify_leaf_self_signed().unwrap());
    }
}
