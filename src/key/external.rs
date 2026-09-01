//! External CSR validation: the caller keeps the private key.
//!
//! [`validate_external_csr`] verifies that a submitted CSR (a) carries a
//! valid self-signature and (b) requests *exactly* the intended identifier
//! set — typed SANs, both directions, no extras, no missing, and never an
//! IP address spelled as a dNSName.

use std::collections::BTreeSet;
use std::net::IpAddr;

use x509_parser::asn1_rs::FromDer;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::ParsedExtension;

use crate::domain::{Identifier, IdentifierSet};
use crate::error::{AcmeError, Result};

/// Validates an externally supplied CSR against the intended identifiers.
///
/// Returns the parsed identifier set on success; errors name the exact
/// mismatch. Policy violations (wrong SAN types, extra names) are rejected
/// before any order is created.
pub fn validate_external_csr(csr_der: &[u8], expected: &IdentifierSet) -> Result<IdentifierSet> {
    let (_, request) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| AcmeError::InvalidInput(format!("cannot parse CSR: {e}")))?;

    // Self-signature proves possession of the private key.
    request
        .verify_signature()
        .map_err(|e| AcmeError::crypto(format!("CSR self-signature invalid: {e}")))?;

    let mut dns_names = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let extensions = request.requested_extensions().ok_or_else(|| {
        AcmeError::InvalidInput("CSR carries no extension request (SAN missing)".to_string())
    })?;
    for ext in extensions {
        if let ParsedExtension::SubjectAlternativeName(san) = ext {
            for name in &san.general_names {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => {
                        dns_names.insert(dns.to_string());
                    }
                    x509_parser::extensions::GeneralName::IPAddress(octets) => {
                        if let Some(ip) = octets_to_ip(octets) {
                            ips.insert(ip);
                        }
                    }
                    other => {
                        return Err(AcmeError::InvalidInput(format!(
                            "CSR contains an unsupported SAN entry ({other:?}); \
                             only dNSName and iPAddress are allowed"
                        )));
                    }
                }
            }
        }
    }

    let observed: IdentifierSet = IdentifierSet::new(
        dns_names
            .iter()
            .filter_map(|n| Identifier::try_dns(n).ok())
            .chain(ips.into_iter().map(Identifier::Ip))
            .collect(),
    )
    .map_err(|e| AcmeError::InvalidInput(e.to_string()))?;

    if observed != *expected {
        let missing: Vec<_> = expected
            .iter()
            .filter(|id| !observed.as_slice().contains(id))
            .map(|id| id.to_string())
            .collect();
        let extra: Vec<_> = observed
            .iter()
            .filter(|id| !expected.as_slice().contains(id))
            .map(|id| id.to_string())
            .collect();
        return Err(AcmeError::InvalidInput(format!(
            "CSR identifiers do not match the intent exactly (missing: {missing:?}, extra: {extra:?})"
        )));
    }
    Ok(observed)
}

fn octets_to_ip(octets: &[u8]) -> Option<IpAddr> {
    match octets.len() {
        4 => Some(IpAddr::from([octets[0], octets[1], octets[2], octets[3]])),
        16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(octets);
            Some(IpAddr::from(bytes))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, SanType};

    fn build_csr(identifiers: &[Identifier]) -> Vec<u8> {
        let pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        for identifier in identifiers {
            match identifier {
                Identifier::Dns(name) => params.subject_alt_names.push(SanType::DnsName(
                    name.to_wire_value().try_into().expect("valid DNS SAN"),
                )),
                Identifier::Ip(addr) => params.subject_alt_names.push(SanType::IpAddress(*addr)),
            }
        }
        let request = params.serialize_request(&pair).unwrap();
        request.der().to_vec()
    }

    #[test]
    fn exact_match_passes_with_typed_sans() {
        let expected = IdentifierSet::new(vec![
            Identifier::try_dns("example.com").unwrap(),
            Identifier::try_ip("192.0.2.1").unwrap(),
            Identifier::try_ip("2001:db8::1").unwrap(),
        ])
        .unwrap();
        let csr = build_csr(&[
            Identifier::try_dns("EXAMPLE.com").unwrap(),
            Identifier::try_ip("192.0.2.1").unwrap(),
            Identifier::try_ip("2001:db8::1").unwrap(),
        ]);
        let observed = validate_external_csr(&csr, &expected).unwrap();
        assert_eq!(observed, expected);
    }

    #[test]
    fn extra_san_is_rejected() {
        let expected = IdentifierSet::parse(["example.com"]).unwrap();
        let csr = build_csr(&[
            Identifier::try_dns("example.com").unwrap(),
            Identifier::try_dns("extra.example.org").unwrap(),
        ]);
        let err = validate_external_csr(&csr, &expected).unwrap_err();
        assert!(err.to_string().contains("extra"), "got: {err}");
    }

    #[test]
    fn missing_san_is_rejected() {
        let expected = IdentifierSet::parse(["example.com", "www.example.com"]).unwrap();
        let csr = build_csr(&[Identifier::try_dns("example.com").unwrap()]);
        let err = validate_external_csr(&csr, &expected).unwrap_err();
        assert!(err.to_string().contains("missing"), "got: {err}");
    }

    #[test]
    fn wrong_san_type_is_rejected() {
        // An IP spelled as a dNSName is not the same identifier.
        let expected = IdentifierSet::new(vec![Identifier::try_ip("192.0.2.1").unwrap()]).unwrap();
        let csr = build_csr(&[Identifier::try_dns("192.0.2.1").unwrap()]);
        assert!(validate_external_csr(&csr, &expected).is_err());
    }

    #[test]
    fn garbage_csr_is_rejected_cleanly() {
        let expected = IdentifierSet::parse(["example.com"]).unwrap();
        let err = validate_external_csr(b"not a csr", &expected).unwrap_err();
        assert!(err.to_string().contains("parse"));
    }
}
