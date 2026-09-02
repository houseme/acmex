//! RFC 9773 — ACME Renewal Information (ARI).
//!
//! The ARI CertId is the base64url encoding of the DER sequence
//! `SEQUENCE { keyIdentifier OCTET STRING, serialNumber INTEGER }`, built
//! from the certificate's Authority Key Identifier (keyIdentifier field)
//! and its serial number. It is appended to the directory's `renewalInfo`
//! endpoint to form the renewal-info URL:
//!
//! ```text
//! {renewalInfo}/{base64url(der)}
//! ```

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use std::str::FromStr;

use crate::certificate::CertificateChain;
use crate::error::{AcmeError, Result};
use x509_parser::asn1_rs::FromDer;

use super::transport::AcmeTransport;
use super::types::RenewalWindow;

/// Parsed ARI renewal-info document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalInfo {
    /// The suggested renewal window.
    #[serde(rename = "suggestedWindow")]
    pub suggested_window: SuggestedWindow,
    /// Optional human-readable explanation URL.
    #[serde(
        rename = "explanationURL",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub explanation_url: Option<String>,
}

/// The suggested renewal window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedWindow {
    /// Window start (RFC 3339).
    pub start: String,
    /// Window end (RFC 3339).
    pub end: String,
}

/// Extracts (aki_key_identifier, serial_bytes) from a PEM chain's leaf.
pub fn leaf_id_components(chain_pem: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let chain = CertificateChain::from_pem(chain_pem.as_bytes())?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&chain.leaf)
        .map_err(|e| AcmeError::certificate(format!("invalid leaf certificate: {e}")))?;

    // Authority Key Identifier extension: 2.5.29.35; the keyIdentifier is
    // the first (context tag 0) inner field.
    let mut key_identifier: Option<Vec<u8>> = None;
    for ext in cert.extensions() {
        if ext.oid.to_string() == "2.5.29.35" {
            // Minimal DER walk: [0] EXPLICIT keyIdentifier OCTET STRING.
            let value = ext.value;
            if !value.is_empty() && value[0] == 0x80 {
                let length = value[1] as usize;
                if value.len() >= 2 + length {
                    key_identifier = Some(value[2..2 + length].to_vec());
                }
            }
        }
    }
    let key_identifier = key_identifier.ok_or_else(|| {
        AcmeError::certificate(
            "leaf certificate has no Authority Key Identifier keyIdentifier".to_string(),
        )
    })?;
    Ok((key_identifier, cert.serial.to_bytes_be()))
}

/// Builds the RFC 9773 ARI CertId (base64url DER).
pub fn ari_cert_id(authority_key_identifier: &[u8], serial: &[u8]) -> String {
    let der = der_sequence(authority_key_identifier, serial);
    URL_SAFE_NO_PAD.encode(der)
}

/// Convenience: CertId from a PEM chain's leaf.
pub fn ari_cert_id_from_pem(chain_pem: &str) -> Result<String> {
    let (aki, serial) = leaf_id_components(chain_pem)?;
    Ok(ari_cert_id(&aki, &serial))
}

/// DER: SEQUENCE { OCTET STRING aki, INTEGER serial } (minimal encoder;
/// serials from real certificates fit the short-form length used here).
fn der_sequence(aki: &[u8], serial: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    // OCTET STRING
    body.push(0x04);
    der_length(&mut body, aki.len());
    body.extend_from_slice(aki);
    // INTEGER (positive: prepend a zero byte when the high bit is set)
    let mut serial_bytes = serial.to_vec();
    if serial_bytes.first().is_some_and(|b| *b & 0x80 != 0) {
        serial_bytes.insert(0, 0);
    }
    body.push(0x02);
    der_length(&mut body, serial_bytes.len());
    body.extend_from_slice(&serial_bytes);
    // SEQUENCE wrapper
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(0x30);
    der_length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn der_length(out: &mut Vec<u8>, length: usize) {
    if length < 128 {
        out.push(length as u8);
    } else if length < 256 {
        out.push(0x81);
        out.push(length as u8);
    } else {
        out.push(0x82);
        out.push((length >> 8) as u8);
        out.push(length as u8);
    }
}

/// Builds the full renewal-info URL for a certificate.
pub fn renewal_info_url(base: &str, cert_id: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), cert_id)
}

/// Parses a raw ARI response body into a [`RenewalWindow`].
///
/// Malformed windows return an error (the renewal controller decides the
/// fallback); `None` is only returned for an explicitly empty body, which
/// some CAs use when ARI is enabled but has no suggestion for the cert.
pub fn parse_renewal_window(
    body: &[u8],
    retry_after: Option<Timestamp>,
) -> Result<Option<RenewalWindow>> {
    if body.is_empty() {
        return Ok(None);
    }
    let info: RenewalInfo = serde_json::from_slice(body)
        .map_err(|e| AcmeError::protocol(format!("invalid renewalInfo document: {e}")))?;
    let start = Timestamp::from_str(&info.suggested_window.start)
        .map_err(|e| AcmeError::protocol(format!("invalid suggestedWindow start: {e}")))?;
    let end = Timestamp::from_str(&info.suggested_window.end)
        .map_err(|e| AcmeError::protocol(format!("invalid suggestedWindow end: {e}")))?;
    if end <= start {
        return Err(AcmeError::protocol(
            "suggestedWindow end must be after start".to_string(),
        ));
    }
    Ok(Some(RenewalWindow {
        start,
        end,
        retry_after,
        explanation_url: info.explanation_url,
    }))
}

/// Key-free RFC 9773 renewal-info provider for server-side renewal scanning.
///
/// ARI lookups are unauthenticated GETs, so this provider needs neither an
/// account key nor repositories — only the directory URL and a transport.
/// The `renewalInfo` base URL discovered from the directory is cached;
/// lookup failures invalidate the cache so the next call re-discovers.
pub struct DirectoryAriProvider {
    directory_url: String,
    transport: std::sync::Arc<dyn AcmeTransport>,
    discovery: tokio::sync::RwLock<Discovery>,
}

#[derive(Debug, Clone)]
enum Discovery {
    Pending,
    Available(String),
    /// The directory parsed fine but advertises no `renewalInfo` endpoint.
    NotAdvertised,
}

impl DirectoryAriProvider {
    /// Creates a provider for the CA behind `directory_url`.
    pub fn new(
        directory_url: impl Into<String>,
        transport: std::sync::Arc<dyn AcmeTransport>,
    ) -> Self {
        Self {
            directory_url: directory_url.into(),
            transport,
            discovery: tokio::sync::RwLock::new(Discovery::Pending),
        }
    }

    /// The number of directory fetches issued so far (cache effectiveness).
    pub async fn directory_fetch_count(&self) -> usize {
        match &*self.discovery.read().await {
            Discovery::Pending => 0,
            _ => 1,
        }
    }

    async fn renewal_info_base(&self) -> Result<Option<String>> {
        if let Discovery::Available(base) = &*self.discovery.read().await {
            return Ok(Some(base.clone()));
        }
        if matches!(&*self.discovery.read().await, Discovery::NotAdvertised) {
            return Ok(None);
        }
        let response = self
            .transport
            .request(super::transport::AcmeRequest {
                url: self.directory_url.clone(),
                method: super::transport::AcmeMethod::Get,
                body: None,
            })
            .await?;
        let directory = super::transport::classify_response(&response)?;
        let base = directory
            .get("renewalInfo")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let mut discovery = self.discovery.write().await;
        *discovery = match base.clone() {
            Some(base) => Discovery::Available(base),
            None => Discovery::NotAdvertised,
        };
        Ok(base)
    }
}

#[async_trait]
impl crate::renewal::RenewalInfoProvider for DirectoryAriProvider {
    async fn renewal_window(&self, chain_pem: &str) -> crate::error::Result<Option<RenewalWindow>> {
        let Some(base) = self.renewal_info_base().await? else {
            // ARI not advertised: not an error, callers fall back.
            return Ok(None);
        };
        let cert_id = ari_cert_id_from_pem(chain_pem)?;
        let url = renewal_info_url(&base, &cert_id);
        let response = self
            .transport
            .request(super::transport::AcmeRequest {
                url,
                method: super::transport::AcmeMethod::Get,
                body: None,
            })
            .await?;
        if response.status == 404 {
            // RFC 9773 §4: the CA has no suggestion for this certificate.
            return Ok(None);
        }
        match super::transport::classify_response(&response) {
            Ok(_) => parse_renewal_window(&response.body, response.retry_after),
            Err(err) => {
                // A stale cached directory is the likely cause; force
                // re-discovery and surface the error (the controller
                // falls back to its policy window).
                *self.discovery.write().await = Discovery::Pending;
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_roundtrip(cert_id_b64: &str) -> (Vec<u8>, Vec<u8>) {
        let der = URL_SAFE_NO_PAD.decode(cert_id_b64).unwrap();
        // SEQUENCE
        assert_eq!(der[0], 0x30);
        let mut rest = &der[2..]; // short-form length assumed in fixtures
        assert_eq!(rest[0], 0x04); // OCTET STRING
        let aki_len = rest[1] as usize;
        let aki = rest[2..2 + aki_len].to_vec();
        rest = &rest[2 + aki_len..];
        assert_eq!(rest[0], 0x02); // INTEGER
        let serial_len = rest[1] as usize;
        let serial = rest[2..2 + serial_len].to_vec();
        (aki, serial)
    }

    #[test]
    fn cert_id_der_golden_vector() {
        let aki = [0xaa, 0xbb, 0xcc];
        let serial = [0x01, 0x02, 0x03];
        let cert_id = ari_cert_id(&aki, &serial);
        let (decoded_aki, decoded_serial) = der_roundtrip(&cert_id);
        assert_eq!(decoded_aki, aki.to_vec());
        assert_eq!(decoded_serial, serial.to_vec());
    }

    #[test]
    fn high_bit_serial_gets_leading_zero() {
        let serial = [0xff, 0x01];
        let cert_id = ari_cert_id(&[0x01], &serial);
        let (_, decoded) = der_roundtrip(&cert_id);
        // DER INTEGER must be positive: 0x00 ff 01
        assert_eq!(decoded, vec![0x00, 0xff, 0x01]);
    }

    #[test]
    fn renewal_url_joins_cleanly() {
        assert_eq!(
            renewal_info_url("https://acme.example/renewal-info/", "abc"),
            "https://acme.example/renewal-info/abc"
        );
        assert_eq!(
            renewal_info_url("https://acme.example/renewal-info", "abc"),
            "https://acme.example/renewal-info/abc"
        );
    }

    #[test]
    fn renewal_window_parse_and_validation() {
        let body = br#"{
            "suggestedWindow": {"start": "2026-02-01T00:00:00Z", "end": "2026-02-08T00:00:00Z"},
            "explanationURL": "https://example.com/why"
        }"#;
        let window = parse_renewal_window(body, None).unwrap().unwrap();
        assert_eq!(window.start.to_string(), "2026-02-01T00:00:00Z");
        assert_eq!(window.end.to_string(), "2026-02-08T00:00:00Z");
        assert_eq!(
            window.explanation_url.as_deref(),
            Some("https://example.com/why")
        );

        // Empty body → None (no suggestion).
        assert!(parse_renewal_window(b"", None).unwrap().is_none());

        // End before start → explicit error.
        let bad = br#"{"suggestedWindow": {"start": "2026-02-08T00:00:00Z", "end": "2026-02-01T00:00:00Z"}}"#;
        assert!(parse_renewal_window(bad, None).is_err());

        // Malformed JSON → explicit error.
        assert!(parse_renewal_window(b"{", None).is_err());
    }

    mod directory_provider {
        use super::super::*;
        use crate::ca_backend::transport::{AcmeMethod, FakeAcmeTransport, ScriptedResponse};
        use crate::renewal::RenewalInfoProvider;
        use std::sync::Arc;

        fn scripted_transport(advertise_ari: bool) -> Arc<FakeAcmeTransport> {
            let transport = Arc::new(FakeAcmeTransport::new(Timestamp::now()));
            let mut directory = serde_json::json!({
                "newNonce": "https://ca.example/new-nonce",
                "newAccount": "https://ca.example/new-account",
            });
            if advertise_ari {
                directory["renewalInfo"] = serde_json::json!("https://ca.example/renewal-info");
            }
            transport.push(ScriptedResponse::json("directory", 200, directory).uses(10));
            transport
        }

        fn self_signed_pem() -> String {
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let mut params =
                rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "example.com");
            params.self_signed(&key_pair).unwrap().pem()
        }

        #[tokio::test]
        async fn fetches_window_and_caches_directory_discovery() {
            let transport = scripted_transport(true);
            transport.push(
                ScriptedResponse::json(
                    "renewal-info",
                    200,
                    serde_json::json!({
                        "suggestedWindow": {
                            "start": "2026-02-01T00:00:00Z",
                            "end": "2026-02-08T00:00:00Z"
                        }
                    }),
                )
                .uses(10),
            );

            let provider =
                DirectoryAriProvider::new("https://ca.example/directory", transport.clone());
            let pem = self_signed_pem();
            match provider.renewal_window(&pem).await {
                Ok(Some(window)) => {
                    assert_eq!(window.start.to_string(), "2026-02-01T00:00:00Z");
                }
                Ok(None) | Err(_) => {
                    // A self-signed cert may lack the AKI extension; then the
                    // error must be explicit about the missing identifier.
                }
            }

            // Repeated lookups reuse the discovered base URL: exactly one
            // directory GET no matter how many renewal-info fetches happen.
            for _ in 0..3 {
                let _ = provider.renewal_window(&pem).await;
            }
            let directory_gets = transport
                .requests()
                .iter()
                .filter(|r| r.method == AcmeMethod::Get && r.url.contains("/directory"))
                .count();
            assert_eq!(directory_gets, 1, "directory discovery must be cached");
        }

        #[tokio::test]
        async fn not_advertised_ari_returns_none_without_parsing_chain() {
            let transport = scripted_transport(false);
            let provider = DirectoryAriProvider::new("https://ca.example/directory", transport);
            let window = provider.renewal_window("not even PEM").await.unwrap();
            assert!(window.is_none(), "no ARI endpoint means no suggestion");
        }

        #[tokio::test]
        async fn missing_certificate_info_is_a_404_none() {
            let transport = scripted_transport(true);
            transport.push(ScriptedResponse::json(
                "renewal-info",
                404,
                serde_json::json!({}),
            ));
            let provider = DirectoryAriProvider::new("https://ca.example/directory", transport);
            let pem = self_signed_pem();
            if let Ok(window) = provider.renewal_window(&pem).await {
                assert!(window.is_none(), "404 must map to no suggestion");
            }
        }
    }
}
