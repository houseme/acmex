/// Encoding utilities for Base64, PEM, and Hex formats.
/// This module provides a unified interface for various encoding schemes
/// required by the ACME protocol and certificate management.
use crate::error::{AcmeError, Result};
use base64::Engine;

/// A utility for Base64 encoding and decoding.
pub struct Base64Encoding;

impl Base64Encoding {
    /// Encodes data using URL-safe Base64 without padding (RFC 4648).
    /// This is the standard encoding for ACME JWS payloads and nonces.
    pub fn encode(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    /// Decodes data from URL-safe Base64.
    /// Automatically handles missing padding if necessary.
    pub fn decode(data: &str) -> Result<Vec<u8>> {
        tracing::debug!("Decoding URL-safe Base64 data (length: {})", data.len());
        // Add necessary padding for the base64 crate if it's not already there
        let padded = match data.len() % 4 {
            2 => format!("{}==", data),
            3 => format!("{}=", data),
            _ => data.to_string(),
        };

        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&padded)
            .map_err(|e| {
                tracing::error!("Failed to decode URL-safe Base64: {}", e);
                AcmeError::crypto(format!("Base64 decode error: {}", e))
            })
    }

    /// Encodes data using standard Base64 with padding.
    pub fn encode_standard(data: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        STANDARD.encode(data)
    }

    /// Decodes data from standard Base64 with padding.
    pub fn decode_standard(data: &str) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD;
        STANDARD
            .decode(data)
            .map_err(|e| {
                tracing::error!("Failed to decode standard Base64: {}", e);
                AcmeError::crypto(format!("Base64 decode error: {}", e))
            })
    }
}

/// A utility for PEM (Privacy-Enhanced Mail) encoding and decoding.
pub struct PemEncoding;

impl PemEncoding {
    /// Encodes binary data into a PEM-formatted string with the specified label.
    pub fn encode(data: &[u8], label: &str) -> String {
        tracing::debug!("Encoding data to PEM with label: {}", label);
        let pem = pem::Pem::new(label.to_string(), data.to_vec());
        pem::encode(&pem)
    }

    /// Decodes binary data from a PEM-formatted string.
    /// Returns a tuple containing the label and the raw bytes.
    pub fn decode(pem_data: &str) -> Result<(String, Vec<u8>)> {
        let pem = pem::parse(pem_data)
            .map_err(|e| {
                tracing::error!("Failed to parse PEM data: {}", e);
                AcmeError::crypto(format!("PEM parse error: {}", e))
            })?;

        Ok((pem.tag().to_string(), pem.contents().to_vec()))
    }

    /// Checks if the provided string is a valid PEM-formatted block.
    pub fn is_valid(data: &str) -> bool {
        pem::parse(data).is_ok()
    }

    /// Extracts binary data from a PEM string, optionally verifying the label.
    pub fn extract_data(pem_data: &str, expected_label: Option<&str>) -> Result<Vec<u8>> {
        let (label, data) = Self::decode(pem_data)?;

        if let Some(expected) = expected_label {
            if label != expected {
                tracing::error!("PEM label mismatch: expected '{}', found '{}'", expected, label);
                return Err(AcmeError::crypto(format!(
                    "Expected PEM label '{}', got '{}'",
                    expected, label
                )));
            }
        }

        Ok(data)
    }
}

/// A utility for Hexadecimal encoding and decoding.
pub struct HexEncoding;

impl HexEncoding {
    /// Encodes binary data into a lowercase hexadecimal string.
    pub fn encode(data: &[u8]) -> String {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        let mut result = String::with_capacity(data.len() * 2);
        for &byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
        }
        result
    }

    /// Decodes binary data from a hexadecimal string.
    pub fn decode(hex_str: &str) -> Result<Vec<u8>> {
        if hex_str.len() % 2 != 0 {
            tracing::error!("Hex string has invalid length (must be even): {}", hex_str.len());
            return Err(AcmeError::crypto(
                "Hex string length must be even".to_string(),
            ));
        }

        let mut result = Vec::with_capacity(hex_str.len() / 2);
        for chunk in hex_str.as_bytes().chunks(2) {
            let hex = std::str::from_utf8(chunk)
                .map_err(|e| {
                    tracing::error!("Invalid UTF-8 in hex chunk: {}", e);
                    AcmeError::crypto(format!("Invalid UTF-8: {}", e))
                })?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|e| {
                    tracing::error!("Failed to parse hex byte '{}': {}", hex, e);
                    AcmeError::crypto(format!("Hex decode error: {}", e))
                })?;
            result.push(byte);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_decode() {
        let data = b"hello world";
        let encoded = Base64Encoding::encode(data);
        let decoded = Base64Encoding::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_url_safe() {
        let data = b"\xfb\xff\xfe";
        let encoded = Base64Encoding::encode(data);
        // URL-safe should use - and _ instead of + and /
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_pem_encode_decode() {
        let data = b"test data";
        let pem = PemEncoding::encode(data, "TEST");

        assert!(pem.contains("-----BEGIN TEST-----"));
        assert!(pem.contains("-----END TEST-----"));

        let (label, decoded) = PemEncoding::decode(&pem).unwrap();
        assert_eq!(label, "TEST");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = b"test";
        let hex = HexEncoding::encode(data);
        let decoded = HexEncoding::decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }
}
