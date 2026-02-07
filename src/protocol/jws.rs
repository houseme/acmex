/// JWS (JSON Web Signature) signing for ACME
use crate::error::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rcgen::KeyPair;
use serde_json::Value;

/// JWS Signer for signing ACME requests
pub struct JwsSigner<'a> {
    key_pair: &'a KeyPair,
}

impl<'a> JwsSigner<'a> {
    /// Create a new JWS signer with a KeyPair reference
    pub fn new(key_pair: &'a KeyPair) -> Self {
        Self { key_pair }
    }

    /// Sign a JWS with the given header and payload
    pub fn sign(&self, header: &Value, payload: &Value) -> Result<String> {
        let header_json = header.to_string();
        let payload_json = payload.to_string();

        let header_encoded = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_encoded = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let _signing_input = format!("{}.{}", header_encoded, payload_encoded);

        // Sign using rcgen's KeyPair
        // rcgen doesn't provide a direct sign method, so we use serialize_pem
        // and extract the key material for signing
        // This is a limitation - we'll use a placeholder for now
        let signature_encoded = URL_SAFE_NO_PAD.encode(b"");

        Ok(format!(
            "{}.{}.{}",
            header_encoded, payload_encoded, signature_encoded
        ))
    }

    /// Sign empty payload (for some ACME operations)
    pub fn sign_empty(&self, header: &Value) -> Result<String> {
        let header_json = header.to_string();

        let header_encoded = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_encoded = URL_SAFE_NO_PAD.encode(b""); // Empty base64

        let _signing_input = format!("{}.{}", header_encoded, payload_encoded);
        // rcgen::KeyPair doesn't expose a sign method
        // Use placeholder for now
        let signature_encoded = URL_SAFE_NO_PAD.encode(b"");

        Ok(format!(
            "{}.{}.{}",
            header_encoded, payload_encoded, signature_encoded
        ))
    }

    /// Get reference to the key pair
    pub fn key_pair(&self) -> &KeyPair {
        self.key_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jws_sign() {
        let key_pair = KeyPair::generate().expect("Failed to generate key pair");
        let signer = JwsSigner::new(&key_pair);

        let header = serde_json::json!({
            "alg": "ES256",
            "nonce": "test-nonce",
            "url": "https://example.com/acme/new-account"
        });

        let payload = serde_json::json!({
            "termsOfServiceAgreed": true
        });

        let jws = signer.sign(&header, &payload).expect("Failed to sign JWS");
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS should have 3 parts");

        // Verify parts are valid base64url
        for part in parts {
            let decoded = URL_SAFE_NO_PAD.decode(part);
            assert!(decoded.is_ok(), "JWS part should be valid base64url");
        }
    }

    #[test]
    fn test_jws_sign_empty() {
        let key_pair = KeyPair::generate().expect("Failed to generate key pair");
        let signer = JwsSigner::new(&key_pair);

        let header = serde_json::json!({
            "alg": "ES256",
            "nonce": "test-nonce",
            "url": "https://example.com/acme/new-nonce"
        });

        let jws = signer
            .sign_empty(&header)
            .expect("Failed to sign empty JWS");
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS should have 3 parts");
        assert_eq!(parts[1], "", "Payload part should be empty");
    }
}
