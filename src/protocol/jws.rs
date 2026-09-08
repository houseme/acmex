/// JWS (JSON Web Signature) signing for ACME
use crate::crypto::keypair::KeyType;
use crate::error::{AcmeError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rcgen::{KeyPair, SigningKey};
use serde_json::{Value, json};

/// JWS Signer for signing ACME requests
pub struct JwsSigner<'a> {
    key_pair: &'a KeyPair,
}

impl<'a> JwsSigner<'a> {
    /// Create a new JWS signer with a KeyPair reference
    pub fn new(key_pair: &'a KeyPair) -> Self {
        Self { key_pair }
    }

    /// The JWA algorithm this signer's key requires (`EdDSA`, `ES256`,
    /// `ES384`, `ES512` or `RS256`). Every JWS protected header must take
    /// its `alg` from here instead of hardcoding one.
    pub fn jwa_algorithm(&self) -> Result<&'static str> {
        Ok(KeyType::for_key_pair(self.key_pair)?.jwa_algorithm())
    }

    /// Sign a JWS with the given header and payload
    pub fn sign(&self, header: &Value, payload: &Value) -> Result<String> {
        let header_json = header.to_string();
        let payload_json = if payload.is_null() {
            String::new()
        } else {
            payload.to_string()
        };

        let header_encoded = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_encoded = if payload.is_null() {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(payload_json.as_bytes())
        };

        let signing_input = format!("{}.{}", header_encoded, payload_encoded);

        // Sign using rcgen's KeyPair (requires SigningKey trait)
        let signature = self
            .key_pair
            .sign(signing_input.as_bytes())
            .map_err(|e| AcmeError::crypto(format!("JWS signing failed: {}", e)))?;

        // JWS requires the raw `R||S` encoding for ECDSA (RFC 7518 §3.4),
        // while the signing backend emits ASN.1 DER `Ecdsa-Sig-Value`.
        // Ed25519 and RSA (PKCS#1 v1.5) signatures are already raw.
        let signature = match KeyType::from_key_pair(self.key_pair) {
            Some(key_type) => match key_type.ecdsa_coordinate_octets() {
                Some(coordinate_octets) => crate::crypto::keypair::der::ecdsa_signature_der_to_raw(
                    &signature,
                    coordinate_octets,
                )?,
                None => signature,
            },
            // Unclassifiable key: keep the backend signature verbatim (the
            // header `alg` derived in `jwa_algorithm` rejects it explicitly).
            None => signature,
        };

        let signature_encoded = URL_SAFE_NO_PAD.encode(&signature);

        // ACME (RFC 8555 §6.2) requires the flattened JSON serialization:
        // the POST body is a JSON object, not the compact `a.b.c` form. The
        // compact serialization is only an intermediate for signing.
        Ok(json!({
            "protected": header_encoded,
            "payload": payload_encoded,
            "signature": signature_encoded,
        })
        .to_string())
    }

    /// Sign empty payload (for some ACME operations)
    pub fn sign_empty(&self, header: &Value) -> Result<String> {
        self.sign(header, &Value::Null)
    }

    /// Get reference to the key pair
    pub fn key_pair(&self) -> &KeyPair {
        self.key_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair::{KeyPairGenerator, KeyType};
    use crate::protocol::Jwk;

    /// Parses the flattened JSON envelope into its base64url segments.
    fn jws_segments(jws: &str) -> (String, String, String) {
        let object: serde_json::Value = serde_json::from_str(jws).expect("flattened JSON JWS");
        (
            object["protected"].as_str().unwrap().to_string(),
            object["payload"].as_str().unwrap().to_string(),
            object["signature"].as_str().unwrap().to_string(),
        )
    }

    fn decode_signature(jws: &str) -> Vec<u8> {
        let (_, _, signature) = jws_segments(jws);
        URL_SAFE_NO_PAD
            .decode(signature)
            .expect("signature is base64url")
    }

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

        // RFC 8555 §6.2: the POST body is the flattened JSON serialization.
        let (protected, payload_encoded, _) = jws_segments(&jws);
        let decoded_header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        assert_eq!(decoded_header["nonce"], "test-nonce");
        let decoded_payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_encoded).unwrap()).unwrap();
        assert_eq!(decoded_payload["termsOfServiceAgreed"], true);
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
        let (_, payload_encoded, _) = jws_segments(&jws);
        assert_eq!(payload_encoded, "", "POST-as-GET payload is empty");
    }

    #[test]
    fn jwa_algorithm_is_derived_from_the_key() {
        let cases = [
            (KeyType::Ed25519, "EdDSA"),
            (KeyType::EcdsaP256, "ES256"),
            (KeyType::EcdsaP384, "ES384"),
            (KeyType::EcdsaP521, "ES512"),
            (KeyType::Rsa2048, "RS256"),
            (KeyType::Rsa4096, "RS256"),
        ];
        for (key_type, expected) in cases {
            let key = KeyPairGenerator::new(key_type).generate().unwrap();
            assert_eq!(
                JwsSigner::new(&key).jwa_algorithm().unwrap(),
                expected,
                "for {key_type}"
            );
        }
    }

    /// Full ES256 flow: generate → JWK → thumbprint → JWS sign. The JWS
    /// signature must be the raw fixed-width `R||S` encoding (64 octets for
    /// P-256), not the DER encoding the signing backend emits.
    #[test]
    fn es256_full_flow_signs_raw_and_builds_the_jwk() {
        let key = KeyPairGenerator::new(KeyType::EcdsaP256)
            .generate()
            .expect("P-256 key");
        let signer = JwsSigner::new(&key);

        let jwk = Jwk::for_key_pair(&key).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.params.get("crv").unwrap(), "P-256");
        let thumbprint = jwk.thumbprint_sha256().unwrap();

        let alg = signer.jwa_algorithm().unwrap();
        assert_eq!(alg, "ES256");

        let header = serde_json::json!({
            "alg": alg,
            "jwk": jwk.to_value(),
            "nonce": "test-nonce",
            "url": "https://example.com/acme/new-account",
        });
        let payload = serde_json::json!({ "termsOfServiceAgreed": true });
        let jws = signer.sign(&header, &payload).unwrap();

        let signature = decode_signature(&jws);
        assert_eq!(signature.len(), 64, "raw ES256 R||S is 64 octets");

        // The full-crypto proof lives in
        // `es256_raw_signature_verifies_with_fixed_width_verifier`
        // (feature-gated); here, additionally assert the JWK thumbprint is
        // stable across repeated derivation.
        let jwk_again = Jwk::for_key_pair(&key).unwrap();
        assert_eq!(jwk_again.thumbprint_sha256().unwrap(), thumbprint);
    }

    #[test]
    fn es384_and_es512_sign_at_their_coordinate_widths() {
        for (key_type, alg, signature_len) in [
            (KeyType::EcdsaP384, "ES384", 96),
            (KeyType::EcdsaP521, "ES512", 132),
        ] {
            let key = KeyPairGenerator::new(key_type).generate().unwrap();
            let signer = JwsSigner::new(&key);
            assert_eq!(signer.jwa_algorithm().unwrap(), alg);
            let header = serde_json::json!({ "alg": alg, "nonce": "n", "url": "u" });
            let jws = signer.sign(&header, &serde_json::json!({})).unwrap();
            assert_eq!(
                decode_signature(&jws).len(),
                signature_len,
                "raw {alg} R||S is {signature_len} octets"
            );
        }
    }

    /// RS256 (PKCS#1 v1.5) signatures pass through as fixed-width raw; with
    /// the default `aws-lc-rs` backend the signature is really verified
    /// against the JWK `n`/`e` components.
    #[test]
    fn rs256_full_flow_signs_and_verifies_against_the_jwk() {
        let key = KeyPairGenerator::new(KeyType::Rsa2048)
            .generate()
            .expect("RSA key");
        let signer = JwsSigner::new(&key);
        assert_eq!(signer.jwa_algorithm().unwrap(), "RS256");

        let jwk = Jwk::for_key_pair(&key).unwrap();
        assert_eq!(jwk.kty, "RSA");

        let header = serde_json::json!({
            "alg": "RS256",
            "jwk": jwk.to_value(),
            "nonce": "test-nonce",
            "url": "https://example.com/acme/new-account",
        });
        let payload = serde_json::json!({ "termsOfServiceAgreed": true });
        let jws = signer.sign(&header, &payload).unwrap();

        let signature = decode_signature(&jws);
        assert_eq!(signature.len(), 256, "RS256 signature is modulus-sized");

        // Loop back through the JWK: decode n/e (minimal octets) and really
        // verify under the default aws-lc-rs backend.
        let n = URL_SAFE_NO_PAD
            .decode(jwk.params.get("n").unwrap().as_str().unwrap())
            .unwrap();
        let e = URL_SAFE_NO_PAD
            .decode(jwk.params.get("e").unwrap().as_str().unwrap())
            .unwrap();
        assert_eq!(n.len(), 256);
        assert_eq!(e, vec![0x01, 0x00, 0x01]);

        let (protected, payload_encoded, _) = jws_segments(&jws);
        // Only consumed by the aws-lc-rs verification below; the variable
        // (not the value) is unused under other backends.
        #[cfg_attr(not(feature = "aws-lc-rs"), allow(unused_variables))]
        let signing_input = format!("{protected}.{payload_encoded}");

        #[cfg(feature = "aws-lc-rs")]
        {
            use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
            let public_key = RsaPublicKeyComponents { n: &n, e: &e };
            public_key
                .verify(
                    &RSA_PKCS1_2048_8192_SHA256,
                    signing_input.as_bytes(),
                    &signature,
                )
                .expect("RS256 signature verifies against the JWK components");
        }
    }

    /// The real ES256 proof: the raw signature verifies with the
    /// fixed-width (PKCS#11-style) P-256 verifier, which accepts only
    /// `R||S`, never DER.
    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn es256_raw_signature_verifies_with_fixed_width_verifier() {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

        let key = KeyPairGenerator::new(KeyType::EcdsaP256)
            .generate()
            .unwrap();
        let signer = JwsSigner::new(&key);
        let header = serde_json::json!({ "alg": "ES256", "nonce": "n", "url": "u" });
        let payload = serde_json::json!({ "termsOfServiceAgreed": true });
        let jws = signer.sign(&header, &payload).unwrap();

        let (protected, payload_encoded, _) = jws_segments(&jws);
        let signing_input = format!("{protected}.{payload_encoded}");
        let signature = decode_signature(&jws);
        assert_eq!(signature.len(), 64);

        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key_raw());
        public_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("raw ES256 signature verifies");
    }

    #[test]
    fn ed25519_signing_is_unchanged() {
        let key = KeyPairGenerator::ed25519().generate().unwrap();
        let signer = JwsSigner::new(&key);
        assert_eq!(signer.jwa_algorithm().unwrap(), "EdDSA");

        let header = serde_json::json!({ "alg": "EdDSA", "nonce": "n", "url": "u" });
        let jws = signer.sign(&header, &serde_json::json!({})).unwrap();
        let signature = decode_signature(&jws);
        assert_eq!(signature.len(), 64);

        // Deterministic: re-signing reproduces the exact same JWS.
        let (protected, payload_encoded, _) = jws_segments(&jws);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_encoded).unwrap()).unwrap();
        assert_eq!(signer.sign(&header, &payload).unwrap(), jws);
    }
}
