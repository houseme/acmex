/// JSON Web Key (JWK) implementation for ACME
use crate::error::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// JSON Web Key representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC", "OKP")
    pub kty: String,

    /// Use (typically "sig" for signing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    /// Key operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    /// Additional parameters (flattened into the JWK)
    #[serde(flatten)]
    pub params: HashMap<String, Value>,
}

impl Jwk {
    /// Create a new JWK with Ed25519 public key
    pub fn new_ed25519(x: impl Into<String>) -> Self {
        let mut params = HashMap::new();
        params.insert("crv".to_string(), Value::String("Ed25519".to_string()));
        params.insert("x".to_string(), Value::String(x.into()));

        Self {
            kty: "OKP".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            params,
        }
    }

    /// Create a new JWK with RSA public key
    pub fn new_rsa(n: impl Into<String>, e: impl Into<String>) -> Self {
        let mut params = HashMap::new();
        params.insert("n".to_string(), Value::String(n.into()));
        params.insert("e".to_string(), Value::String(e.into()));

        Self {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            params,
        }
    }

    /// Create a new JWK with EC public key
    pub fn new_ec(crv: impl Into<String>, x: impl Into<String>, y: impl Into<String>) -> Self {
        let mut params = HashMap::new();
        params.insert("crv".to_string(), Value::String(crv.into()));
        params.insert("x".to_string(), Value::String(x.into()));
        params.insert("y".to_string(), Value::String(y.into()));

        Self {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            params,
        }
    }

    /// Builds the public JWK of an arbitrary supported account key
    /// (Ed25519, ECDSA P-256/P-384/P-521 or RSA), deriving every parameter
    /// from the key itself. This is the single JWK derivation point for all
    /// signing paths — callers must not hardcode a key type.
    ///
    /// * Ed25519: `kty=OKP, crv=Ed25519, x=<raw 32-byte public key>`
    /// * ECDSA: `kty=EC, crv=P-256|P-384|P-521, x/y=<coordinates>` split
    ///   from the SEC1 uncompressed point exported by the key
    /// * RSA: `kty=RSA, n=<modulus>, e=<exponent>` parsed from the DER
    ///   `RSAPublicKey` the key exports (RFC 7518 §6.3 minimal octets)
    pub fn for_key_pair(key: &rcgen::KeyPair) -> Result<Self> {
        use base64::Engine;

        let key_type = crate::crypto::keypair::KeyType::for_key_pair(key)?;
        let public_key = key.public_key_raw();
        if let Some(crv) = key_type.json_web_key_curve() {
            // SEC1 uncompressed point: `04 || X || Y`, coordinates of equal,
            // curve-fixed length (RFC 7518 §6.2.1).
            if public_key.is_empty() || public_key[0] != 0x04 {
                return Err(crate::error::AcmeError::crypto(
                    "EC public key is not an uncompressed SEC1 point",
                ));
            }
            let coordinate_octets = key_type
                .ecdsa_coordinate_octets()
                .ok_or_else(|| crate::error::AcmeError::crypto("unsupported EC curve"))?;
            if public_key.len() != 1 + 2 * coordinate_octets {
                return Err(crate::error::AcmeError::crypto(format!(
                    "EC public key is {} bytes, expected {} for {crv}",
                    public_key.len(),
                    1 + 2 * coordinate_octets
                )));
            }
            let (x, y) = public_key[1..].split_at(coordinate_octets);
            return Ok(Self::new_ec(
                crv,
                URL_SAFE_NO_PAD.encode(x),
                URL_SAFE_NO_PAD.encode(y),
            ));
        }
        match key_type {
            crate::crypto::keypair::KeyType::Ed25519 => {
                Ok(Self::new_ed25519(URL_SAFE_NO_PAD.encode(public_key)))
            }
            crate::crypto::keypair::KeyType::Rsa2048 | crate::crypto::keypair::KeyType::Rsa4096 => {
                let (n, e) = crate::crypto::keypair::der::parse_rsa_public_key(public_key)?;
                Ok(Self::new_rsa(
                    URL_SAFE_NO_PAD.encode(n),
                    URL_SAFE_NO_PAD.encode(e),
                ))
            }
            _ => Err(crate::error::AcmeError::crypto(
                "unsupported account key: cannot build a JWK for this key type",
            )),
        }
    }

    /// Generate JWK thumbprint according to RFC 7638
    /// Uses SHA-256 hash for the thumbprint
    pub fn thumbprint_sha256(&self) -> Result<String> {
        // Build required members in lexicographic order
        match self.kty.as_str() {
            "RSA" => {
                let e = self
                    .params
                    .get("e")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::AcmeError::invalid_input("Missing RSA 'e' parameter")
                    })?;

                let n = self
                    .params
                    .get("n")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::AcmeError::invalid_input("Missing RSA 'n' parameter")
                    })?;

                let required = json!({
                    "e": e,
                    "kty": "RSA",
                    "n": n,
                });

                self.compute_thumbprint(&required)
            }
            "EC" => {
                let crv = self
                    .params
                    .get("crv")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::AcmeError::invalid_input("Missing EC 'crv' parameter")
                    })?;

                let x = self
                    .params
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::AcmeError::invalid_input("Missing EC 'x' parameter")
                    })?;

                let y = self
                    .params
                    .get("y")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::AcmeError::invalid_input("Missing EC 'y' parameter")
                    })?;

                let required = json!({
                    "crv": crv,
                    "kty": "EC",
                    "x": x,
                    "y": y,
                });

                self.compute_thumbprint(&required)
            }
            "OKP" => {
                let crv = self
                    .params
                    .get("crv")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::AcmeError::invalid_input("Missing OKP 'crv' parameter")
                    })?;

                let x = self
                    .params
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::AcmeError::invalid_input("Missing OKP 'x' parameter")
                    })?;

                let required = json!({
                    "crv": crv,
                    "kty": "OKP",
                    "x": x,
                });

                self.compute_thumbprint(&required)
            }
            _ => Err(crate::error::AcmeError::invalid_input(format!(
                "Unsupported key type: {}",
                self.kty
            ))),
        }
    }

    /// Compute SHA-256 thumbprint from required members
    fn compute_thumbprint(&self, required: &Value) -> Result<String> {
        let json_str = required.to_string();
        let mut hasher = Sha256::new();
        hasher.update(json_str.as_bytes());
        let digest = hasher.finalize();

        Ok(URL_SAFE_NO_PAD.encode(digest))
    }

    /// Convert to JSON value for embedding in JWS header
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_ed25519() {
        let jwk = Jwk::new_ed25519("AAAA");
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.params.get("crv").unwrap().as_str().unwrap(), "Ed25519");
        assert_eq!(jwk.params.get("x").unwrap().as_str().unwrap(), "AAAA");
    }

    #[test]
    fn test_new_rsa() {
        let jwk = Jwk::new_rsa("AAAA", "AQAB");
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.params.get("n").unwrap().as_str().unwrap(), "AAAA");
        assert_eq!(jwk.params.get("e").unwrap().as_str().unwrap(), "AQAB");
    }

    #[test]
    fn test_new_ec() {
        let jwk = Jwk::new_ec(
            "P-256",
            "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y8lrnvOohSs2gksT69r56Fq3MZ_yCjL8MyCvD94PoWU",
        );
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.params.get("crv").unwrap().as_str().unwrap(), "P-256");
    }

    #[test]
    fn test_thumbprint_ed25519() {
        let jwk = Jwk::new_ed25519("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        let thumbprint = jwk
            .thumbprint_sha256()
            .expect("Failed to compute thumbprint");
        // The thumbprint will vary, just verify it's a valid base64url string
        assert!(!thumbprint.is_empty());
        assert!(
            thumbprint
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn test_thumbprint_rsa() {
        let jwk = Jwk::new_rsa(
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "AQAB",
        );
        let thumbprint = jwk
            .thumbprint_sha256()
            .expect("Failed to compute thumbprint");
        assert!(!thumbprint.is_empty());
    }

    #[test]
    fn test_to_value() {
        let jwk = Jwk::new_ed25519("AAAA");
        let value = jwk.to_value();
        assert!(value.is_object());
        assert_eq!(value.get("kty").unwrap().as_str().unwrap(), "OKP");
    }

    /// RFC 8037 Appendix A.3: the canonical thumbprint of this well-known
    /// Ed25519 key. Guards the compatibility red line: the Ed25519
    /// thumbprint — the key authorization input — must never change.
    #[test]
    fn thumbprint_matches_the_rfc_8037_ed25519_vector() {
        let jwk = Jwk::new_ed25519("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(
            jwk.thumbprint_sha256().unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    /// EC thumbprint, verified against a hand-built RFC 7638 required-member
    /// string (keys in lexicographic order: crv, kty, x, y).
    #[test]
    fn thumbprint_matches_hand_built_ec_required_members() {
        let jwk = Jwk::new_ec(
            "P-256",
            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        );
        let mut hasher = Sha256::new();
        hasher.update(br#"{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#);
        let expected = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(jwk.thumbprint_sha256().unwrap(), expected);
    }

    #[test]
    fn for_key_pair_builds_es256_jwk_from_generated_key() {
        use crate::crypto::keypair::{KeyPairGenerator, KeyType};
        use base64::Engine;

        let key = KeyPairGenerator::new(KeyType::EcdsaP256)
            .generate()
            .unwrap();
        let jwk = Jwk::for_key_pair(&key).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.params.get("crv").unwrap(), "P-256");
        let x = URL_SAFE_NO_PAD
            .decode(jwk.params.get("x").unwrap().as_str().unwrap())
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode(jwk.params.get("y").unwrap().as_str().unwrap())
            .unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        // Round trip: the point reconstructs from the JWK coordinates.
        let point = key.public_key_raw();
        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..33], x.as_slice());
        assert_eq!(&point[33..], y.as_slice());
        assert!(!jwk.thumbprint_sha256().unwrap().is_empty());
    }

    #[test]
    fn for_key_pair_builds_p384_and_p521_jwks() {
        use crate::crypto::keypair::{KeyPairGenerator, KeyType};

        for (key_type, crv, coordinate_octets) in [
            (KeyType::EcdsaP384, "P-384", 48),
            (KeyType::EcdsaP521, "P-521", 66),
        ] {
            let key = KeyPairGenerator::new(key_type).generate().unwrap();
            let jwk = Jwk::for_key_pair(&key).unwrap();
            assert_eq!(jwk.kty, "EC");
            assert_eq!(jwk.params.get("crv").unwrap(), crv);
            let x = URL_SAFE_NO_PAD
                .decode(jwk.params.get("x").unwrap().as_str().unwrap())
                .unwrap();
            assert_eq!(x.len(), coordinate_octets, "{crv} x coordinate");
        }
    }

    #[test]
    fn for_key_pair_builds_rsa_jwk_with_minimal_octets() {
        use crate::crypto::keypair::{KeyPairGenerator, KeyType};
        use base64::Engine;

        let key = KeyPairGenerator::new(KeyType::Rsa2048).generate().unwrap();
        let jwk = Jwk::for_key_pair(&key).unwrap();
        assert_eq!(jwk.kty, "RSA");
        let n = URL_SAFE_NO_PAD
            .decode(jwk.params.get("n").unwrap().as_str().unwrap())
            .unwrap();
        let e = URL_SAFE_NO_PAD
            .decode(jwk.params.get("e").unwrap().as_str().unwrap())
            .unwrap();
        assert_eq!(n.len(), 256, "modulus without the DER sign octet");
        assert_eq!(e, vec![0x01, 0x00, 0x01], "exponent 65537, minimal octets");
        assert!(!jwk.thumbprint_sha256().unwrap().is_empty());
    }

    #[test]
    fn for_key_pair_keeps_ed25519_shape_unchanged() {
        use crate::crypto::keypair::KeyPairGenerator;
        use base64::Engine;

        let key = KeyPairGenerator::ed25519().generate().unwrap();
        let jwk = Jwk::for_key_pair(&key).unwrap();
        let expected = Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(key.public_key_raw()));
        assert_eq!(jwk, expected);
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.params.get("crv").unwrap(), "Ed25519");
    }
}
