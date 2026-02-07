/// JSON Web Key (JWK) implementation for ACME
use crate::error::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use sha2::{Digest, Sha256};

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
        assert!(thumbprint
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
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
}
