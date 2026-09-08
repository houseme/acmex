/// Key pair management supporting EdDSA (Ed25519), ECDSA (P-256/P-384/P-521)
/// and RSA (2048/4096) keys.
/// This module provides utilities for generating and managing cryptographic keys
/// used for ACME account identification and certificate signing requests, and
/// the type derivation every JWS/JWK path builds its algorithm choice on.
use crate::error::AcmeError;
use crate::error::Result;
use rcgen::{
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_ED25519,
    PKCS_RSA_SHA256, RsaKeySize,
};

/// Enumeration of supported key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// EdDSA Ed25519 (Recommended for performance and security).
    Ed25519,
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// ECDSA P-521.
    EcdsaP521,
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 4096-bit.
    Rsa4096,
}

impl KeyType {
    /// Returns the JSON Web Algorithm (JWA) identifier for the key type.
    pub fn jwa_algorithm(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "EdDSA",
            KeyType::EcdsaP256 => "ES256",
            KeyType::EcdsaP384 => "ES384",
            KeyType::EcdsaP521 => "ES512",
            KeyType::Rsa2048 | KeyType::Rsa4096 => "RS256",
        }
    }

    /// Infers the key type of an existing key pair from its rcgen signature
    /// algorithm and public key. This is the single derivation point for the
    /// JWS `alg` header, the JWK shape and the ECDSA signature conversion —
    /// no signing path may hardcode an algorithm any more.
    ///
    /// RSA strengths are distinguished by the exported modulus length; RSA
    /// keys of an unclassified size return `None` so callers fail explicitly
    /// instead of labeling the key with a wrong algorithm.
    pub fn from_key_pair(key: &rcgen::KeyPair) -> Option<Self> {
        let algorithm = key.algorithm();
        if *algorithm == PKCS_ED25519 {
            return Some(Self::Ed25519);
        }
        if *algorithm == PKCS_ECDSA_P256_SHA256 {
            return Some(Self::EcdsaP256);
        }
        if *algorithm == PKCS_ECDSA_P384_SHA384 {
            return Some(Self::EcdsaP384);
        }
        if *algorithm == PKCS_ECDSA_P521_SHA512 {
            return Some(Self::EcdsaP521);
        }
        if *algorithm == PKCS_RSA_SHA256 {
            let modulus_octets = der::rsa_public_key_modulus_octets(key.public_key_raw())?;
            return match modulus_octets {
                256 => Some(Self::Rsa2048),
                512 => Some(Self::Rsa4096),
                _ => None,
            };
        }
        None
    }

    /// Convenient classification used by the JWS/JWK paths: derives the type
    /// or reports an explicit error naming the unclassifiable key.
    pub fn for_key_pair(key: &rcgen::KeyPair) -> Result<Self> {
        Self::from_key_pair(key)
            .ok_or_else(|| unsupported_account_key_message(key.algorithm(), key.public_key_raw()))
    }

    /// The fixed octet length of one ECDSA coordinate (R or S) for the JWS
    /// raw `R||S` signature encoding; `None` for non-ECDSA types.
    pub fn ecdsa_coordinate_octets(&self) -> Option<usize> {
        match self {
            KeyType::EcdsaP256 => Some(32),
            KeyType::EcdsaP384 => Some(48),
            // P-521 is 521 bits: coordinates occupy 66 octets, the top octet
            // using only its 7 low bits.
            KeyType::EcdsaP521 => Some(66),
            _ => None,
        }
    }

    /// The JWK `crv` parameter for EC types (RFC 7518 §6.2.1.1); `None` for
    /// non-EC types.
    pub fn json_web_key_curve(&self) -> Option<&'static str> {
        match self {
            KeyType::EcdsaP256 => Some("P-256"),
            KeyType::EcdsaP384 => Some("P-384"),
            KeyType::EcdsaP521 => Some("P-521"),
            _ => None,
        }
    }

    /// Parses the `[ca] account_key_type` configuration value. Accepts
    /// exactly the documented identifiers, case-insensitively.
    pub fn from_config_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ed25519" => Some(Self::Ed25519),
            "ecdsa_p256" => Some(Self::EcdsaP256),
            "ecdsa_p384" => Some(Self::EcdsaP384),
            "ecdsa_p521" => Some(Self::EcdsaP521),
            "rsa2048" => Some(Self::Rsa2048),
            "rsa4096" => Some(Self::Rsa4096),
            _ => None,
        }
    }

    /// Returns the OpenSSL curve name for EC keys, if applicable.
    pub fn openssl_curve(&self) -> Option<&'static str> {
        match self {
            KeyType::EcdsaP256 => Some("prime256v1"),
            KeyType::EcdsaP384 => Some("secp384r1"),
            KeyType::EcdsaP521 => Some("secp521r1"),
            _ => None,
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::EcdsaP256 => write!(f, "ECDSA-P256"),
            KeyType::EcdsaP384 => write!(f, "ECDSA-P384"),
            KeyType::EcdsaP521 => write!(f, "ECDSA-P521"),
            KeyType::Rsa2048 => write!(f, "RSA-2048"),
            KeyType::Rsa4096 => write!(f, "RSA-4096"),
        }
    }
}

/// The explicit error for keys [`KeyType::from_key_pair`] cannot classify.
///
/// RSA keys report their actual modulus length so an unclassified strength
/// (e.g. RSA-3072) is immediately diagnosable instead of surfacing a generic
/// "cannot derive an algorithm" message.
fn unsupported_account_key_message(
    algorithm: &rcgen::SignatureAlgorithm,
    public_key_der: &[u8],
) -> AcmeError {
    if *algorithm == PKCS_RSA_SHA256
        && let Some(bits) = der::rsa_public_key_modulus_octets(public_key_der)
            .map(|octets| octets.saturating_mul(8))
    {
        return AcmeError::crypto(format!(
            "unsupported account key: RSA key with {bits}-bit modulus; expected 2048 or 4096"
        ));
    }
    AcmeError::crypto("unsupported account key: cannot derive a JWS algorithm from this key type")
}

/// A representation of a public key in JSON Web Key (JWK) format.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwkPublicKey {
    /// Key type (e.g., "RSA", "EC", "OKP").
    pub kty: String,
    /// Algorithm identifier (e.g., "RS256", "ES256", "EdDSA").
    pub alg: String,
    /// Intended use of the key (typically "sig" for signing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    /// RSA modulus (n).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (e).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// Curve name for EC/OKP keys (e.g., "P-256", "Ed25519").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X coordinate for EC/OKP keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate for EC keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// A generator for creating new cryptographic key pairs.
pub struct KeyPairGenerator {
    /// The type of key to generate.
    key_type: KeyType,
}

impl KeyPairGenerator {
    /// Creates a new `KeyPairGenerator` for the specified key type.
    pub fn new(key_type: KeyType) -> Self {
        Self { key_type }
    }

    /// Creates a generator for Ed25519 keys (Recommended).
    pub fn ed25519() -> Self {
        Self::new(KeyType::Ed25519)
    }

    /// Creates a generator for ECDSA P-256 keys.
    pub fn ecdsa_p256() -> Self {
        Self::new(KeyType::EcdsaP256)
    }

    /// Creates a generator for ECDSA P-384 keys.
    pub fn ecdsa_p384() -> Self {
        Self::new(KeyType::EcdsaP384)
    }

    /// Generates a new key pair based on the configured key type.
    pub fn generate(&self) -> Result<rcgen::KeyPair> {
        tracing::info!("Generating new {} key pair", self.key_type);
        let generated = match self.key_type {
            KeyType::Ed25519 => rcgen::KeyPair::generate_for(&PKCS_ED25519),
            KeyType::EcdsaP256 => rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
            KeyType::EcdsaP384 => rcgen::KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384),
            KeyType::EcdsaP521 => rcgen::KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512),
            KeyType::Rsa2048 => {
                rcgen::KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
            }
            KeyType::Rsa4096 => {
                rcgen::KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_4096)
            }
        };
        generated.map_err(|e| {
            tracing::error!("Failed to generate {} key: {}", self.key_type, e);
            AcmeError::crypto(format!("Failed to generate {} key: {}", self.key_type, e))
        })
    }
}

/// Minimal DER reader for the two ASN.1 structures the ACME wire format
/// needs from rcgen keys: the RFC 8017 `RSAPublicKey` (JWK `n`/`e`) and the
/// `Ecdsa-Sig-Value` emitted by the aws-lc-rs signing backend (which JWS
/// needs as raw `R||S`). Deliberately small and dependency-free; DER only
/// mandates definite lengths, which is all that is accepted here.
pub(crate) mod der {
    use crate::error::{AcmeError, Result};

    const TAG_INTEGER: u8 = 0x02;
    const TAG_SEQUENCE: u8 = 0x30;

    fn malformed(what: &str) -> AcmeError {
        AcmeError::crypto(format!("malformed DER: {what}"))
    }

    /// Reads one TLV element, returning `(tag, content, remaining)`.
    fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
        let (&tag, rest) = input
            .split_first()
            .ok_or_else(|| malformed("unexpected end of input"))?;
        let (&first, rest) = rest
            .split_first()
            .ok_or_else(|| malformed("missing length octet"))?;
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let octets = usize::from(first & 0x7f);
            if octets == 0 || octets > core::mem::size_of::<usize>() {
                return Err(malformed("unsupported length encoding"));
            }
            if rest.len() < octets {
                return Err(malformed("truncated length"));
            }
            let (len_bytes, rest) = rest.split_at(octets);
            let length = len_bytes
                .iter()
                .fold(0usize, |acc, &byte| (acc << 8) | usize::from(byte));
            (length, rest)
        };
        if rest.len() < length {
            return Err(malformed("content shorter than the declared length"));
        }
        let (content, remaining) = rest.split_at(length);
        Ok((tag, content, remaining))
    }

    /// Reads one TLV and asserts its tag.
    fn expect<'a>(input: &'a [u8], tag: u8, what: &str) -> Result<(&'a [u8], &'a [u8])> {
        let (found, content, rest) = read_tlv(input)?;
        if found != tag {
            return Err(malformed(&format!(
                "expected {what} (tag 0x{tag:02x}), found tag 0x{found:02x}"
            )));
        }
        Ok((content, rest))
    }

    /// The minimal big-endian magnitude of a DER `INTEGER`, as required by
    /// the JOSE unsigned integer encodings (RFC 7518 §6.3.1.1: the minimum
    /// number of octets). DER keeps values positive with a single leading
    /// zero octet; non-minimal longer runs are tolerated and stripped.
    fn unsigned_magnitude(integer: &[u8]) -> Result<&[u8]> {
        if integer.is_empty() {
            return Err(malformed("empty INTEGER"));
        }
        if integer[0] & 0x80 != 0 {
            return Err(malformed(
                "negative INTEGER where an unsigned value is required",
            ));
        }
        let first_significant = integer
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(integer.len() - 1);
        Ok(&integer[first_significant..])
    }

    /// Modulus octet length of an RFC 8017 `RSAPublicKey`, used to classify
    /// RSA key strengths; `None` when the input is not an `RSAPublicKey`.
    pub(crate) fn rsa_public_key_modulus_octets(der: &[u8]) -> Option<usize> {
        parse_rsa_public_key(der).ok().map(|(n, _)| n.len())
    }

    /// Parses `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
    /// publicExponent INTEGER }` into `(n, e)` minimal big-endian octets.
    pub(crate) fn parse_rsa_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (sequence, trailing) = expect(der, TAG_SEQUENCE, "RSAPublicKey SEQUENCE")?;
        if !trailing.is_empty() {
            return Err(malformed("trailing bytes after RSAPublicKey"));
        }
        let (n, rest) = expect(sequence, TAG_INTEGER, "RSA modulus INTEGER")?;
        let (e, rest) = expect(rest, TAG_INTEGER, "RSA exponent INTEGER")?;
        if !rest.is_empty() {
            return Err(malformed("unexpected fields in RSAPublicKey"));
        }
        Ok((
            unsigned_magnitude(n)?.to_vec(),
            unsigned_magnitude(e)?.to_vec(),
        ))
    }

    /// Converts an ASN.1 `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER,
    /// s INTEGER }` into the JWS raw signature encoding (RFC 7518 §3.4):
    /// `R || S`, each value left-padded with zero octets to
    /// `coordinate_octets` (32 for P-256, 48 for P-384 and 66 for P-521).
    pub(crate) fn ecdsa_signature_der_to_raw(
        der: &[u8],
        coordinate_octets: usize,
    ) -> Result<Vec<u8>> {
        let (sequence, trailing) = expect(der, TAG_SEQUENCE, "Ecdsa-Sig-Value SEQUENCE")?;
        if !trailing.is_empty() {
            return Err(malformed("trailing bytes after Ecdsa-Sig-Value"));
        }
        let (r, rest) = expect(sequence, TAG_INTEGER, "ECDSA r INTEGER")?;
        let (s, rest) = expect(rest, TAG_INTEGER, "ECDSA s INTEGER")?;
        if !rest.is_empty() {
            return Err(malformed("unexpected fields in Ecdsa-Sig-Value"));
        }
        let mut raw = Vec::with_capacity(coordinate_octets * 2);
        for (name, integer) in [("r", r), ("s", s)] {
            let magnitude = unsigned_magnitude(integer)?;
            if magnitude.len() > coordinate_octets {
                return Err(AcmeError::crypto(format!(
                    "ECDSA {name} value exceeds the {coordinate_octets}-octet coordinate size"
                )));
            }
            let padding = coordinate_octets - magnitude.len();
            raw.resize(raw.len() + padding, 0);
            raw.extend_from_slice(magnitude);
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_jwa() {
        assert_eq!(KeyType::Ed25519.jwa_algorithm(), "EdDSA");
        assert_eq!(KeyType::EcdsaP256.jwa_algorithm(), "ES256");
        assert_eq!(KeyType::Rsa2048.jwa_algorithm(), "RS256");
    }

    #[test]
    fn test_generate_ed25519() {
        let generator = KeyPairGenerator::ed25519();
        let result = generator.generate();
        assert!(result.is_ok(), "Ed25519 generation should work");
    }

    /// Probe (empirical, backend-observed): documents the exact wire format
    /// of `rcgen::KeyPair::public_key_raw()` per key type. ECDSA keys export
    /// the SEC1 uncompressed point (`04 || X || Y`), Ed25519 the raw 32-byte
    /// key and RSA the DER-encoded RFC 8017 `RSAPublicKey` SEQUENCE.
    #[test]
    fn probe_public_key_raw_format() {
        let ec = KeyPairGenerator::ecdsa_p256().generate().unwrap();
        let ec_raw = ec.public_key_raw();
        assert_eq!(ec_raw.len(), 65, "P-256 uncompressed point is 65 bytes");
        assert_eq!(ec_raw[0], 0x04, "uncompressed point marker");

        let p384 = KeyPairGenerator::ecdsa_p384().generate().unwrap();
        assert_eq!(p384.public_key_raw().len(), 97, "P-384 point is 97 bytes");

        let p521 = KeyPairGenerator::new(KeyType::EcdsaP521)
            .generate()
            .unwrap();
        assert_eq!(p521.public_key_raw().len(), 133, "P-521 point is 133 bytes");

        let ed = KeyPairGenerator::ed25519().generate().unwrap();
        assert_eq!(ed.public_key_raw().len(), 32, "Ed25519 raw key is 32 bytes");

        let rsa = KeyPairGenerator::new(KeyType::Rsa2048).generate().unwrap();
        let rsa_raw = rsa.public_key_raw();
        assert_eq!(
            rsa_raw[0], 0x30,
            "RSA public key is a DER SEQUENCE (RSAPublicKey)"
        );
        assert!(
            rsa_raw.len() > 256,
            "2048-bit modulus does not fit: {}",
            rsa_raw.len()
        );
    }

    /// Probe (empirical): `rcgen::KeyPair::sign` emits ASN.1 DER
    /// `Ecdsa-Sig-Value` for ECDSA keys (aws-lc-rs backend), while Ed25519
    /// and RSA (PKCS#1 v1.5) signatures are already fixed-width raw.
    #[test]
    fn probe_signature_format() {
        use rcgen::SigningKey;

        let ec = KeyPairGenerator::ecdsa_p256().generate().unwrap();
        let sig = ec.sign(b"probe").unwrap();
        assert_eq!(sig[0], 0x30, "ECDSA signature is DER-encoded (SEQUENCE)");

        let ed = KeyPairGenerator::ed25519().generate().unwrap();
        assert_eq!(ed.sign(b"probe").unwrap().len(), 64);

        let rsa = KeyPairGenerator::new(KeyType::Rsa2048).generate().unwrap();
        assert_eq!(
            rsa.sign(b"probe").unwrap().len(),
            256,
            "RS256 PKCS#1 v1.5 signature is modulus-sized"
        );
    }

    #[test]
    fn generate_all_declared_key_types() {
        let cases = [
            (KeyType::Ed25519, &PKCS_ED25519),
            (KeyType::EcdsaP256, &PKCS_ECDSA_P256_SHA256),
            (KeyType::EcdsaP384, &PKCS_ECDSA_P384_SHA384),
            (KeyType::EcdsaP521, &PKCS_ECDSA_P521_SHA512),
            (KeyType::Rsa2048, &PKCS_RSA_SHA256),
            (KeyType::Rsa4096, &PKCS_RSA_SHA256),
        ];

        for (key_type, algorithm) in cases {
            let key = KeyPairGenerator::new(key_type)
                .generate()
                .unwrap_or_else(|err| panic!("{key_type} generation failed: {err}"));
            assert_eq!(key.algorithm(), algorithm);
        }
    }

    #[test]
    fn from_key_pair_recognizes_every_supported_type() {
        let cases = [
            KeyType::Ed25519,
            KeyType::EcdsaP256,
            KeyType::EcdsaP384,
            KeyType::EcdsaP521,
            KeyType::Rsa2048,
            KeyType::Rsa4096,
        ];
        for key_type in cases {
            let key = KeyPairGenerator::new(key_type).generate().unwrap();
            assert_eq!(
                KeyType::from_key_pair(&key),
                Some(key_type),
                "misclassified {key_type}"
            );
        }
    }

    #[test]
    fn config_str_round_trips_every_documented_value() {
        let cases = [
            ("ed25519", KeyType::Ed25519),
            ("ecdsa_p256", KeyType::EcdsaP256),
            ("ecdsa_p384", KeyType::EcdsaP384),
            ("ecdsa_p521", KeyType::EcdsaP521),
            ("rsa2048", KeyType::Rsa2048),
            ("rsa4096", KeyType::Rsa4096),
            ("ECDSA_P256", KeyType::EcdsaP256),
        ];
        for (value, expected) in cases {
            assert_eq!(
                KeyType::from_config_str(value),
                Some(expected),
                "for {value}"
            );
        }
        for unknown in ["p256", "rsa", "ed448", ""] {
            assert_eq!(
                KeyType::from_config_str(unknown),
                None,
                "`{unknown}` must not parse"
            );
        }
    }

    /// Builds a short-form DER `INTEGER` that keeps `value` positive.
    fn der_integer(value: &[u8]) -> Vec<u8> {
        let mut out = vec![0x02];
        if value[0] & 0x80 != 0 {
            out.push((value.len() + 1) as u8);
            out.push(0x00);
        } else {
            out.push(value.len() as u8);
        }
        out.extend_from_slice(value);
        out
    }

    fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
        let content_len: usize = items.iter().map(Vec::len).sum();
        let mut out = vec![0x30];
        if content_len < 128 {
            out.push(content_len as u8);
        } else {
            // Long-form length for the P-521-sized fixtures.
            let len_bytes = content_len.to_be_bytes();
            let first = len_bytes.iter().position(|&b| b != 0).unwrap();
            let significant = &len_bytes[first..];
            out.push(0x80 | significant.len() as u8);
            out.extend_from_slice(significant);
        }
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    #[test]
    fn ecdsa_der_to_raw_pads_minimal_values_to_the_coordinate_size() {
        // r = 1, s = 0x0102 for P-256: both sides padded with leading zeros.
        let der = der_sequence(&[
            der_integer(&[0x01]),       // r
            der_integer(&[0x01, 0x02]), // s
        ]);
        let raw = der::ecdsa_signature_der_to_raw(&der, 32).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(&raw[..31], &[0u8; 31]);
        assert_eq!(raw[31], 0x01, "r = 1 occupies the last octet of R");
        assert_eq!(&raw[32..62], &[0u8; 30]);
        assert_eq!(&raw[62..], &[0x01, 0x02]);
    }

    #[test]
    fn ecdsa_der_to_raw_handles_high_bit_values_for_all_coordinate_sizes() {
        // High-bit r values force DER to prepend a zero octet, which must be
        // stripped and the value re-padded to the exact coordinate size.
        for (coordinate_octets, full, partial) in
            [(32usize, 32usize, 20usize), (48, 48, 40), (66, 66, 65)]
        {
            let r = vec![0xffu8; full];
            let s = vec![0x80u8; partial];
            let der = der_sequence(&[der_integer(&r), der_integer(&s)]);
            let raw = der::ecdsa_signature_der_to_raw(&der, coordinate_octets).unwrap();
            assert_eq!(
                raw.len(),
                coordinate_octets * 2,
                "coordinate {coordinate_octets}"
            );
            assert_eq!(
                &raw[..coordinate_octets],
                r.as_slice(),
                "r must survive verbatim"
            );
            let mut expected_s = vec![0u8; coordinate_octets - partial];
            expected_s.extend_from_slice(&s);
            assert_eq!(&raw[coordinate_octets..], expected_s.as_slice());
        }
    }

    #[test]
    fn ecdsa_der_to_raw_rejects_malformed_input() {
        let build = |r: &[u8], s: &[u8]| der_sequence(&[der_integer(r), der_integer(s)]);

        // A coordinate larger than the target size cannot be raw-encoded.
        let oversized = der_sequence(&[der_integer(&[0x01; 33]), der_integer(&[0x01; 32])]);
        assert!(der::ecdsa_signature_der_to_raw(&oversized, 32).is_err());

        // Negative INTEGERs (top bit set, no leading zero) are rejected:
        // real signers always emit the sign-preserving zero octet.
        let mut negative_r = vec![0x02, 0x20];
        negative_r.extend_from_slice(&[0xffu8; 32]);
        let negative = der_sequence(&[negative_r, der_integer(&[0x01; 32])]);
        assert!(der::ecdsa_signature_der_to_raw(&negative, 32).is_err());

        // Trailing garbage after the signature SEQUENCE.
        let mut trailing = build(&[0x01; 32], &[0x02; 32]);
        trailing.push(0x00);
        assert!(der::ecdsa_signature_der_to_raw(&trailing, 32).is_err());

        // Truncated input.
        assert!(der::ecdsa_signature_der_to_raw(&[0x30, 0x80], 32).is_err());
        assert!(der::ecdsa_signature_der_to_raw(&[], 32).is_err());
    }

    #[test]
    fn rsa_public_key_der_parses_into_minimal_components() {
        let key = KeyPairGenerator::new(KeyType::Rsa2048).generate().unwrap();
        let (n, e) = der::parse_rsa_public_key(key.public_key_raw()).unwrap();
        assert_eq!(n.len(), 256, "2048-bit modulus, leading zero stripped");
        assert_eq!(e, vec![0x01, 0x00, 0x01], "F4 = 65537");
        assert_eq!(
            der::rsa_public_key_modulus_octets(key.public_key_raw()),
            Some(256)
        );

        let key = KeyPairGenerator::new(KeyType::Rsa4096).generate().unwrap();
        let (n, _) = der::parse_rsa_public_key(key.public_key_raw()).unwrap();
        assert_eq!(n.len(), 512);

        assert_eq!(der::rsa_public_key_modulus_octets(b"not der"), None);
    }

    /// An RSA account key of an unclassified strength is rejected with its
    /// actual modulus length, so an RSA-3072 key is diagnosable from the
    /// error alone (rcgen cannot generate odd RSA sizes, so the RSAPublicKey
    /// DER for a 3072-bit modulus is handcrafted here with long-form lengths,
    /// which the `der_integer`/`der_sequence` helpers do not emit).
    #[test]
    fn unsupported_rsa_key_error_names_the_modulus_length() {
        // SEQUENCE { INTEGER (0x00 || 0x8a * 384), INTEGER (65537) }:
        // content = (4 + 385) + 5 = 394 = 0x018a octets.
        let mut rsa_public_key = vec![0x30, 0x82, 0x01, 0x8a];
        rsa_public_key.extend_from_slice(&[0x02, 0x82, 0x01, 0x81, 0x00]);
        rsa_public_key.extend_from_slice(&[0x8au8; 384]);
        rsa_public_key.extend_from_slice(&[0x02, 0x03, 0x01, 0x00, 0x01]);

        let err = unsupported_account_key_message(&PKCS_RSA_SHA256, &rsa_public_key);
        assert!(
            err.to_string().contains(
                "unsupported account key: RSA key with 3072-bit modulus; expected 2048 or 4096"
            ),
            "error must name the modulus length: {err}"
        );

        // Non-RSA keys keep the generic message (no RSA modulus to report).
        let err = unsupported_account_key_message(&PKCS_ED25519, &[0x01, 0x02, 0x03]);
        assert!(
            err.to_string()
                .contains("cannot derive a JWS algorithm from this key type"),
            "non-RSA fallback message: {err}"
        );

        // A malformed RSA public key falls back to the generic message too.
        let err = unsupported_account_key_message(&PKCS_RSA_SHA256, b"not der");
        assert!(
            err.to_string()
                .contains("cannot derive a JWS algorithm from this key type"),
            "malformed RSA fallback message: {err}"
        );
    }
}
