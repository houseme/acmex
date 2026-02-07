//! 密钥对管理 - 支持 EdDSA (Ed25519) 和 ECDSA (P-256) 密钥

use crate::error::AcmeError;
use crate::error::Result;

/// 密钥类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// EdDSA Ed25519 (推荐)
    Ed25519,
    /// ECDSA P-256
    EcdsaP256,
    /// ECDSA P-384
    EcdsaP384,
    /// ECDSA P-521
    EcdsaP521,
    /// RSA 2048
    Rsa2048,
    /// RSA 4096
    Rsa4096,
}

impl KeyType {
    /// 获取密钥类型的 JWA 算法标识
    pub fn jwa_algorithm(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "EdDSA",
            KeyType::EcdsaP256 => "ES256",
            KeyType::EcdsaP384 => "ES384",
            KeyType::EcdsaP521 => "ES512",
            KeyType::Rsa2048 | KeyType::Rsa4096 => "RS256",
        }
    }

    /// 获取密钥类型的 OpenSSL 曲线名称
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

/// JWK 公钥表示
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwkPublicKey {
    /// 密钥类型 ("RSA", "EC", "OKP")
    pub kty: String,
    /// 算法 ("RS256", "ES256", "EdDSA" 等)
    pub alg: String,
    /// 使用 ("sig" 用于签名)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    /// RSA 模数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA 公共指数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// ECDSA/EdDSA 曲线
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// ECDSA/EdDSA X 坐标
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// ECDSA Y 坐标
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// 密钥对生成器
pub struct KeyPairGenerator {
    key_type: KeyType,
}

impl KeyPairGenerator {
    /// 创建新的密钥对生成器
    pub fn new(key_type: KeyType) -> Self {
        Self { key_type }
    }

    /// 使用 Ed25519 (推荐)
    pub fn ed25519() -> Self {
        Self::new(KeyType::Ed25519)
    }

    /// 使用 ECDSA P-256
    pub fn ecdsa_p256() -> Self {
        Self::new(KeyType::EcdsaP256)
    }

    /// 使用 ECDSA P-384
    pub fn ecdsa_p384() -> Self {
        Self::new(KeyType::EcdsaP384)
    }

    /// 生成密钥对 (返回 rcgen::KeyPair)
    pub fn generate(&self) -> Result<rcgen::KeyPair> {
        match self.key_type {
            KeyType::Ed25519 => rcgen::KeyPair::generate()
                .map_err(|e| AcmeError::crypto(format!("Failed to generate Ed25519 key: {}", e))),
            _ => Err(AcmeError::crypto(format!(
                "Key type {} generation not yet implemented",
                self.key_type
            ))),
        }
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
}
