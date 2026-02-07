//! 哈希工具 - 支持多种哈希算法

use crate::error::Result;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// 哈希算法枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA256 (推荐用于 DNS-01)
    Sha256,
    /// SHA384
    Sha384,
    /// SHA512
    Sha512,
}

impl HashAlgorithm {
    /// 计算哈希值
    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    /// 获取哈希值的十六进制字符串
    pub fn hash_hex(&self, data: &[u8]) -> Result<String> {
        let hash = self.hash(data)?;
        Ok(crate::crypto::encoding::HexEncoding::encode(&hash))
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "SHA256"),
            HashAlgorithm::Sha384 => write!(f, "SHA384"),
            HashAlgorithm::Sha512 => write!(f, "SHA512"),
        }
    }
}

/// SHA256 哈希函数
pub struct Sha256Hash;

impl Sha256Hash {
    /// 计算 SHA256 哈希
    pub fn hash(data: &[u8]) -> Result<Vec<u8>> {
        HashAlgorithm::Sha256.hash(data)
    }

    /// 计算 SHA256 哈希并返回十六进制字符串
    pub fn hash_hex(data: &[u8]) -> Result<String> {
        let hash = Self::hash(data)?;
        Ok(crate::crypto::encoding::HexEncoding::encode(&hash))
    }

    /// 计算 SHA256 哈希并返回 Base64 编码
    pub fn hash_base64(data: &[u8]) -> Result<String> {
        use base64::Engine;
        let hash = Self::hash(data)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = Sha256Hash::hash(data).unwrap();

        // 已知的 SHA256("test data") 值
        assert_eq!(
            hex::encode(&hash),
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_sha256_hash_hex() {
        let data = b"hello";
        let hex = Sha256Hash::hash_hex(data).unwrap();
        assert!(!hex.is_empty());
        assert_eq!(hex.len(), 64); // SHA256 produces 64 hex characters
    }

    #[test]
    fn test_sha256_hash_base64() {
        let data = b"test";
        let base64 = Sha256Hash::hash_base64(data).unwrap();
        assert!(!base64.is_empty());
    }
}
