//! 签名器 - 提供统一的签名接口

use crate::error::{AcmeError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 数字签名
#[derive(Debug, Clone)]
pub struct Signature {
    /// 签名数据
    pub data: Vec<u8>,
    /// 签名算法
    pub algorithm: String,
}

impl Signature {
    /// 创建新签名
    pub fn new(data: Vec<u8>, algorithm: String) -> Self {
        Self { data, algorithm }
    }

    /// 获取 Base64 编码的签名
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.data)
    }
}

/// 签名器特征 - 提供统一的签名接口
pub trait Signer: Send + Sync {
    /// 签名数据
    fn sign(&self, data: &[u8]) -> Result<Signature>;

    /// 获取签名算法名称
    fn algorithm(&self) -> &str;

    /// 验证签名 (可选实现)
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool> {
        Ok(false) // 默认不支持
    }
}

/// HMAC 签名器
pub struct HmacSigner {
    key: Vec<u8>,
    algorithm: String,
}

impl HmacSigner {
    /// 创建 HMAC 签名器
    pub fn new(key: Vec<u8>, algorithm: String) -> Self {
        Self { key, algorithm }
    }

    /// 使用 SHA256 创建 HMAC 签名器 (HS256)
    pub fn hs256(key: Vec<u8>) -> Self {
        Self::new(key, "HS256".to_string())
    }
}

impl Signer for HmacSigner {
    fn sign(&self, data: &[u8]) -> Result<Signature> {
        match self.algorithm.as_str() {
            "HS256" | "HMAC-SHA256" => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
                    .map_err(|e| AcmeError::crypto(format!("HMAC key error: {}", e)))?;
                mac.update(data);
                let result = mac.finalize().into_bytes().to_vec();
                Ok(Signature::new(result, self.algorithm.clone()))
            }
            _ => Err(AcmeError::crypto(format!(
                "Unsupported HMAC algorithm: {}",
                self.algorithm
            ))),
        }
    }

    fn algorithm(&self) -> &str {
        &self.algorithm
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        match self.algorithm.as_str() {
            "HS256" | "HMAC-SHA256" => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
                    .map_err(|e| AcmeError::crypto(format!("HMAC key error: {}", e)))?;
                mac.update(data);
                Ok(mac.verify_slice(signature).is_ok())
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_base64() {
        let sig = Signature::new(vec![1, 2, 3, 4], "test".to_string());
        let base64 = sig.to_base64();
        assert!(!base64.is_empty());
    }

    #[test]
    fn test_hmac_signer() {
        let key = b"secret-key".to_vec();
        let signer = HmacSigner::hs256(key);
        let data = b"hello world";

        let sig = signer.sign(data).unwrap();
        assert_eq!(sig.algorithm, "HS256");
        assert_eq!(sig.data.len(), 32);

        let verified = signer.verify(data, &sig.data).unwrap();
        assert!(verified);

        let wrong_data = b"wrong data";
        let verified_wrong = signer.verify(wrong_data, &sig.data).unwrap();
        assert!(!verified_wrong);
    }
}
