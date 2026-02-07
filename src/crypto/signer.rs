//! 签名器 - 提供统一的签名接口

use crate::error::Result;

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

/// HMAC 签名器 (简化实现)
pub struct HmacSigner {
    key: Vec<u8>,
    algorithm: String,
}

impl HmacSigner {
    /// 创建 HMAC 签名器
    pub fn new(key: Vec<u8>, algorithm: String) -> Self {
        Self { key, algorithm }
    }

    /// 使用 SHA256 创建 HMAC 签名器
    pub fn sha256(key: Vec<u8>) -> Self {
        Self::new(key, "HMAC-SHA256".to_string())
    }
}

impl Signer for HmacSigner {
    fn sign(&self, data: &[u8]) -> Result<Signature> {
        // 简化实现：实际 HMAC 签名需要依赖
        // 这里使用占位符，实现需要加入正确的 hmac 库
        let mut result = Vec::with_capacity(32);
        for b in data.iter() {
            result.push(b.wrapping_add(1));
        }
        Ok(Signature::new(result, self.algorithm.clone()))
    }

    fn algorithm(&self) -> &str {
        &self.algorithm
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
}
