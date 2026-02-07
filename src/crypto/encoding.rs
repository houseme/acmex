//! 编码工具 - Base64、PEM 等编码/解码

use crate::error::{AcmeError, Result};
use base64::Engine;

/// Base64 编码器
pub struct Base64Encoding;

impl Base64Encoding {
    /// 使用 URL-safe Base64 进行编码 (无填充)
    pub fn encode(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    /// 使用 URL-safe Base64 进行解码 (无填充)
    pub fn decode(data: &str) -> Result<Vec<u8>> {
        // 添加必要的填充
        let padded = match data.len() % 4 {
            2 => format!("{}==", data),
            3 => format!("{}=", data),
            _ => data.to_string(),
        };

        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&padded)
            .map_err(|e| AcmeError::crypto(format!("Base64 decode error: {}", e)))
    }

    /// 标准 Base64 编码 (带填充)
    pub fn encode_standard(data: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        STANDARD.encode(data)
    }

    /// 标准 Base64 解码 (带填充)
    pub fn decode_standard(data: &str) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD;
        STANDARD
            .decode(data)
            .map_err(|e| AcmeError::crypto(format!("Base64 decode error: {}", e)))
    }
}

/// PEM 编码器
pub struct PemEncoding;

impl PemEncoding {
    /// 将二进制数据编码为 PEM 格式
    pub fn encode(data: &[u8], label: &str) -> String {
        let pem = pem::Pem::new(label.to_string(), data.to_vec());
        pem::encode(&pem)
    }

    /// 从 PEM 格式解码二进制数据
    pub fn decode(pem_data: &str) -> Result<(String, Vec<u8>)> {
        let pem = pem::parse(pem_data)
            .map_err(|e| AcmeError::crypto(format!("PEM parse error: {}", e)))?;

        // 使用公开方法访问 pem 结构
        Ok((pem.tag().to_string(), pem.contents().to_vec()))
    }

    /// 检查是否为有效的 PEM 格式
    pub fn is_valid(data: &str) -> bool {
        pem::parse(data).is_ok()
    }

    /// 从 PEM 中提取二进制数据
    pub fn extract_data(pem_data: &str, expected_label: Option<&str>) -> Result<Vec<u8>> {
        let (label, data) = Self::decode(pem_data)?;

        if let Some(expected) = expected_label {
            if label != expected {
                return Err(AcmeError::crypto(format!(
                    "Expected PEM label '{}', got '{}'",
                    expected, label
                )));
            }
        }

        Ok(data)
    }
}

/// 十六进制编码器
pub struct HexEncoding;

impl HexEncoding {
    /// 编码为十六进制字符串
    pub fn encode(data: &[u8]) -> String {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        let mut result = String::with_capacity(data.len() * 2);
        for &byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
        }
        result
    }

    /// 从十六进制字符串解码
    pub fn decode(hex_str: &str) -> Result<Vec<u8>> {
        if hex_str.len() % 2 != 0 {
            return Err(AcmeError::crypto(
                "Hex string length must be even".to_string(),
            ));
        }

        let mut result = Vec::with_capacity(hex_str.len() / 2);
        for chunk in hex_str.as_bytes().chunks(2) {
            let hex = std::str::from_utf8(chunk)
                .map_err(|e| AcmeError::crypto(format!("Invalid UTF-8: {}", e)))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|e| AcmeError::crypto(format!("Hex decode error: {}", e)))?;
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
