# AcmeX 加密模块功能文档

## 1. 概述
`crypto` 模块是 AcmeX 的核心安全组件，负责处理所有与加密、签名、哈希和密钥管理相关的操作。该模块旨在提供一个统一、安全且易于扩展的接口，以支持 ACME 协议（RFC 8555）中的各种安全需求。

## 2. 核心功能

### 2.1 密钥对管理 (`keypair.rs`)
- **支持算法**: 
  - **Ed25519 (推荐)**: 提供极高的性能和安全性，是现代 ACME 客户端的首选。
  - **ECDSA (P-256, P-384, P-521)**: 广泛兼容的椭圆曲线算法。
  - **RSA (2048, 4096)**: 传统但兼容性最强的算法。
- **JWK 支持**: 能够将公钥转换为 JSON Web Key (JWK) 格式，用于 ACME 账户注册和 JWS 签名。
- **自动化生成**: 提供 `KeyPairGenerator` 简化密钥对的创建流程。

### 2.2 签名与验证 (`signer.rs`)
- **统一接口**: 通过 `Signer` trait 抽象了对称（HMAC）和非对称（EdDSA, ECDSA）签名操作。
- **JWS 集成**: 生成符合 RFC 7515 标准的签名数据，支持 URL-safe Base64 编码。
- **HMAC 支持**: 提供 `HmacSigner` 用于内部完整性校验或特定协议扩展。

### 2.3 哈希计算 (`hash.rs`)
- **多算法支持**: 封装了 SHA-256、SHA-384 和 SHA-512。
- **便捷工具**: 
  - `hash_hex`: 直接获取十六进制字符串。
  - `hash_base64`: 获取符合 ACME 要求的 URL-safe Base64 编码哈希值（常用于 DNS-01 挑战的 TXT 记录计算）。

### 2.4 编码处理 (`encoding.rs`)
- **Base64URL**: 严格遵循 RFC 4648，不带填充（No Padding），确保与 ACME 服务器的无缝对接。
- **Hex**: 用于日志记录和调试信息的十六进制编码。

## 3. 安全设计
- **可观测性**: 所有关键加密操作（如密钥生成、签名计算）均集成 `tracing` 日志，支持在不泄露私钥的前提下进行流程追踪。
- **错误处理**: 细化了加密相关的错误分类（`AcmeError::Crypto`），提供明确的失败原因。
- **内存安全**: 利用 Rust 的所有权模型确保密钥数据在生命周期结束时被正确处理。

## 4. 使用示例

### 生成 Ed25519 密钥对
```rust
let generator = KeyPairGenerator::ed25519();
let key_pair = generator.generate()?;
```

### 计算 DNS-01 挑战所需的哈希
```rust
let key_auth = "token.thumbprint";
let dns_value = Sha256Hash::hash_base64(key_auth.as_bytes())?;
```
