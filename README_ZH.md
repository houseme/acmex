# AcmeX

[English](./README.md) | [中文](./README_ZH.md)

一个使用 Rust 编写的简单 ACME v2 客户端，用于获取 TLS 证书。支持 TLS-ALPN-01、HTTP-01 和 DNS-01 挑战，与 rustls 集成，并支持
Let's Encrypt、Google Trust Services 和 ZeroSSL。

[![AcmeX](https://img.shields.io/badge/version-v0.7.0--dev-blue)](https://github.com/houseme/acmex)

**AcmeX** 是一个企业级 ACME v2 (RFC 8555) 客户端和管理服务器。

## 🚀 核心特性 (v0.7.0)

- **异步任务架构**: 通过 202 Accepted 轮询模式实现非阻塞证书签发。
- **企业级 API 服务器**: 由 Axum 驱动的 RESTful API，支持 `X-API-Key` 认证。
- **广阔的 DNS 生态**: 内置支持 11 个提供商，包括 AWS Route53、阿里云、华为云、腾讯云等。
- **Nonce 池管理**: 高性能的 ACME Nonce 预取和缓存机制。
- **实时 OCSP 监控**: 自动检查已签发证书的撤销状态。
- **多后端存储**: 支持文件、Redis 和内存存储。

## 特性

- 完整的 ACME v2 支持 (RFC 8555)
- 支持 TLS-ALPN-01, HTTP-01, 和 DNS-01 挑战验证
- 与 rustls 集成，确保内存安全的 TLS 处理
- 支持基于文件的持久化（默认）和 Redis 缓存（可选）
- 默认支持 Let's Encrypt，通过 feature 开启 Google Trust Services 和 ZeroSSL
- 提供 CLI 工具和库 (Library) 两种使用方式
- 生产环境就绪：内置 Axum 服务器，支持 Prometheus 指标监控和 Tracing 链路追踪

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
acmex = "0.7.0"
```

开启 Redis 支持：

```toml
[dependencies]
acmex = { version = "0.7.0", features = ["redis"] }
```

## 用法

### 作为库使用

```rust
use acmex::{AcmeClient, AcmeConfig, ChallengeType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AcmeConfig::new(vec!["example.com".to_string()])
        .contact(vec!["mailto:user@example.com".to_string()])
        .prod(false);
    let client = AcmeClient::new(config);
    let (cert, key) = client.provision_certificate(ChallengeType::TlsAlpn01, None).await?;
    // 在 rustls 中使用 cert 和 key
    Ok(())
}
```

### 作为命令行工具使用

```bash
cargo run -- --domains example.com --email user@example.com --cache-dir ./acmex_cache
```

使用 Redis:

```bash
cargo run --features redis -- --domains example.com --email user@example.com --redis-url redis://127.0.0.1:6379
```

## 📦 服务模式

启动 AcmeX 管理服务器：

```bash
# 设置 API Key 用于身份验证
export ACMEX_API_KEYS="admin-token-1,admin-token-2"

# 启动服务器
acmex serve 0.0.0.0:8080 --config acmex.toml
```

## 🛠 接口使用示例 (API)

通过 REST API 申请证书：

```bash
curl -X POST http://localhost:8080/api/orders \
     -H "X-API-Key: admin-token-1" \
     -H "Content-Type: application/json" \
     -d '{"domains": ["example.com", "*.example.com"]}'

# 响应: 202 Accepted {"task_id": "abc-123"}
```

## 📚 文档

- [架构概览](docs/ARCHITECTURE.md)
- [可观测性指南](docs/OBSERVABILITY.md)
- [REST API 参考](docs/api/openapi.yaml)
- [如何实现 DNS 提供商](docs/DNS-01_IMPLEMENTATION.md)

## 许可证

本项目采用双许可证协议：

- [MIT 许可证](LICENSE-MIT)
- [Apache 许可证 2.0 版](LICENSE-APACHE)

您可以根据需要选择其中任意一个许可证来使用本项目。除非您明确声明，您为本项目提交的任何贡献将默认采用上述双许可证协议，无需附加其他条款或条件。

详细内容请参阅 [LICENSE-MIT](./LICENSE-MIT) 和 [LICENSE-APACHE](./LICENSE-APACHE) 文件。
