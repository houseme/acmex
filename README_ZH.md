# AcmeX

[![Crates.io](https://img.shields.io/crates/v/acmex.svg)](https://crates.io/crates/acmex)
[![Documentation](https://docs.rs/acmex/badge.svg)](https://docs.rs/acmex)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

**AcmeX** 是一个使用 Rust 编写的模块化、企业级 ACME v2 (RFC 8555) 客户端和服务器生态系统。它专为高性能、可靠性和可扩展性而设计，支持多种 DNS 提供商、存储后端和加密库。

## 🏗 架构设计

AcmeX 采用分层设计，以确保关注点分离和易于维护：

- **应用层 (Application Layer)**: CLI 和基于 Axum 的 REST API 入口。
- **编排层 (Orchestration Layer)**: 用于配置、验证和续订的高级工作流管理。
- **调度层 (Scheduling Layer)**: 任务执行和并发管理。
- **协议层 (Protocol Layer)**: 底层 ACME 实现（JWS、Nonce 管理、目录）。
- **存储层 (Storage Tier)**: 可插拔后端（文件、Redis、内存、加密存储）。
- **证书层 (Certificate Tier)**: 证书链验证、CSR 生成和 OCSP 状态检查。

## 🚀 核心特性

- **完整 ACME v2 支持**: 完整实现 RFC 8555 协议。
- **异步任务执行**: 针对耗时操作采用非阻塞任务轮询模式。
- **多种验证方式**: 支持 `HTTP-01`、`DNS-01` 和 `TLS-ALPN-01`。
- **广泛的 DNS 支持**: 内置 Cloudflare、AWS Route53、阿里云、Azure 等多家提供商。
- **灵活的存储方案**: 支持本地文件、Redis 和加密存储。
- **可观测性**: 集成指标监控 (Prometheus)、结构化日志 (Tracing) 和 OpenTelemetry 支持。
- **安全优先**: 基于 Rust 的内存安全，使用 `zeroize` 处理敏感数据，遵循 RFC 7807 错误报告规范。

## 🛠 安装

在你的 `Cargo.toml` 中添加 AcmeX：

```toml
[dependencies]
acmex = "0.7.0"
```

## 📖 快速上手

```rust
use acmex::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 配置客户端
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    let mut client = AcmeClient::new(config)?;

    // 2. 签发证书
    let domains = vec!["example.com".to_string()];
    let mut solver_registry = ChallengeSolverRegistry::new();
    // 在此处添加你的验证器 (例如 Http01Solver, Dns01Solver)

    let bundle = client.issue_certificate(domains, &mut solver_registry).await?;

    // 3. 保存证书
    bundle.save_to_files("cert.pem", "key.pem")?;

    Ok(())
}
```

## 🛠 开发指南

### 前置条件
- Rust 1.75+
- Docker (用于 Redis/测试)

### 运行测试
```bash
cargo test
```

## 📄 项目文档

详细文档请参阅 `docs` 目录：
- [架构概览](docs/ARCHITECTURE.md)
- [可观测性指南](docs/OBSERVABILITY.md)
- [V0.7.0 规划](docs/V0.7.0_PLANNING.md)

## 📜 开源协议

本项目采用以下协议授权：
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) 或 http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
