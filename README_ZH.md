# AcmeX

[![Crates.io](https://img.shields.io/crates/v/acmex.svg)](https://crates.io/crates/acmex)
[![Documentation](https://docs.rs/acmex/badge.svg)](https://docs.rs/acmex)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust Version](https://img.shields.io/badge/rust-1.92+-orange.svg)](https://www.rust-lang.org/)

**AcmeX** 是一个使用 Rust 编写的模块化、企业级 ACME v2 (RFC 8555) 客户端和服务器生态系统。它专为高性能、可靠性和可扩展性而设计，支持多种
DNS 提供商、存储后端和加密库。AcmeX 支持自动化证书生命周期管理，具有 OCSP 验证、多提供商 DNS-01 挑战和 RESTful 管理 API
等高级功能。

## 🏗 架构设计

AcmeX 采用分层设计，以确保关注点分离和易于维护：

- **应用层 (Application Layer)**: CLI 和基于 Axum 的 REST API 入口，用于用户交互。
- **编排层 (Orchestration Layer)**: 用于配置、验证和续订的高级工作流管理。
- **调度层 (Scheduling Layer)**: 任务执行和并发管理，用于异步操作。
- **协议层 (Protocol Layer)**: 底层 ACME 实现（JWS、Nonce 管理、目录处理）。
- **存储层 (Storage Tier)**: 可插拔后端（文件、Redis、内存、加密存储）用于持久化。
- **证书层 (Certificate Tier)**: 证书链验证、CSR 生成和 OCSP 状态检查以确保安全性。

## 🚀 核心特性

- **完整 ACME v2 支持**: 完整实现 RFC 8555，包括所有挑战类型和账户管理。
- **异步任务执行**: 针对耗时操作采用非阻塞任务轮询模式，确保响应性。
- **多种验证方式**: 支持 `HTTP-01`、`DNS-01` 和 `TLS-ALPN-01` 挑战。
- **广泛的 DNS 支持**: 内置 Cloudflare、AWS Route53、阿里云、Azure、Google Cloud、华为、腾讯等多提供商。
- **灵活的存储方案**: 支持本地文件、Redis 和加密存储后端。
- **多 CA 支持**: 与 Let's Encrypt、Google CA、ZeroSSL 和自定义 ACME 服务器集成。
- **可观测性**: 集成指标监控 (Prometheus)、结构化日志 (Tracing) 和 OpenTelemetry 支持。
- **安全优先**: 基于 Rust 的内存安全，使用 `zeroize` 处理敏感数据，遵循 RFC 7807 错误报告规范。
- **CLI 和 API**: 命令行界面和 RESTful API，便于集成和管理。
- **功能门控**: DNS 提供商、存储后端和加密库的可选依赖，保持核心轻量。

## 🛠 安装

在你的 `Cargo.toml` 中添加 AcmeX：

```toml
[dependencies]
acmex = "0.8.0"
```

### 功能标志

根据需要启用可选功能：

```toml
[dependencies.acmex]
version = "0.8.0"
features = ["dns-cloudflare", "redis", "cli"]
```

可用功能：

- **加密**: `aws-lc-rs` (默认), `ring-crypto`
- **存储**: `redis`
- **DNS 提供商**: `dns-cloudflare`, `dns-route53`, `dns-alibaba`, `dns-azure`, `dns-google`, `dns-huawei`, `dns-tencent`
  等
- **CA**: `google-ca`, `zerossl-ca`
- **其他**: `metrics`, `cli`

## 📖 快速上手

### 基本证书签发

```rust
use acmex::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 配置客户端
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    let mut client = AcmeClient::new(config)?;

    // 2. 设置挑战解决器
    let mut solver_registry = ChallengeSolverRegistry::new();
    // 对于 Cloudflare 的 DNS-01 挑战 (启用 dns-cloudflare 功能)
    // solver_registry.register(Box::new(CloudflareSolver::new(api_token, zone_id)?));
    // 对于 HTTP-01 挑战
    // solver_registry.register(Box::new(Http01Solver::new()));

    // 3. 签发证书
    let domains = vec!["example.com".to_string(), "www.example.com".to_string()];
    let bundle = client.issue_certificate(domains, &mut solver_registry).await?;

    // 4. 保存证书
    bundle.save_to_files("cert.pem", "key.pem")?;

    Ok(())
}
```

### 运行 API 服务器

```bash
# 构建并运行服务器
cargo run --features cli -- --config acmex.toml
```

示例 `acmex.toml`：

```toml
[server]
host = "0.0.0.0"
port = 8080
api_key = "your-secret-api-key"

[storage]
backend = "file"
path = "./data"

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "admin@example.com"
```

## 🛠 开发指南

### 前置条件

- Rust 1.92+
- Docker (用于 Redis 测试)

### 构建

```bash
cargo build
```

### 运行测试

```bash
cargo test
```

### 示例

探索 `examples/` 目录以获取更多使用模式：

- [基本签发](examples/basic_issuance.rs)
- [DNS-01 挑战](examples/dns_01_challenge.rs)
- [自定义 API 服务器](examples/api_server_custom.rs)

## 📄 项目文档

详细文档请参阅 `docs` 目录：

- [架构概览](docs/ARCHITECTURE.md)
- [DNS 提供商指南](docs/DNS_PROVIDERS.md)
- [API 实现](docs/api/README.md)
- [可观测性指南](docs/OBSERVABILITY.md)
- [V0.8.0 发布说明](docs/RELEASE_NOTES_v0.8.0.md)

API 文档：[docs.rs/acmex](https://docs.rs/acmex)

## 🤝 贡献

我们欢迎贡献！请参阅我们的[贡献指南](CONTRIBUTING.md)以了解如何开始。

### 报告问题

- [GitHub Issues](https://github.com/houseme/acmex/issues)
- 对于安全问题，请发送邮件至 [housemecn@gmail.com](mailto:housemecn@gmail.com)

## 📜 开源协议

本项目采用以下协议授权：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) 或 http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
