# AcmeX

[English](./README.md) | [中文](./README_ZH.md)

A simple ACME v2 client for obtaining TLS certificates, built with Rust. Supports TLS-ALPN-01, HTTP-01, and DNS-01
challenges, integrates with rustls, and works with Let's Encrypt, Google Trust Services, and ZeroSSL.

[![AcmeX](https://img.shields.io/badge/version-v0.7.0--dev-blue)](https://github.com/houseme/acmex)

**AcmeX** is an enterprise-grade ACME v2 (RFC 8555) client and management server.

## 🚀 Key Features (v0.7.0)

- **Asynchronous Task Architecture**: Non-blocking certificate issuance via 202 Accepted polling.
- **Enterprise API Server**: RESTful API powered by Axum with `X-API-Key` authentication.
- **Broad DNS Ecosystem**: Built-in support for 11 providers including AWS Route53, Alibaba Cloud, Huawei Cloud, Tencent
  Cloud, etc.
- **Nonce Pooling**: High-performance pre-fetching and caching of ACME nonces.
- **Real-time OCSP Monitoring**: Automated status checks for issued certificates.
- **Multi-backend Storage**: File, Redis, and Memory storage support.

## Features

- Comprehensive ACME v2 support (RFC 8555)
- TLS-ALPN-01, HTTP-01, and DNS-01 challenges
- rustls integration for memory-safe TLS
- File-based caching (default) and Redis caching (optional)
- Let's Encrypt by default, Google Trust Services and ZeroSSL via features
- CLI tool and library usage
- Production-ready with axum, Prometheus monitoring, and tracing

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
acmex = "0.7.0"
```

For Redis support:

```toml
[dependencies]
acmex = { version = "0.7.0", features = ["redis"] }
```

## Usage

### As a Library

```rust
use acmex::{AcmeClient, AcmeConfig, ChallengeType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AcmeConfig::new(vec!["example.com".to_string()])
        .contact(vec!["mailto:user@example.com".to_string()])
        .prod(false);
    let client = AcmeClient::new(config);
    let (cert, key) = client.provision_certificate(ChallengeType::TlsAlpn01, None).await?;
    // Use cert and key with rustls
    Ok(())
}
```

### As a CLI Tool

```bash
cargo run -- --domains example.com --email user@example.com --cache-dir ./acmex_cache
```

With Redis:

```bash
cargo run --features redis -- --domains example.com --email user@example.com --redis-url redis://127.0.0.1:6379
```

## 📦 Service Mode

Start the AcmeX management server:

```bash
# Set API keys for authentication
export ACMEX_API_KEYS="admin-token-1,admin-token-2"

# Start server
acmex serve 0.0.0.0:8080 --config acmex.toml
```

## 🛠 Usage Example (API)

Obtain a certificate via REST API:

```bash
curl -X POST http://localhost:8080/api/orders \
     -H "X-API-Key: admin-token-1" \
     -H "Content-Type: application/json" \
     -d '{"domains": ["example.com", "*.example.com"]}'

# Response: 202 Accepted {"task_id": "abc-123"}
```

## 📚 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Observability Guide](docs/OBSERVABILITY.md)
- [REST API Reference](docs/api/openapi.yaml)
- [Implementing DNS Providers](docs/DNS-01_IMPLEMENTATION.md)

## License

This project is licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

You may choose either license to use this project. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.

See the [LICENSE-MIT](./LICENSE-MIT) and [LICENSE-APACHE](./LICENSE-APACHE) files for details.
