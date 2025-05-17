# AcmeX

[English](./README.md) | [中文](./README_ZH.md)

A simple ACME v2 client for obtaining TLS certificates, built with Rust. Supports TLS-ALPN-01, HTTP-01, and DNS-01
challenges, integrates with rustls, and works with Let's Encrypt, Google Trust Services, and ZeroSSL.

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
acmex = "0.0.1"
```

For Redis support:

```toml
[dependencies]
acmex = { version = "0.0.1", features = ["redis"] }
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

## License

This project is licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

You may choose either license to use this project. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.

See the [LICENSE-MIT](./LICENSE-MIT) and [LICENSE-APACHE](./LICENSE-APACHE) files for details.
