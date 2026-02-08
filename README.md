# AcmeX

[![Crates.io](https://img.shields.io/crates/v/acmex.svg)](https://crates.io/crates/acmex)
[![Documentation](https://docs.rs/acmex/badge.svg)](https://docs.rs/acmex)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

**AcmeX** is a modular, enterprise-grade ACME v2 (RFC 8555) client and server ecosystem written in Rust. It is designed for high performance, reliability, and extensibility, supporting various DNS providers, storage backends, and cryptographic libraries.

## 🏗 Architecture

AcmeX follows a layered design to ensure separation of concerns and ease of maintenance:

- **Application Layer**: CLI and REST API (Axum-based) entry points.
- **Orchestration Layer**: High-level workflow management for provisioning, validation, and renewal.
- **Scheduling Layer**: Task execution and concurrency management.
- **Protocol Layer**: Low-level ACME implementation (JWS, Nonce management, Directory).
- **Storage Tier**: Pluggable backends (File, Redis, Memory, Encrypted).
- **Certificate Tier**: Chain verification, CSR generation, and OCSP status checking.

## 🚀 Key Features

- **Full ACME v2 Support**: Complete implementation of RFC 8555.
- **Asynchronous Execution**: Non-blocking task polling for long-running operations.
- **Multiple Challenge Types**: Support for `HTTP-01`, `DNS-01`, and `TLS-ALPN-01`.
- **Extensive DNS Support**: Built-in providers for Cloudflare, AWS Route53, Alibaba Cloud, Azure, and more.
- **Flexible Storage**: Support for local files, Redis, and encrypted storage.
- **Observability**: Integrated metrics (Prometheus), structured logging (Tracing), and OpenTelemetry support.
- **Security First**: Memory safety via Rust, `zeroize` for sensitive data, and RFC 7807 error reporting.

## 🛠 Installation

Add AcmeX to your `Cargo.toml`:

```toml
[dependencies]
acmex = "0.7.0"
```

## 📖 Quick Start

```rust
use acmex::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Configure the client
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    let mut client = AcmeClient::new(config)?;

    // 2. Issue a certificate
    let domains = vec!["example.com".to_string()];
    let mut solver_registry = ChallengeSolverRegistry::new();
    // Add your solvers here (e.g., Http01Solver, Dns01Solver)

    let bundle = client.issue_certificate(domains, &mut solver_registry).await?;

    // 3. Save the certificate
    bundle.save_to_files("cert.pem", "key.pem")?;

    Ok(())
}
```

## 🛠 Development

### Prerequisites
- Rust 1.75+
- Docker (for Redis/Testing)

### Running Tests
```bash
cargo test
```

## 📄 Documentation

Detailed documentation is available in the `docs` directory:
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Observability Guide](docs/OBSERVABILITY.md)
- [V0.7.0 Planning](docs/V0.7.0_PLANNING.md)

## 📜 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
