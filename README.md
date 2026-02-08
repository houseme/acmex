# AcmeX

[![Crates.io](https://img.shields.io/crates/v/acmex.svg)](https://crates.io/crates/acmex)
[![Documentation](https://docs.rs/acmex/badge.svg)](https://docs.rs/acmex)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust Version](https://img.shields.io/badge/rust-1.92+-orange.svg)](https://www.rust-lang.org/)

**AcmeX** is a modular, enterprise-grade ACME v2 (RFC 8555) client and server ecosystem written in Rust. It is designed
for high performance, reliability, and extensibility, supporting various DNS providers, storage backends, and
cryptographic libraries. AcmeX enables automated certificate lifecycle management with advanced features like OCSP
verification, multi-provider DNS-01 challenges, and a RESTful management API.

## 🏗 Architecture

AcmeX follows a layered design to ensure separation of concerns and ease of maintenance:

- **Application Layer**: CLI and REST API (Axum-based) entry points for user interaction.
- **Orchestration Layer**: High-level workflow management for provisioning, validation, and renewal processes.
- **Scheduling Layer**: Task execution and concurrency management for asynchronous operations.
- **Protocol Layer**: Low-level ACME implementation (JWS, Nonce management, Directory handling).
- **Storage Tier**: Pluggable backends (File, Redis, Memory, Encrypted) for persistence.
- **Certificate Tier**: Chain verification, CSR generation, and OCSP status checking for security.

## 🚀 Key Features

- **Full ACME v2 Support**: Complete implementation of RFC 8555, including all challenge types and account management.
- **Asynchronous Execution**: Non-blocking task polling for long-running operations, ensuring responsiveness.
- **Multiple Challenge Types**: Support for `HTTP-01`, `DNS-01`, and `TLS-ALPN-01` challenges.
- **Extensive DNS Support**: Built-in providers for Cloudflare, AWS Route53, Alibaba Cloud, Azure, Google Cloud, Huawei,
  Tencent, and more.
- **Flexible Storage**: Support for local files, Redis, and encrypted storage backends.
- **Multi-CA Support**: Integration with Let's Encrypt, Google CA, ZeroSSL, and custom ACME servers.
- **Observability**: Integrated metrics (Prometheus), structured logging (Tracing), and OpenTelemetry support.
- **Security First**: Memory safety via Rust, `zeroize` for sensitive data, and RFC 7807 error reporting.
- **CLI and API**: Command-line interface and RESTful API for easy integration and management.
- **Feature Gates**: Optional dependencies for DNS providers, storage backends, and crypto libraries to keep the core
  lightweight.

## 🛠 Installation

Add AcmeX to your `Cargo.toml`:

```toml
[dependencies]
acmex = "0.8.0"
```

### Feature Flags

Enable optional features as needed:

```toml
[dependencies.acmex]
version = "0.8.0"
features = ["dns-cloudflare", "redis", "cli"]
```

Available features:

- **Crypto**: `aws-lc-rs` (default), `ring-crypto`
- **Storage**: `redis`
- **DNS Providers**: `dns-cloudflare`, `dns-route53`, `dns-alibaba`, `dns-azure`, `dns-google`, `dns-huawei`,
  `dns-tencent`, etc.
- **CAs**: `google-ca`, `zerossl-ca`
- **Other**: `metrics`, `cli`

## 📖 Quick Start

### Basic Certificate Issuance

```rust
use acmex::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Configure the client
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    let mut client = AcmeClient::new(config)?;

    // 2. Set up challenge solvers
    let mut solver_registry = ChallengeSolverRegistry::new();
    // For DNS-01 challenge with Cloudflare (enable dns-cloudflare feature)
    // solver_registry.register(Box::new(CloudflareSolver::new(api_token, zone_id)?));
    // For HTTP-01 challenge
    // solver_registry.register(Box::new(Http01Solver::new()));

    // 3. Issue a certificate
    let domains = vec!["example.com".to_string(), "www.example.com".to_string()];
    let bundle = client.issue_certificate(domains, &mut solver_registry).await?;

    // 4. Save the certificate
    bundle.save_to_files("cert.pem", "key.pem")?;

    Ok(())
}
```

### Running the API Server

```bash
# Build and run the server
cargo run --features cli -- --config acmex.toml
```

Example `acmex.toml`:

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

## 🛠 Development

### Prerequisites

- Rust 1.92+
- Docker (for Redis testing)

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Examples

Explore the `examples/` directory for more usage patterns:

- [Basic Issuance](examples/basic_issuance.rs)
- [DNS-01 Challenge](examples/dns_01_challenge.rs)
- [API Server Custom](examples/api_server_custom.rs)

## 📄 Documentation

Detailed documentation is available in the `docs` directory:

- [Architecture Overview](docs/ARCHITECTURE.md)
- [DNS Providers Guide](docs/DNS_PROVIDERS.md)
- [API Implementation](docs/api/README.md)
- [Observability Guide](docs/OBSERVABILITY.md)
- [V0.8.0 Release Notes](docs/RELEASE_NOTES_v0.8.0.md)

API documentation: [docs.rs/acmex](https://docs.rs/acmex)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on how to get started.

### Reporting Issues

- [GitHub Issues](https://github.com/houseme/acmex/issues)
- For security issues, please email [housemecn@gmail.com](mailto:housemecn@gmail.com)

## 📜 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
