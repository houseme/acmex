# AcmeX Examples

This directory contains example code demonstrating various ways to use the AcmeX library.

## 📋 List of Examples

| Example              | Description                                                                              | command                                  |
|----------------------|------------------------------------------------------------------------------------------|------------------------------------------|
| `basic_issuance`     | Simplest way to register an account and issue a certificate using HTTP-01.               | `cargo run --example basic_issuance`     |
| `advanced_scheduler` | Usage of the `AdvancedRenewalScheduler` for background certificate lifecycle management. | `cargo run --example advanced_scheduler` |
| `api_server_custom`  | How to embed and start the AcmeX management API server within your own project.          | `cargo run --example api_server_custom`  |
| `dns_01_challenge`   | Configuring and using a DNS-01 challenge solver with a provider (e.g., Cloudflare).      | `cargo run --example dns_01_challenge`   |

## 🚀 Running Examples

Most examples require an ACME server. You can use Let's Encrypt Staging for testing:

```bash
# Run the basic issuance example
cargo run --example basic_issuance
```

### Environment Variables

Some examples might look for specific environment variables for credentials:

- `ACMEX_API_KEYS`: Comma-separated keys for API server authentication.
- `CLOUDFLARE_API_TOKEN`: Required for DNS-01 examples using Cloudflare.
- `ALIBABA_ACCESS_KEY_ID` & `ALIBABA_ACCESS_KEY_SECRET`: For Alibaba Cloud DNS.

## 🛠 Prerequisites

Ensure you have the required features enabled in your `Cargo.toml` if you are copying these into your own project. For
most examples, the default features are sufficient.

For DNS providers, you might need:

```bash
cargo run --example dns_01_challenge --features dns-cloudflare
```

