# AcmeX Examples

This directory contains example code demonstrating the two API generations of
AcmeX:

- **Durable workflow API (v0.9+, current)** — intents, operations and a
  repository-backed workflow engine. This is what the HTTP API, `acmex serve`
  and `acmex obtain --wait` use. Start here for new code.
- **Legacy `AcmeClient` style (v0.8-era)** — the in-process ACME session API.
  Still supported, but new integrations should prefer the intent/workflow
  path.

## 📋 List of Examples

| Example              | API generation            | Description                                                                                        | Command                                                     |
|----------------------|---------------------------|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| `intent_issuance`    | v0.9+ durable workflow    | Full intent → issue operation → workflow engine → verify → file deployment, against a scripted in-process CA (no network needed). | `cargo run --example intent_issuance`                       |
| `renewal_controller` | v0.9+ durable workflow    | The `RenewalController` and the pure `calculate_decision` function: renewal windows, priorities, shadow mode and durable renew operations. | `cargo run --example renewal_controller`                    |
| `renewal_controller` | v0.9+ durable workflow    | The `RenewalController` and the pure `calculate_decision` function: renewal windows, priorities, shadow mode and durable renew operations. Replaces the old `advanced_scheduler` demo of the deprecated `AdvancedRenewalScheduler`. | `cargo run --example renewal_controller`                    |
| `basic_issuance`     | legacy `AcmeClient`       | Simplest way to register an account and issue a certificate using HTTP-01 (needs a reachable ACME server). | `cargo run --example basic_issuance`                        |
| `api_server_custom`  | legacy `AcmeClient`       | How to embed and start the AcmeX management API server within your own project.                     | `cargo run --example api_server_custom`                     |
| `dns_01_challenge`   | legacy `AcmeClient`       | Configuring and using a DNS-01 challenge solver with a provider (e.g., Cloudflare).                 | `cargo run --example dns_01_challenge --features dns-cloudflare` |

The two v0.9+ examples run fully offline: they script the ACME conversation
with `acmex::ca_backend::FakeAcmeTransport` (the same fixture the integration
tests use) and print what they would do. Everything except the network is
real — managed keys, CSR, strict verification and the durable file sink all
run for real. See `examples/intent_issuance.rs` for the assembly, and
`src/server/worker.rs` (`build_engine_from_config` / `register_executors`)
for the production wiring.

## 🚀 Running Examples

The offline examples need nothing but cargo:

```bash
cargo run --example intent_issuance
cargo run --example renewal_controller
```

The legacy examples talk to a real ACME server. Use Let's Encrypt Staging for
testing:

```bash
# Run the basic issuance example
cargo run --example basic_issuance
```

### Environment Variables

Some examples look for specific environment variables for credentials:

- `ACMEX_API_KEYS`: Comma-separated keys for API server authentication.
- `CLOUDFLARE_API_TOKEN`: Required for the DNS-01 example using Cloudflare.
- `ALIBABA_ACCESS_KEY_ID` & `ALIBABA_ACCESS_KEY_SECRET`: For Alibaba Cloud DNS.

## 🛠 Prerequisites

Ensure you have the required features enabled in your `Cargo.toml` if you are copying these into your own project. For
most examples, the default features are sufficient.

For DNS providers, you might need:

```bash
cargo run --example dns_01_challenge --features dns-cloudflare
```
