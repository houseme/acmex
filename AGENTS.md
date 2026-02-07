# AcmeX Agent Guide

This guide provides essential context and patterns for AI agents working on the AcmeX codebase.

## 🏗 Big Picture Architecture

- **Orchestration Layer (`src/orchestrator/`)**: Coordination of high-level ACME workflows. Use `Orchestrator` trait
  with `execute()`, `status()`, and `cancel()`.
- **Scheduling Layer (`src/scheduler/`)**: Task management with priority, concurrency (via semaphores), and retry logic.
- **Protocol Layer (`src/protocol/`)**: Low-level ACME (RFC 8555) implementation. Features `NoncePool` for optimized
  performance.
- **Server Layer (`src/server/`)**: Axum-based REST API. Features `/api` nested routes, `X-API-Key` auth, and *
  *asynchronous task execution**.
- **Storage Tier (`src/storage/`)**: Pluggable backends (File, Redis, Memory) with `StorageMigrator`.
- **Certificate Tier (`src/certificate/`)**: Chain verification logic and real-time **OCSP verification** via
  `OcspVerifier`.

## 🛠 Critical Workflows & Commands

- **Build with Enterprise Features**: `cargo build --all-features`
- **Check Compilation**: `cargo check --all-features`
- **Server Execution**: `acmex serve --addr 0.0.0.0:8080 --config config.toml`
- **API Check**:
    - Public: `GET /health`
    - Management (Requires `X-API-Key`): `GET /api/orders`, `GET /api/certificates`

## 💎 Project Patterns

### 1. Asynchronous API Execution (202 Accepted)

Most management APIs spawning long-running ACME tasks follow this pattern:

- **Handler**: Generates a 16-char random `task_id`.
- **State**: Inserts a `TaskInfo` into `state.tasks`.
- **Execution**: Spawns a `tokio::spawn` background task calling an `Orchestrator`.
- **Response**: Returns `StatusCode::ACCEPTED` with the `task_id`.
- **Polling**: Users query `GET /api/orders/:id` to check `OrchestrationStatus`.

### 2. Standardized Error Reporting (RFC 7807)

Use `AcmeError::to_problem_details()` to convert internal errors into standard JSON responses. Handler return types
should be `impl IntoResponse` calling `.into_response()`.

### 3. Audit Logging

Always trigger `EventAuditor::track_event(AcmeEvent::...)` for significant state changes (Account created, Order
created, Certificate revoked).

### 4. OCSP Status Integration

Integrate `OcspVerifier::verify_status(cert_der)` into certificate-related handlers to provide real-time revocation
data.

### 5. Feature Gating

All DNS providers and optional backends (Redis) MUST be feature-gated in `Cargo.toml` and `src/dns/providers/mod.rs`.

### 6. Timestamping

Uniformly use the `jiff` library. Compare timestamps using `.timestamp().as_second()`.

## 🔗 Key Integration Points

- **New DNS-01 Provider**: Add to `src/dns/providers/`, register in `mod.rs`, and implement `DnsProvider`.
- **New API Handler**: Add to `src/server/`, register route in `src/server/api.rs`, and adhere to the `AppState` /
  `TaskInfo` pattern.
- **Metrics**: Use `MetricsRegistry` for Prometheus counters and `EventAuditor` for audit trails.

## ✍️ Coding Conventions

- **Async Traits**: Use `#[async_trait]` and ensure traits are `Send + Sync`.
- **Cloning**: `AcmeClient` implements `Clone`. Clone it for use inside `tokio::spawn` tasks.
- **Dependencies**:
    - Crypto: `aws-lc-rs` (Primary).
    - HTTP: `reqwest` (Client) / `axum` (Server).
    - Serialization: `serde` / `serde_json`.

See `.github/copilot-instructions.md` for current v0.7.0 development roadmap.
