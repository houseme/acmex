# AcmeX Agent Guide (v0.7.0)

This guide provides a comprehensive overview of the AcmeX project architecture, patterns, and development standards for AI agents and contributors.

## 🏗 Architecture Overview

AcmeX is designed as a modular, enterprise-grade ACME v2 (RFC 8555) client and server ecosystem.

### 1. Layered Design
- **Application Layer (`src/cli/`, `src/server/`)**: Entry points for CLI users and REST API consumers.
- **Orchestration Layer (`src/orchestrator/`)**: High-level workflow management (Provisioning, Validation, Renewal). Uses the `Orchestrator` trait for state-machine-like execution.
- **Scheduling Layer (`src/scheduler/`)**: Manages task execution, priorities, and concurrency limits using semaphores.
- **Protocol Layer (`src/protocol/`)**: Low-level ACME implementation (JWS, Nonce management, Directory, Objects).
- **Storage Tier (`src/storage/`)**: Pluggable backends (File, Redis, Memory, Encrypted) with migration support.
- **Certificate Tier (`src/certificate/`)**: Chain verification, CSR generation, and real-time OCSP status checking.

### 2. Core Components
- **`AcmeClient`**: The primary interface for interacting with ACME servers. It is `Clone`-friendly and thread-safe.
- **`NoncePool`**: Optimized nonce management with pre-fetching and caching to minimize round-trips.
- **`Orchestrator` Trait**: Defines `execute()`, `status()`, and `cancel()` for long-running tasks.
- **`AppState`**: Shared state in the Axum server, containing the task tracker, metrics, and client instances.

## 💎 Critical Design Patterns

### 1. Asynchronous Task Execution (Post-Task-Polling)
To handle long-running ACME operations without blocking HTTP requests:
1. **Request**: User hits an endpoint (e.g., `POST /api/orders`).
2. **Acceptance**: Server generates a `task_id`, spawns a background `tokio::spawn` task, and returns `202 Accepted`.
3. **Tracking**: The task updates its status in `AppState.tasks`.
4. **Polling**: User queries `GET /api/orders/:id` to check progress.

### 2. Standardized Error Reporting (RFC 7807)
All API errors must be converted to `ProblemDetails` using `AcmeError::to_problem_details()`. This ensures consistent, machine-readable error responses.

### 3. Feature Gating
AcmeX uses extensive feature flags to keep the binary lean:
- **Crypto**: `aws-lc-rs` (default) or `ring`.
- **Storage**: `redis` is optional.
- **DNS Providers**: Each provider (e.g., `dns-cloudflare`, `dns-route53`) is gated.

### 4. Observability & Audit
- **Metrics**: Use `MetricsRegistry` for Prometheus-compatible counters and histograms.
- **Audit Logs**: Trigger `EventAuditor::track_event(AcmeEvent::...)` for all significant state changes (e.g., account creation, certificate issuance).
- **Tracing**: Use `tracing::instrument` for structured logging across async boundaries.

## 🛠 Development Workflows

### Adding a New DNS Provider
1. Create `src/dns/providers/your_provider.rs`.
2. Implement the `DnsProvider` trait.
3. Register the provider in `src/dns/providers/mod.rs` with appropriate `#[cfg(feature = "...")]`.
4. Add the feature flag to `Cargo.toml`.

### Adding a New API Endpoint
1. Define the handler in `src/server/api/`.
2. Ensure it uses `AppState` and follows the 202 Accepted pattern if it's a long-running task.
3. Register the route in `src/server/api.rs`.
4. Update the `X-API-Key` middleware if the endpoint requires authentication.

## ✍️ Coding Standards
- **Async**: Use `#[async_trait]` for traits. Prefer `tokio` primitives.
- **Time**: Use the `jiff` library for all timestamp operations.
- **Safety**: Use `zeroize` for sensitive data in memory.
- **Testing**: Write unit tests for logic and integration tests (in `tests/`) for ACME flows using mock servers.

## 🔗 Reference Documentation
- `docs/ARCHITECTURE.md`: Detailed system design.
- `docs/V0.7.0_PLANNING.md`: Current roadmap and feature status.
- `docs/OBSERVABILITY.md`: Metrics and logging configuration.
