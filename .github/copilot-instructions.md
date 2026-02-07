# GitHub Copilot Instructions for AcmeX

**Project**: AcmeX (Enterprise ACME v2 Client & Server)  
**Version**: v0.7.0 (Phase 5: Testing & Documentation)  
**Stack**: Rust 1.93+ (Edition 2024), Tokio, Axum, Reqwest, Jiff, AWS-LC-RS.

---

## 🎯 Project Context

AcmeX is a high-performance, modular ACME v2 implementation. It supports automated certificate lifecycle management with a focus on enterprise features like OCSP verification, multi-provider DNS-01 challenges, and a RESTful management API.

### Core Architecture Layers
1.  **Protocol (`src/protocol/`)**: RFC 8555 implementation, JWS, NoncePool.
2.  **Orchestration (`src/orchestrator/`)**: Async state machines for provisioning and renewal.
3.  **Server (`src/server/`)**: Axum API with `X-API-Key` auth and background task tracking.
4.  **Storage (`src/storage/`)**: Abstracted backends (File, Redis, Memory).
5.  **DNS Providers (`src/dns/providers/`)**: 10+ integrated providers (Cloudflare, Route53, Huawei, Alibaba, etc.).

---

## 🛠️ Development Guidelines

### 1. Async Task Pattern (202 Accepted)
When implementing management APIs that trigger ACME workflows:
- **Do not** wait for the ACME process to finish in the handler.
- **Do** generate a unique `task_id`.
- **Do** spawn a `tokio::spawn` task.
- **Do** return `StatusCode::ACCEPTED` with the `task_id`.
- **Example**: See `src/server/api/order.rs`.

### 2. Error Handling
- Use `AcmeError` for internal errors.
- Convert to HTTP responses using `AcmeError::to_problem_details()` (RFC 7807).
- Always provide meaningful context in error variants.

### 3. Feature Gating & Dependencies
- Keep the core library lightweight.
- Use feature flags for:
    - Specific DNS providers (e.g., `dns-huawei`).
    - Storage backends (e.g., `redis`).
    - Crypto backends (`aws-lc-rs` vs `ring`).
- Use `jiff` for all time-related logic.

### 4. Security & Audit
- Protect management endpoints with `X-API-Key`.
- Log significant events via `EventAuditor`.
- Use `OcspVerifier` to check certificate revocation status in real-time.

---

## 🤖 Copilot Interaction Patterns

### Requesting Code Generation
- **DNS Provider**: "Implement a new `DnsProvider` for [Provider Name] following the pattern in `src/dns/providers/cloudflare.rs`."
- **API Endpoint**: "Create an Axum handler for [Action] that follows the 202 Accepted task pattern and updates `AppState`."
- **Tests**: "Write an integration test for the `OrderOrchestrator` using a mock ACME server."

### Code Style Preferences
- Prefer `impl IntoResponse` for Axum handlers.
- Use `tracing::info!/error!` for logging.
- Ensure all new traits are `Send + Sync`.
- Follow Rust 2024 edition idioms (e.g., improved `impl Trait` handling).

---

## 📅 Current Focus: Phase 5 (v0.7.0)
- **Testing**: Enhancing integration tests and adding mock-based unit tests for DNS providers.
- **Documentation**: Completing OpenAPI specs and developer guides in `docs/`.
- **Stability**: Fixing Clippy lints and ensuring 100% feature-gate compatibility.

**Last Updated**: 2026-02-08  
**Status**: v0.7.0-beta Development
