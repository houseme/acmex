# AcmeX Agent Guide

This guide provides essential context and patterns for AI agents working on the AcmeX codebase.

## 🏗 Big Picture Architecture

- **Orchestration Layer**: Coordination of complex ACME workflows (provision, validate, renew). Use `Orchestrator` trait
  in `src/orchestrator/mod.rs`.
- **Scheduling Layer**: Asynchronous task management with priorities and concurrency control. See `src/scheduler/`.
- **Protocol Layer**: Low-level ACME (RFC 8555) implementation. Optimized with `NoncePool`.
- **Server Layer**: Enterprise-ready REST API based on Axum. Use `AppState` for shared resources. API Key auth via
  `src/server/auth.rs`.
- **Storage Tier**: Pluggable backends (File, Redis, Memory) with `StorageMigrator` support.

## 🛠 Critical Workflows & Commands

- **Build with Enterprise Features**: `cargo build --all-features`
- **Server API Check**: `GET /health` (Public), `GET /api/certificates` (Requires `X-API-Key: secret-admin-key`)
- **Key Rollover**: Triggers via `KeyRollover` in `src/account/key_rollover.rs`.

## 💎 Project Patterns

- **Problem Details (RFC 7807)**: Use `AcmeError::to_problem_details()` for consistent REST API error reporting.
- **Ocsp Checks**: Integrate real-time status via `OcspVerifier` during chain verification.
- **Feature Gating**: All DNS providers MUST be feature-gated in `src/dns/providers/mod.rs` and `Cargo.toml`.
- **Async & Concurrent**: Use `tokio` for all I/O. Use `Semaphore` in schedulers to limit concurrency.

## 🔗 Key Integration Points

- **DNS-01 Solvers**: New providers go into `src/dns/providers/`.
- **Metrics**: High-level auditing via `EventAuditor` in `src/metrics/events.rs`.

## ✍️ Coding Conventions

- **Async & Traits**: Use `#[async_trait]` and ensure traits are `Send + Sync`.
- **Error Handling**: Use `crate::error::Result<T>` which uses `AcmeError` (built with `thiserror`).
    - Example: `return Err(AcmeError::Protocol("invalid nonce".into()))`
- **Logging**: Use `tracing` macros. Prefer field-based logging for structured data.
    - Example: `info!(domain = %domain, "Completed challenge verification")`
- **Types**: Always check `src/types.rs` for shared enums like `ChallengeType`, `OrderStatus`, and `RevocationReason`.
- **Dependency Strategy**:
    - `aws-lc-rs` is the preferred crypto provider (via `rcgen` and `rustls`).
    - `hickory-resolver` for DNS-01 verification.

See `.github/copilot-instructions.md` for current Phase 3 development goals.
