# AcmeX Agent Guide (v0.10.0 line)

## 🏗 Architecture Overview

AcmeX is a modular ACME v2 (RFC 8555) client and **certificate lifecycle
control plane**: durable workflows turn `CertificateIntent`s into issued,
verified, deployed and ARI-renewed certificates.

### 1. Two API Generations (both live)
- **New control plane (preferred)**: `src/domain/` (strong-typed model,
  zero infra deps) → `src/application/` (CQRS service: intents, operations)
  → `src/workflow/` (17-step durable engine: crash-safe, compensating,
  lease-fenced) → `src/ca_backend/` (ACME session: EAB, ARI, key rollover,
  ES256/RS256/EdDSA) + `src/challenge/` (presenter ports: dns-01,
  dns-account-01, http-01, tls-alpn-01) + `src/key/` (software + AWS KMS
  providers, external CSR) + `src/delivery/` (file, k8s secret, vault kv,
  http agent sinks).
- **Legacy client facade (frozen, sunset 2027-03-31)**: `src/client.rs`
  (`AcmeClient`), `src/protocol/` (JWS/JWK/nonce primitives shared by both
  paths), `src/orchestrator/`, `src/scheduler/`, `src/storage/`. Legacy
  `/api` routes shrink only; new capability goes to `/api/v1`.

### 2. Persistence & Messaging
- **`src/repository/`**: 9 aggregates over memory/file/redis backends with
  atomic CAS, fencing-token leases, and a transactional **outbox**. Traits
  are frozen; EntityStore is `pub(crate)`.
- **`src/notifications/`**: webhook + SMTP email delivery driven by the
  durable outbox consumer (HMAC-signed, replay-window checked).

### 3. Entrypoints
- **`src/cli/`**: `init` / `obtain --wait` / `daemon` (renewal controller +
  outbox consumer) / `serve` (REST + worker) / account & order & cert tools.
- **`src/server/`**: Axum REST (`/api/v1` + legacy `/api`), workflow worker
  assembly (`server/worker.rs` — the shared engine assembly for CLI and
  library consumers), API-key auth, health/metrics endpoints.

## 💎 Critical Design Patterns

### 1. Durable Operations (202 Accepted + Resume)
1. **Request**: `POST /api/v1/certificate-intents` (mandatory
   `Idempotency-Key`), then `:issue` returns `202 Accepted` + `Location`
   pointing at the operation.
2. **Drive**: workflow workers lease operations and advance the 17-step
   spine; every step persists before/after its external side effects
   (crash = resume, never re-order).
3. **Poll**: `GET /api/v1/operations/{id}`; terminal states are stable
   enums with classified errors (`retryable` vs `terminal`).
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

## 🔗 Reference Documentation (current facts only)
- `docs/PROJECT_ANALYSIS_AND_PLAN_ZH.md`: full capability matrix and gap list.
- `docs/roadmap/v0.10.0/README.md`: the active task/verification roadmap.
- `docs/roadmap/v0.9.0/`: implementation audit, FEATURE_MATRIX,
  KNOWN_LIMITATIONS (external-evidence debts).
- `docs/DOCUMENTATION_INDEX.md`: what is current vs historical archive.

## ✍️ Non-Negotiables (project red lines)
- No simulated success: never sleep-and-return-ok, never hardcode responses
  ("Nothing pretends to succeed").
- Secrets never appear in Debug/log/error output; credentials travel as
  SecretRefs (`env:`/`file:`/`vault:`).
- New public fields must be `#[serde(default)]` (persisted records must
  deserialize across upgrades).
- Time via `jiff`; errors classified (retryable vs terminal); CAS loops for
  every state transition; locks never held across `.await`.
- A skipped external test is not a pass (exit 77 convention).
