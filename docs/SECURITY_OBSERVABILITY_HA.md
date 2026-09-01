# AcmeX Security, Observability and HA Baseline

This document is the production baseline for the v0.9.0 T11 workstream.

## Security Baseline

- Management API credentials are required before management routes are exposed.
  `/health` remains a lightweight liveness endpoint and `/ready` reports only
  coarse readiness state.
- Runtime API key state stores SHA-256 digests, key IDs, status, expiry,
  rotation window, tenant, roles and permissions. Plaintext keys should only be
  present at process startup or inside short-lived `SecretBytes`.
- Sensitive configuration values use `SecretRef`: `env:NAME`, `file:/path`,
  `vault:<mount>:<path>:<key>` or `provider:<scheme>:<reference>`.
- File secrets and key material should be owned by the AcmeX runtime user and
  readable only by that user.
- Public listeners must be explicitly configured. The default API bind address
  is loopback.
- TLS or mTLS termination is an operator responsibility unless AcmeX is run
  behind a trusted local sidecar.
- Webhook delivery is outbox-backed and at least once. Consumers must dedupe by
  `event_id`. HMAC signatures use `X-AcmeX-Event-Id`,
  `X-AcmeX-Signature-Timestamp` and `X-AcmeX-Signature`.
- Webhook failures do not roll back completed ACME state. Failed deliveries
  retry with bounded exponential backoff and eventually move to dead letter for
  manual replay.
- Metrics labels must stay low cardinality: CA, challenge type, provider type,
  sink type, result, workflow step and error class. Domains, operation IDs,
  certificate serials, tokens, JWS payloads and private keys are forbidden.

## Trace Convention

Use these span fields when the value exists:

- `tenant_id`
- `intent_id`
- `lineage_id`
- `operation_id`
- `workflow_step`
- `ca_id`
- `challenge_type`
- `provider_id`
- `sink_id`
- `request_id`

Do not record private key PEM, DNS/API tokens, EAB HMAC keys, key authorization
values, complete JWS documents, webhook secrets or raw certificate private keys.
Identifier values should default to a normalized hash in shared telemetry.

## Readiness and Diagnostics

- `GET /health`: process liveness only.
- `GET /ready`: coarse load-balancer readiness. It checks configuration,
  repository presence, worker configuration and management credential presence.
- `GET /api/diagnostics`: authenticated operational view with pending outbox,
  cleanup backlog and configured metric names.

Readiness does not actively call every CA, DNS provider or webhook endpoint.
External dependency flaps should alert operators without ejecting every AcmeX
instance from service.

## SLOs

- Issuance operation success rate: target 99.5 percent over 30 days.
- Issuance P95 latency: target below 5 minutes, excluding CA rate-limit windows.
- Renewal safety: 99.9 percent of managed certificates renewed before the
  configured safety deadline.
- Certificate expiry: any active certificate below the emergency threshold is a
  page.
- Outbox delivery: oldest pending event below 10 minutes in normal operation.
- Cleanup: pending challenge cleanup older than the lease TTL is a page.
- Compensation or rollback failure is a page.

## Prometheus Rule Example

```yaml
groups:
  - name: acmex-v090
    rules:
      - alert: AcmeXCertificateExpiresSoon
        expr: acmex_certificate_seconds_to_expiry{state="active"} < 172800
        for: 5m
        labels:
          severity: page
        annotations:
          summary: Active certificate expires within 48 hours

      - alert: AcmeXOutboxBacklog
        expr: sum(acmex_outbox_pending) > 100
        for: 10m
        labels:
          severity: ticket
        annotations:
          summary: AcmeX webhook outbox backlog is growing

      - alert: AcmeXRenewalFailures
        expr: increase(acmex_renewal_failures_total[15m]) > 0
        for: 1m
        labels:
          severity: page
        annotations:
          summary: AcmeX renewal failure observed

      - alert: AcmeXRepositoryErrors
        expr: increase(acmex_repository_errors_total[5m]) > 0
        for: 1m
        labels:
          severity: ticket
        annotations:
          summary: AcmeX repository errors observed
```

## Dashboard Fields

- Operation throughput and result split from `acmex_operations_total`.
- Step latency from `acmex_operation_step_duration_seconds`.
- ACME request rate, latency, badNonce and rate-limit error class.
- Challenge propagation latency and cleanup pending count.
- Renewal due count, renewal failures and certificate seconds to expiry.
- Deployment result split by sink type.
- Outbox pending count by event type and repository errors by backend.
