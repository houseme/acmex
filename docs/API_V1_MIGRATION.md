# Legacy API to API v1 Migration

Legacy `/api` routes remain available for compatibility, but every response
now carries:

- `Deprecation: true`
- `Sunset: Wed, 31 Mar 2027 23:59:59 GMT`
- `Link: </docs/API_V1_MIGRATION.md>; rel="deprecation"`

The Sunset date is the v0.10.0 release-engineering placeholder and must be
reconfirmed by T21 before release cut.

## Route Map

| Legacy route | API v1 replacement | Behavior change |
|---|---|---|
| `POST /api/orders` | `POST /api/v1/certificate-intents` then `POST /api/v1/certificate-intents/{id}/issue` | Creation and issuance are split. Mutating calls require `Idempotency-Key`; issuance returns `202` with `Location: /api/v1/operations/{id}`. |
| `GET /api/orders` | `GET /api/v1/operations` | v1 returns durable operation projections with stable status strings, progress, current step, retry time and subject. |
| `GET /api/orders/{id}` | `GET /api/v1/operations/{id}` | v1 operation ids are `op_...`; old in-memory task ids are not stable after restart. |
| `POST /api/orders/renew-all` | `POST /api/v1/certificate-lineages/{id}/renew` per lineage | v1 does not expose fleet-wide renewal from the public API; schedulers create durable renew operations. |
| `GET /api/certificates` | `GET /api/v1/certificate-intents`, `GET /api/v1/certificate-lineages/{id}/versions` | v1 separates desired state (intent), lineage and immutable versions. |
| `GET /api/certificates/{id}` | `GET /api/v1/certificate-versions/{id}` | v1 never serializes private key material. |
| `POST /api/certificates/{id}/renew` | `POST /api/v1/certificate-lineages/{id}/renew` | Renewal is lineage-scoped and returns a durable operation to poll. |
| `POST /api/certificates/{id}/revoke` | `POST /api/v1/certificate-versions/{id}/revoke` | v1 creates a durable revoke operation; success means the CA backend was called and the local version state reached `revoked`. |
| `GET /api/accounts`, `GET/PATCH/DELETE /api/accounts/{id}` | No v1 replacement in T17 | Account lifecycle work is owned by T14; legacy routes remain compatibility-only until that API is finalized. |
| `GET /api/diagnostics` | `GET /ready`, `GET /health`, metrics listener `/metrics` | v1 operational readiness is split between health/readiness and Prometheus metrics. |

## Challenge Status

Operators should use `GET /api/v1/operations/{id}/challenges` or
`acmex status <operation-id>` to inspect authorization/challenge progress.
The challenge view is side-effect free: it returns the last persisted
propagation observation and CA authorization poll instead of querying DNS
providers or the CA from the read path.

## Compatibility Rule

The legacy `/api` surface is frozen and only shrinks. New certificate
lifecycle capabilities must be added under `/api/v1` and documented in
`docs/api/openapi.yaml`.
