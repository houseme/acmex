# Migration Guide: v0.8.0 to v0.9.0

**From version**: 0.8.x  
**To version**: 0.9.0 once released  
**Status**: draft for the pending v0.9/v0.10 release decision; pending external evidence

## Overview

v0.9.0 introduces the durable lifecycle control plane. The main migration is
from legacy order/task endpoints and transient task state to API v1 intents,
operations, lineages and immutable certificate versions.

This document describes the migration shape only. It is not a release pass, and
it does not imply unrun L4/L5 external gates have passed.

## API Migration

Legacy `/api` remains available during the compatibility window, but every
legacy response carries `Deprecation: true` and
`Sunset: Wed, 31 Mar 2027 23:59:59 GMT`. New integrations should move to
`/api/v1`; the legacy surface only shrinks.

| Legacy route | v0.9+ route | Required change |
|---|---|---|
| `POST /api/orders` | `POST /api/v1/certificate-intents` then `POST /api/v1/certificate-intents/{id}/issue` | Split desired-state creation from issuance execution. Store the returned intent id and operation id separately. |
| `GET /api/orders` | `GET /api/v1/operations` | Read durable operation projections instead of transient task records. |
| `GET /api/orders/{id}` | `GET /api/v1/operations/{id}` | Poll `op_...` ids returned by mutating v1 calls. |
| `POST /api/certificates/{id}/renew` | `POST /api/v1/certificate-lineages/{id}/renew` | Renew by lineage id. |
| `POST /api/certificates/{id}/revoke` | `POST /api/v1/certificate-versions/{id}/revoke` | Revoke an immutable certificate version and poll the returned operation. |
| `GET /api/diagnostics` | `/health`, `/ready`, metrics listener `/metrics` | Split liveness, readiness and Prometheus scraping. |

Mutating API v1 calls require `Idempotency-Key` where documented in
`docs/api/openapi.yaml`.

## Domain And Storage Model

- Replace direct assumptions about `CertificateBundle` with the new
  lineage/version model. A lineage represents continuity; a version is an
  immutable issued certificate.
- Private keys are referenced through key locators or SecretRef-backed stores
  and are not serialized through certificate version API responses.
- Operations are durable records. Persist operation ids in clients and
  automation instead of inferring state from one HTTP request.

## Configuration

Start from `acmex init` or `acmex.toml.example`.

- Set `[repository]` for durable lifecycle state. The file backend uses
  `.acmex/repository` in the example configuration.
- Configure management API credentials through `ACMEX_API_KEYS`; do not add a
  literal API key to configuration files.
- Use `[metrics]` to enable the Prometheus listener. The default example binds
  to `127.0.0.1:9090`.
- Keep DNS, webhook, EAB and sink credentials as SecretRef values such as
  `env:NAME` or `file:path`.

## CLI Changes

- `acmex init` creates the local repository, certificate and secret directory
  structure and verifies that the generated configuration parses.
- `acmex obtain --wait` follows durable operation progress rather than treating
  request acceptance as issuance success.
- `acmex order list` and `acmex order show <id>` query API v1 operations. Use
  `--api-base` to target a non-default server and `--api-key` or
  `ACMEX_API_KEY` for authentication.

## Compatibility Checklist

- Update automation to store API v1 operation ids.
- Replace legacy certificate ids with lineage or version ids depending on the
  action.
- Add explicit `Idempotency-Key` values to mutating v1 calls.
- Confirm readiness, metrics and audit collection in staging before production
  rollout.
