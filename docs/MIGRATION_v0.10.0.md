# Migration Guide: v0.9.0 to v0.10.0

**From version**: v0.9.0 lifecycle model  
**To version**: v0.10.0 once released  
**Status**: draft; pending external evidence

## Overview

v0.10.0 keeps the v0.9 domain model stable and closes the remaining runtime,
API, verification, DNS and observability gaps. Most migrations are
configuration and operator-workflow updates rather than storage rewrites.

This guide is not a release pass. It documents the expected migration path
while T13/T19/T20 L4/L5 external evidence is still pending.

## Configuration Changes

### External Account Binding

Use `[ca.eab]` for CAs that require External Account Binding:

```toml
[ca.eab]
key_id = "ca-issued-key-id"
hmac_key = "env:ACMEX_EAB_HMAC"
```

`hmac_key` is a SecretRef. Do not put literal HMAC material in the config.
Older EAB compatibility aliases are read only for transition and should be
removed from managed configurations.

### DNS Propagation

Use `[dns.propagation]` for global DNS-01 observation policy:

```toml
[dns.propagation]
authoritative_quorum = "all"
recursive_resolvers = []
recursive_quorum = 1
max_wait_secs = 300
poll_interval_secs = 5
query_timeout_secs = 5
```

Provider overrides live under `[dns.providers.<id>.propagation]` and use
field-level fallback to the global policy.

### Webhook Replay Window

Webhook consumers validate signatures with a bounded replay window. Configure
the receiver and signing secret through SecretRef-backed webhook settings, and
ensure clocks are synchronized on every receiving host.

### Repository File Durability (`[repository.file]`)

New optional settings control how durably the file repository makes entity
writes (intents, operations, outbox events, leases):

```toml
[repository.file]
path = "/var/lib/acmex/repository"
fsync = "always"            # "always" (default) or "interval"
fsync_interval_ms = 100     # sweep window; only used when fsync = "interval"
```

- `fsync = "always"` (the default) is the behavior of every earlier
  release: every write is fsynced before its atomic rename, so once a write
  returns it survives an abrupt crash (process kill, power loss). **No
  configuration change is required to keep this behavior** — absent keys
  resolve to `always` exactly as before.
- `fsync = "interval"` is an explicit opt-in that weakens durability for
  throughput: writes become visible immediately, but the fsync is performed
  by a background sweeper at most `fsync_interval_ms` later. **Warning: an
  abrupt crash can lose up to one interval window of acknowledged writes.**
  Only choose this for bulk-write workloads (imports, mass issuance) that
  tolerate that window; `fsync_interval_ms` must be at least 1.

Unknown `fsync` values and `fsync_interval_ms = 0` are configuration errors:
startup fails with an explicit message instead of silently degrading
durability.

The `secrets/` directory (ACME account keys) is **never** governed by these
settings. Secret writes always fsync immediately and unconditionally, both in
`always` and in `interval` mode: a lost account key permanently orphans the
ACME account on the CA side, so that latency is never traded away.

## API Changes

- `PATCH /api/v1/certificate-intents/{id}` updates mutable intent fields only:
  `renewal_policy` and `delivery_targets`. Immutable fields fail with a stable
  problem response.
- `GET /api/v1/operations/{id}/challenges` exposes persisted challenge
  observation state without querying the CA or DNS provider from the read path.
- `GET /api/v1/challenge-cleanup` and
  `POST /api/v1/challenge-cleanup/{id}/retry` expose cleanup operations for
  failed challenge leases.
- Certificate version responses may include `verification_report`. Clients
  should ignore unknown fields and treat absent reports as pre-v0.10 data.

## Certificate Verification

Verification reports include chain trust, identifier policy, profile, public
key consistency and OCSP status. A failed check means the certificate should
not be promoted to active/deployed state unless an operator explicitly handles
the failure class.

## CLI Changes

`acmex order list` and `acmex order show` now inspect durable operations via
API v1. Set `ACMEX_API_KEY` or pass `--api-key` for protected servers.

## Compatibility Checklist

- Move EAB settings to `[ca.eab]`.
- Move DNS-01 propagation tuning to `[dns.propagation]` or provider overrides.
- Only opt into `[repository.file].fsync = "interval"` after confirming the
  workload tolerates the documented crash-loss window; keep `always` for
  anything durability-sensitive.
- Update clients to tolerate `verification_report` on certificate versions.
- Update support runbooks to use challenge observation and cleanup APIs.
- Keep legacy `/api` consumers on the documented migration path before
  `Wed, 31 Mar 2027 23:59:59 GMT`.
