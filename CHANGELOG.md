# Changelog

All notable AcmeX changes are recorded here. This project is still in the
0.x line: minor versions may include behavior changes, and every release note
must call out any unverified external evidence.

## Unreleased

### Added

- Release engineering baseline for the v0.9.0/v0.10.0 closeout: release notes,
  migration guides, release decision record, and a semver compatibility gate.
- CLI `order list` and `order show` now query durable `/api/v1/operations`
  instead of returning placeholders.
- Durable outbox consumer is now wired into every production runtime
  (`serve`, `daemon`, the embedded API server) behind an `[outbox]` config
  section; `[notifications.webhooks]` entries are mapped onto the outbound
  delivery with an optional outbox event-type filter (`events`).
- Redis aggregate repository (behind the existing `redis` feature): all nine
  aggregates with Lua-script atomic CAS, cross-process leases with fencing
  tokens, and outbox retry/dead-letter semantics. Selectable via
  `repository.backend = "redis"` with `[repository.redis] url`.
- Kubernetes Secret and Vault KV v2 certificate sinks, registered from
  `[delivery.kubernetes]` / `[delivery.vault]` settings; credentials are
  SecretRef-only and tokens are resolved per request.
- Local multi-route TLS-ALPN-01 edge listener (SNI routing, RFC 8737 ALPN
  enforcement) assembled into the production worker from
  `[challenge.tls_alpn].listen_addr`; the previous single-authorization
  limitation and the rustls critical-extension rejection of validation
  certificates are fixed.
- Explicitly confirmed key destruction (`KeyProvider::destroy_confirmed`);
  the conservative `destroy` remains as the safe default.
- `[[example]] intent_issuance` demonstrates the durable workflow offline,
  and `renewal_controller` replaces the deprecated scheduler example.

### Changed

- The legacy account API now serves real account records: create passes
  contacts into the ACME registration, and read/update/deactivate round-trip
  to the CA and persist `AccountRecord`s instead of returning hardcoded
  values.

### Fixed

- Issuance spine test fixtures now include the optional verification report
  field introduced by the v0.10 certificate verification model.
- Deployment rollback failures now retry with backoff before becoming
  terminal, and cleanup failures retry in place; neither silently reports
  success.
- Route53 `verify_record` queries the hosted zone (quoted-string and
  split-char TXT values handled) instead of always reporting verified.

## 0.10.0 - pending external evidence

### Added

- Pebble E2E harness structure and CI entrypoint for gated L4 runs.
- External Account Binding via SecretRef-backed HMAC keys and account
  key-change support.
- Certificate verification reports persisted on certificate versions, including
  chain trust, identifier capability, profile, key consistency and OCSP status.
- Stable DNS propagation configuration through `[dns.propagation]` and
  per-provider overrides.
- API v1 contract closeout: intent PATCH, challenge observation resources,
  challenge cleanup retry resources, and legacy API deprecation headers.
- Repository error metrics, workflow trace fields, webhook replay-window
  validation and observability assets.
- Live evidence scripts for Let's Encrypt staging and infrastructure gates.

### Changed

- v0.10.0 is the preferred release target if T13/T19/T20 evidence lands as one
  contiguous validation wave; a separate 0.9.0 release is retained only if the
  Pebble gate completes much earlier than the live external gates.
- Legacy `/api` remains compatibility-only and advertises a Sunset date of
  `Wed, 31 Mar 2027 23:59:59 GMT`.

### Not Yet Release-Validated

- Pebble HTTP-01, DNS-01, TLS-ALPN-01, renewal, revocation and real executor
  restart evidence still require an executed Docker-backed L4 run.
- Let's Encrypt staging, ARI `replaces`, profile behavior and IP identifier
  behavior still require live CA evidence.
- Live DNS provider zones, Redis, Kubernetes, Vault, remote agent and dual
  instance fencing still require L4/L5 evidence.
- Performance baseline must be rerun on the declared release reference host.

## 0.9.0 - pending release decision

### Added

- Durable domain model for identifiers, certificate intents, lineages,
  immutable versions, operations, workflow steps and challenge leases.
- Repository abstraction with file-backed persistence and migration scaffolding.
- Durable workflow engine with restartable operation state.
- Application service and `/api/v1` lifecycle resource model.
- Renewal controller, deployment orchestration, key provider and sink
  abstractions.
- Security, observability and HA baseline: SecretRef, hashed API keys, audit
  events, metrics assets and release gate inventory.

### Changed

- Legacy in-memory order/task flows are no longer the product direction; new
  lifecycle operations use durable API v1 resources.

### Not Yet Release-Validated

- v0.9.0 remains unpublished until the required local, E2E and explicit
  external evidence rows in `docs/roadmap/v0.9.0/RELEASE_CHECKLIST.md` are
  checked with reproducible artifacts.
