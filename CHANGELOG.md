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

### Fixed

- Issuance spine test fixtures now include the optional verification report
  field introduced by the v0.10 certificate verification model.

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
