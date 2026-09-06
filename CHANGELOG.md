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
- Account keys support ES256/ES384/ES512 and RS256: every JWS path (account
  registration, lookup, contact updates, deactivation, key rollover, EAB
  inner JWS, order and revocation calls) now derives its algorithm and JWK
  from the actual key. New keys default to Ed25519 unchanged; opt in via
  `[ca] account_key_type`. This also fixes a latent bug where the generated
  account key was P-256 but was signed and labeled as Ed25519, which every
  real CA would have rejected.
- AWS KMS key provider behind the new `kms-aws` feature (`[key]
  backend = "kms-aws"`): managed keys are created as KMS-held asymmetric
  keys and CSRs are signed remotely via the KMS Sign API — private key
  material never leaves the service and `export` is always `None`.
- External CSR issuance end to end: intents created with
  `key.mode = "external-csr"` now require and use a caller-supplied CSR
  (`external_csr` on intent creation or issue), validated for signature and
  exact identifier match. AcmeX never generates, imports, or persists a
  private key on this path; declaring external CSR previously fell back
  silently to a managed key.
- SMTP email delivery: `[[notifications.email]]` now actually delivers
  outbox events (implicit TLS, STARTTLS or explicit plaintext) with
  per-channel error aggregation alongside webhooks.
- Performance: repository reads avoid deep JSON copies (`Arc<Value>`
  envelopes with borrowed deserialization), the file repository caches
  parsed entities behind stat validation, the legacy Redis storage uses
  `SCAN` plus a reused connection manager, and the release profile enables
  thin LTO. 5 000-intent scans drop from ~21 ms to ~3 ms (memory) and from
  ~108 ms to ~46 ms warm (file) in release builds.

### Changed

- The legacy account API now serves real account records: create passes
  contacts into the ACME registration, and read/update/deactivate round-trip
  to the CA and persist `AccountRecord`s instead of returning hardcoded
  values.
- Deployment health `Unknown` (sink unreachable) no longer triggers
  rollback — only verified `Unhealthy` does; sink `activate` verifies the
  staging fingerprint before promotion, and in-flight deployments recover
  automatically after a crash instead of stalling forever.

### Removed

- The no-op `metrics` and `cli` Cargo features. Neither gated any code —
  `prometheus` and `clap` are unconditional dependencies — so enabling them
  produced builds identical to the defaults. Users passing these flags can
  simply drop them. Recorded as a minor-version change per 0.x semantics.
- The never-consumed `[renewal.hooks]` configuration (`RenewalHooks`);
  existing configs with that section still parse and the section is now
  ignored.

### Fixed

- **JWS bodies now use the RFC 8555 §6.2 flattened JSON serialization.** The
  signer previously emitted the compact `a.b.c` serialization as the POST
  body, which real ACME servers reject — this is the fix that makes ACME
  issuance against a live CA possible end to end (proven by the now-green
  Pebble L4 gate).
- Certificate chain verification supports ECDSA (P-256/384/521) signatures
  via aws-lc-rs or ring, in addition to RSA; Pebble and Let's Encrypt issue
  ECDSA chains by default.
- Challenge acknowledgement tolerates challenges the CA already validated
  (proactive validation), and unknown challenge types advertised by a CA no
  longer break authorization parsing.
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
