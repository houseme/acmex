# v0.9.0 Known Limitations

These limitations are intentionally explicit so T12 cannot turn unrun external
tests into implied success.

- Pebble: the gated harness (`tests/live_pebble_e2e.rs` +
  `scripts/docker-compose.pebble.yml`, driven by `scripts/run_pebble_e2e.sh`)
  executed green repeatedly on 2026-09-06/07: HTTP-01, DNS-01, TLS-ALPN-01,
  renewal, revocation, real-executor restart and failure-rollback scenarios
  all passed against a real Pebble CA (latest runs archive under
  `target/pebble-e2e/`; see `VALIDATION_EVIDENCE.md`, 2026-09-07 section,
  including one archived transient 2/6 failure followed by two consecutive
  6/6 greens). The harness pins the VA to always-valid for the test domain
  because recent Pebble validates every offered challenge, including draft
  types AcmeX does not implement; DNS-01 evidence additionally includes a
  live VA run without that override.
- Let's Encrypt staging is not yet validated.
- Live DNS providers are compile-gated only unless a provider contract run is
  supplied from an isolated zone.
- Kubernetes Secret and Vault KV v2 sinks have live L5 contract evidence
  (2026-09-06 native cluster/dev server; 2026-09-07 containerized
  reproducibility), and the Redis aggregate repository contract suite ran
  against a live Redis server on 2026-09-07 with a documented failover scope
  (`LIVE_INFRASTRUCTURE_EVIDENCE.md`). The remote HTTP agent sink now has a
  real-subprocess live run against the reference agent (`tests/agent_live.rs`,
  2026-09-07); a production agent with persistent/multi-instance state has
  not been exercised.
- The AWS KMS key provider (`kms-aws`) is contract-tested against a mock
  KMS endpoint; live AWS KMS/IAM behavior (real policies, throttling,
  multi-region keys) is not yet validated. SMTP email delivery is
  contract-tested against a fake SMTP server and now has a live local-relay
  round-trip (2026-09-07 entry in LIVE_INFRASTRUCTURE_EVIDENCE.md); external
  provider behavior (managed SMTP services) is not yet validated.
- The offline restart matrix still uses fake idempotent external effects;
  real-executor restart evidence is now provided by the Pebble gate's
  three-window resume scenario (2026-09-06/07), so the fake matrix is
  regression support rather than the sole restart evidence.
- IPv4 and IPv6 identifier behavior is covered by domain policy tests, and
  the local Pebble gate now collects real RFC 8738 IPv4 evidence: two
  consecutive 9/9 greens on 2026-09-07 (UTC) added IPv4 HTTP-01 (challtestsrv
  static address), IPv4 TLS-ALPN-01 (served by acmex's production
  `LocalTlsListener`, since challtestsrv cannot mint the iPAddress-SAN
  validation certificate Pebble requires) and IPv6 HTTP-01 (challtestsrv
  static IPv6 over an `enable_ipv6` bridge; verified on OrbStack/docker
  29.4.0) — see `VALIDATION_EVIDENCE.md`, 2026-09-07/08 section. External CA
  behavior for IP identifiers is not yet validated: IPv4/IPv6 issuance
  against a public or staging CA remains outstanding, and no IPv6 TLS-ALPN-01
  scenario exists yet (only IPv6 HTTP-01).
