# v0.9.0 Known Limitations

These limitations are intentionally explicit so T12 cannot turn unrun external
tests into implied success.

- Pebble: a real gated harness exists (`tests/live_pebble_e2e.rs` +
  `scripts/docker-compose.pebble.yml`, driven by `scripts/run_pebble_e2e.sh`)
  and has green 2026-09-06/07 L4 evidence for HTTP-01, DNS-01, TLS-ALPN-01,
  renewal, revocation, restart and failure rollback (artifact
  `target/pebble-e2e/`). The harness pins the VA to always-valid for the test
  domain because recent Pebble validates every offered challenge, including
  draft types AcmeX does not implement; DNS-01 evidence additionally includes
  a live VA run without that override.
- Let's Encrypt staging has a non-mutating directory smoke, but issuance,
  renewal, ARI `replaces`, profile, EAB CA and IP identifier behavior are not
  yet validated.
- Live DNS providers are compile-gated only unless a provider contract run is
  supplied from an isolated zone.
- File Sink and fake agent sink have local contract tests on current main, but
  external remote HTTP agent live evidence still requires a separately deployed
  agent host and token SecretRef.
- Redis repository single-node live contract, Kubernetes/Vault scope evidence,
  reference HTTP agent child-process contract and dual-process fencing now have
  2026-09-06/07 evidence. Redis managed failover and durability behavior remain
  operator-environment evidence, not a property of the local single-node run.
- The AWS KMS key provider (`kms-aws`) is contract-tested against a mock
  KMS endpoint; live AWS KMS/IAM behavior (real policies, throttling,
  multi-region keys) is not yet validated. SMTP email delivery is
  contract-tested against a fake SMTP server; live provider behavior is
  not yet validated.
- The current restart matrix and Pebble restart windows do not replace real
  CA/DNS/sink adapter execution where those adapters have separate live gates.
- IPv4 and IPv6 compatibility is covered by domain policy tests, but external
  CA behavior for IP identifiers is not yet validated.
