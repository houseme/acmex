# v0.9.0 Known Limitations

These limitations are intentionally explicit so T12 cannot turn unrun external
tests into implied success.

- Pebble: a real gated harness exists (`tests/live_pebble_e2e.rs` +
  `scripts/docker-compose.pebble.yml`, driven by `scripts/run_pebble_e2e.sh`)
  and has green 2026-09-07 L4 evidence for HTTP-01, DNS-01, TLS-ALPN-01,
  renewal, revocation, restart and failure rollback.
- Let's Encrypt staging is not yet validated.
- Live DNS providers are compile-gated only unless a provider contract run is
  supplied from an isolated zone.
- File Sink and fake agent sink have local contract tests on current main, but
  external remote HTTP agent live evidence still requires a separately deployed
  agent host and token SecretRef.
- Redis repository single-node live contract, Kubernetes/Vault scope evidence,
  reference HTTP agent child-process contract and dual-process fencing now have
  2026-09-06/07 evidence. Redis managed failover and durability behavior remain
  operator-environment evidence, not a property of the local single-node run.
- The current restart matrix and Pebble restart windows do not replace real
  CA/DNS/sink adapter execution where those adapters have separate live gates.
- IPv4 and IPv6 compatibility is covered by domain policy tests, but external
  CA behavior for IP identifiers is not yet validated.
