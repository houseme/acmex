# v0.9.0 Known Limitations

These limitations are intentionally explicit so T12 cannot turn unrun external
tests into implied success.

- Pebble: a real DNS-01 harness now exists (`tests/live_pebble_e2e.rs` +
  `scripts/docker-compose.pebble.yml`, driven by `scripts/run_pebble_e2e.sh`)
  but has NOT been executed in a prepared environment yet; HTTP-01 and
  TLS-ALPN-01 Pebble variants are not implemented. Pebble validation remains
  not-yet-passed until a run is executed and green.
- Let's Encrypt staging is not yet validated.
- Live DNS providers are compile-gated only unless a provider contract run is
  supplied from an isolated zone.
- File Sink and fake agent sink have local contract tests on current main, but
  Redis, Kubernetes, Vault, and remote agent live environments are not yet
  validated as L4/L5 release evidence.
- The current restart matrix uses fake idempotent external effects; it is not a
  release pass for real CA/DNS/sink adapters until those executors are wired in.
- IPv4 and IPv6 compatibility is covered by domain policy tests, but external
  CA behavior for IP identifiers is not yet validated.
