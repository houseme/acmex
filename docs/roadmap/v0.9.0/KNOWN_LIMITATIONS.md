# v0.9.0 Known Limitations

These limitations are intentionally explicit so T12 cannot turn unrun external
tests into implied success.

- Pebble HTTP-01, DNS-01, and TLS-ALPN-01 are not yet validated on this branch.
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
