# v0.9.0 Release Checklist

Unchecked items block the v0.9.0 release.

## Required Local Evidence

- [ ] `cargo fmt --all --check`
- [ ] `cargo test`
- [ ] `cargo check --all-features`
- [ ] `cargo check --no-default-features`
- [ ] `cargo clippy --all-features -- -D warnings`
- [ ] `git diff --check`
- [ ] `scripts/run_feature_matrix.sh`
- [ ] `scripts/run_restart_matrix.sh`
- [ ] `scripts/verify_docs_and_openapi.sh`

## Required E2E Evidence

- [x] Pebble HTTP-01 completed.
- [x] Pebble DNS-01 completed.
- [x] Pebble TLS-ALPN-01 completed.
- [x] Restart matrix completed with real T04/T05/T10 executors.
- [x] File sink stage/activate/health/rollback completed.
- [x] Required sink failure rollback completed.

## Explicit External Evidence

- [ ] IPv4 HTTP-01 and TLS-ALPN-01 validated. (local Pebble RFC 8738 evidence: see VALIDATION_EVIDENCE 2026-09-07; external CA validation still pending)
- [ ] IPv6 HTTP-01 and TLS-ALPN-01 validated. (local Pebble RFC 8738 evidence: see VALIDATION_EVIDENCE 2026-09-07; external CA validation still pending)
- [ ] Let's Encrypt staging smoke completed.
- [ ] At least one live DNS provider zone completed.
- [x] Redis repository failover scope documented.
- [x] Kubernetes/Vault/agent sink scope documented. (Kubernetes and Vault
      scopes documented 2026-09-06/07; remote HTTP agent live run against the
      reference agent completed 2026-09-07)

Any unchecked E2E or external row is not a release pass and must be called out in
release notes.
