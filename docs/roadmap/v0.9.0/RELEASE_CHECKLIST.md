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

- [ ] Pebble HTTP-01 completed.
- [ ] Pebble DNS-01 completed.
- [ ] Pebble TLS-ALPN-01 completed.
- [ ] Restart matrix completed with real T04/T05/T10 executors.
- [ ] File sink stage/activate/health/rollback completed.
- [ ] Required sink failure rollback completed.

## Explicit External Evidence

- [ ] IPv4 HTTP-01 and TLS-ALPN-01 validated.
- [ ] IPv6 HTTP-01 and TLS-ALPN-01 validated.
- [ ] Let's Encrypt staging smoke completed.
- [ ] At least one live DNS provider zone completed.
- [ ] Redis repository failover scope documented.
- [ ] Kubernetes/Vault/agent sink scope documented.

Any unchecked E2E or external row is not a release pass and must be called out in
release notes.
