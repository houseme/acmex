# v0.9.0 T12 Validation Evidence

Captured on 2026-09-01 in `/private/tmp/acmex-t12` after rebasing
`houseme/v090-t12-e2e-release-gates` onto `origin/main`.

## Passed Locally

- `cargo fmt --all -- --check`
- `cargo test`
- `cargo clippy --all-features -- -D warnings`
- `git diff --check`
- `scripts/verify_docs_and_openapi.sh`
- `scripts/run_restart_matrix.sh`
- `scripts/run_feature_matrix.sh`
- `scripts/run_performance_baseline.sh`

The full `cargo test` run included current-main T10 contract tests:
`tests/key_provider_test.rs` and `tests/certificate_sink_contract.rs`.

Performance baseline sample:

```text
acmex_perf_host os=Darwin arch=arm64 rust=rustc 1.100.0-nightly (908501772 2026-08-30)
acmex_perf_baseline intents=1000 insert_ms=17 scan_ms=14 backend=memory rust=0.8.0 key_ref_shape=56
```

## Skipped Or Not Yet Validated

- `scripts/run_pebble_e2e.sh` exited 77 because `RUN_PEBBLE_E2E=1` was not set.
  This is not a release pass.
- Pebble HTTP-01, DNS-01, TLS-ALPN-01 were not executed.
- Let's Encrypt staging was not executed.
- Live DNS provider, Redis, Kubernetes, Vault, and remote agent sink E2E were
  not executed.

## Sandbox Note

The first non-escalated `scripts/run_feature_matrix.sh` attempt failed during
`cargo check --all-features` because `aws-lc-fips-sys` tried to write temporary
headers under the Cargo registry source and the sandbox denied that write. The
same script passed after rerunning with filesystem permission for the build
script.
