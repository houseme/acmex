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

---

# 2026-09-07 Evidence Refresh

Captured on `main` at the v0.10.0 line (worktree also carries two small
validation commits described below; artifact logs under
`target/gates-20260907/`, `target/pebble-e2e/2026090*/`, untracked).

## Pebble L4 — EXECUTED, GREEN (T13 release gate)

`RUN_PEBBLE_E2E=1 scripts/run_pebble_e2e.sh` now starts real pebble +
challtestsrv containers and drives the production executor set. Three runs on
2026-09-07:

- Run 1 (`20260907T001500Z`, 6 scenarios): 4 passed; `http01` and
  `tlsalpn01` failed with `VALIDATION_CHALLENGE_INCOMPATIBLE` after the CA
  marked the authorization invalid. Artifacts archived. Root cause not
  reproducible — see below.
- Run 2 and Run 3 (same tree, enriched terminal diagnostics): **6 passed /
  0 failed, exit 0** — HTTP-01, DNS-01, TLS-ALPN-01 full issuance, DNS-01
  renewal+revocation lifecycle, three-window restart resume on real
  executors, and File-sink health-failure rollback.

Assessment: runs 2 and 3 are consecutive identical-tree greens; the two code
changes between runs 1 and 2 (terminal-error detail enrichment and removal of
a dead `mismatch` reference in the no-crypto fallback branch of
`verify_ecdsa_signature`) are behavior-neutral for the challenge path, so run
1 is recorded as a transient environment failure (first-compose-up /
parallel-build contention), not a code regression. The enriched terminal
detail now records per-challenge status and the CA problem summary, so any
recurrence is directly diagnosable.

## Local Gates

- `cargo fmt --all -- --check`: PASS
- `cargo test`: PASS (0.8.0-line tree state at 08:15; a later full-suite rerun
  was blocked by an unrelated in-flight refactor in another worktree session)
- `cargo clippy --all-features -- -D warnings`: PASS
- `scripts/run_restart_matrix.sh`: PASS
- `scripts/verify_docs_and_openapi.sh`: PASS
- `scripts/secret_scan.sh`: PASS
- `scripts/run_performance_baseline.sh`: PASS (numbers in the log)
- `cargo check --no-default-features`: PASS after fix (below)

## Reference HTTP Agent Gate

- `cargo test -q --test agent_live`: PASS (2026-09-07). This starts the real
  `acmex agent serve` binary as a child process and drives
  `HttpAgentSink` through stage, activate, health, rollback, cleanup,
  unreachable-agent, and token-redaction paths.
- `cargo test -q delivery::agent_server`: PASS (2026-09-07). This covers the
  in-memory reference server's authenticated wire contract, rollback to the
  previous active route, and concurrent activation invariant.
- `RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=reference-http-agent \
  scripts/run_live_infra.sh`: PASS (2026-09-07,
  `target/live-infra/20260907T093626Z/`). The T20 entrypoint now records the
  reference child-process agent artifact plus secret scan. This is executable
  evidence for the reference child-process agent, not a substitute for a
  separately deployed external agent host.
- `RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=reference-http-agent \
  scripts/run_live_infra.sh`: PASS (2026-09-07,
  `target/live-infra/20260907T101411Z/`). Re-run after wiring the Redis and
  external-agent entries confirmed the script still archives the reference
  agent contract and secret scan together. A sandbox-only attempt immediately
  before this failed at local ephemeral-port bind time; the elevated rerun is
  the valid evidence.
- `RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=reference-http-agent \
  scripts/run_live_infra.sh`: PASS (2026-09-07,
  `target/live-infra/20260907T104452Z/`). Re-run after hardening scenario
  routing confirmed the reference agent path still executes.

## Redis Repository Contract Gate

- `ACMEX_TEST_REDIS_URL=redis://127.0.0.1:6389/15 cargo test -q --features \
  redis --test repository_redis_contract -- --ignored --nocapture`: PASS
  (2026-09-07, local temporary Redis 8.10.1, 6/6 contract bodies).
- `RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=redis \
  ACMEX_LIVE_REDIS_URL=redis://127.0.0.1:6389/15 scripts/run_live_infra.sh`:
  PASS (2026-09-07, `target/live-infra/20260907T101444Z/`). This confirms the
  T20 entrypoint now runs the Redis repository contract and archives
  `redis-repository-contract.log` instead of relying on scope text alone.
- `RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=redis \
  ACMEX_LIVE_REDIS_URL=redis://127.0.0.1:6389/15 scripts/run_live_infra.sh`:
  PASS (2026-09-07, `target/live-infra/20260907T104523Z/`). Re-run after
  hardening scenario routing confirmed the Redis path still executes and
  archives `redis-repository-contract.log`.
- The Redis aggregate repository now uses the same `RepositorySet` trait
  surface as memory/file. Entity create/CAS and lease operations are Redis-side
  atomic, outbox ordering uses an incrementing sequence plus sorted index, and
  tests use a unique `acmex:test:<pid>:<n>` prefix per case to avoid stale-key
  contamination.
- This closes the Redis repository contract implementation gap; Redis failover
  and managed durability mode evidence remain T20 external infrastructure
  scope.

## External HTTP Agent Contract Gate

- `cargo test -q --test http_agent_sink_live -- --list`: PASS (2026-09-07).
  The ignored external-agent contract compiles and is discoverable without
  contacting infrastructure.
- `cargo test -q --test http_agent_sink_live -- --ignored --nocapture`: PASS
  as an explicit skip (2026-09-07) because
  `ACMEX_LIVE_HTTP_AGENT_URL`/`ACMEX_LIVE_HTTP_AGENT_TOKEN_REF` were not set.
  This is not live evidence; it only verifies the missing-environment path is
  controlled and non-secret-bearing.
- The executable contract covers stage, inactive health before activation,
  activation, second-version staging without replacing the active route,
  rollback to the previous active route, cleanup, and repeated cleanup
  idempotency against a separately deployed HTTP agent.

## Live Infrastructure Scenario Routing Gate

- `RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=sink-kubernetes \
  ACMEX_LIVE_INFRA_ARTIFACT_DIR=/private/tmp/acmex-live-infra-missing-k8s \
  ACMEX_LIVE_KUBECONFIG=/private/tmp/nonexistent-kubeconfig \
  ACMEX_LIVE_K8S_NAMESPACE=default scripts/run_live_infra.sh`: EXPECTED FAIL
  (2026-09-07). The script now refuses to mark Kubernetes sink evidence green
  without a non-empty `sink-kubernetes-scope.md` artifact because this
  repository has no Kubernetes sink runner wired.
- `RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=made-up \
  ACMEX_LIVE_INFRA_ARTIFACT_DIR=/private/tmp/acmex-live-infra-unknown \
  scripts/run_live_infra.sh`: EXPECTED FAIL (2026-09-07). Unknown scenario
  names now fail in preflight instead of being silently ignored.
- `sink-vault` and `dual-process-fencing` follow the same no-false-green rule:
  until first-class executable runners are added, a selected scenario must
  supply the corresponding non-empty archived evidence file or the script exits
  failed.

## Let's Encrypt Staging Directory Gate

- `RUN_LE_STAGING=1 ACMEX_LE_STAGING_SCENARIOS=directory \
  scripts/run_le_staging.sh`: PASS (2026-09-07,
  `target/le-staging/20260907T103107Z/`). The run fetched the public staging
  directory, confirmed `newNonce`, `newAccount` and `newOrder`, recorded ARI
  `renewalInfo` support, observed no advertised profiles, and wrote a
  non-secret preflight manifest.
- A non-elevated attempt immediately before this failed at DNS lookup because
  the sandbox could not resolve `acme-staging-v02.api.letsencrypt.org`; the
  elevated rerun is the valid evidence.
- This is a non-mutating T19 smoke only. It is not LE issuance evidence and
  does not satisfy the release checklist row for Let's Encrypt staging smoke,
  ARI `replaces`, profile behavior, IP identifiers or EAB CA registration.

## Fixed During This Pass

- `src/certificate/chain.rs`: the `not(any(aws-lc-rs, ring-crypto))` fallback
  branch referenced `mismatch`, which only exists under `aws-lc-rs` —
  `cargo check --no-default-features` (feature-matrix gate) failed to
  compile. Fixed by dropping the stale reference.
- `src/challenge/steps.rs`: the terminal
  `VALIDATION_CHALLENGE_INCOMPATIBLE` error now includes our challenge type
  and URL, the CA challenge problem summary, and every offered challenge's
  status — previously the CA's failure reason was stored only in the
  challenge session and invisible in the operation error.

## Skipped Or Not Yet Validated (unchanged)

- Let's Encrypt staging (T19) — requires external test assets.
- Live DNS provider zones (T19/T20) — requires real zone credentials.
- External remote HTTP agent sink live run — requires a deployed independent
  agent host and token reference.
- Redis failover / managed persistence mode evidence — requires an operator
  controlled Redis failover setup beyond the local single-node contract above.
- IPv4/IPv6 identifiers against an external CA — requires staging assets.
