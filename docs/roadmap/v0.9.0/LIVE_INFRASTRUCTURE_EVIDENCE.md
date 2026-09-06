# Live Infrastructure Evidence Scope

This document is the executable scope companion for roadmap T20. It does not
claim any live evidence by itself; a skipped or preflight-only run is not a release pass.

## Gate Matrix

| Scenario | Asset contract | Evidence artifact |
|---|---|---|
| dns-cloudflare | `RUN_LIVE_DNS_CLOUDFLARE=1`, `ACMEX_LIVE_DNS_CLOUDFLARE_ZONE`, `ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN` | `live-dns-cloudflare.log` |
| dns-route53 | `RUN_LIVE_DNS_ROUTE53=1`, `ACMEX_LIVE_DNS_ROUTE53_ZONE`, `ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID`, AWS default credentials chain | `live-dns-route53.log` |
| redis | `ACMEX_LIVE_REDIS_URL` plus an operator note describing AOF/RDB and timeout behavior | `redis-scope.md` |
| sink-http-agent | `ACMEX_LIVE_HTTP_AGENT_URL`, `ACMEX_LIVE_HTTP_AGENT_TOKEN_REF` | `sink-http-agent.log` |
| sink-kubernetes | `ACMEX_LIVE_KUBECONFIG`, `ACMEX_LIVE_K8S_NAMESPACE` | `sink-kubernetes-scope.md` |
| sink-vault | `ACMEX_LIVE_VAULT_ADDR`, `ACMEX_LIVE_VAULT_TOKEN_REF` | `sink-vault-scope.md` |
| dual-process-fencing | `ACMEX_LIVE_FENCING_REPOSITORY`, `ACMEX_LIVE_FENCING_WORKERS=2` | `dual-process-fencing.log` |

## Redis Failover Scope

Redis evidence must separate application semantics from deployment semantics:
CAS conflicts and lease loss are application-level outcomes; durability across
process or node loss depends on the selected Redis persistence mode. The run
notes must state whether AOF, RDB, or managed persistence was active, and must
record which failures require operator replay.

## Sink Scope

Each live sink run records the resource kind, permissions used, stage and
activate behavior, health signal, rollback path, cleanup result, and known
unsupported operations. Tokens and kubeconfigs are references only and must not
be copied into artifacts.

## Recorded Runs

### 2026-09-06 — sink-kubernetes (Kubernetes Secret sink, live cluster)

* **Environment**: OrbStack Kubernetes v1.35.6 (k3s, single node `orbstack`,
  Ready), API server `https://127.0.0.1:26443`. Dedicated namespace
  `acmex-live` with ServiceAccount `acmex-live` and a least-privilege Role
  (`get`/`create`/`update`/`delete`/`patch` on secrets only; `list` verified
  forbidden) bound via RoleBinding. Bearer token issued with
  `kubectl create token acmex-live -n acmex-live --duration=2h` and passed to
  the sink through a `file:` SecretRef; cluster CA extracted from the
  kubeconfig (`certificate-authority-data`, PEM on disk).
* **Command**: `ACMEX_LIVE_K8S_ENDPOINT=... ACMEX_LIVE_K8S_TOKEN=file:... \
  ACMEX_LIVE_K8S_CA=... ACMEX_LIVE_K8S_NAMESPACE=acmex-live \
  cargo test --test k8s_sink_live -- --ignored --nocapture`
  (`tests/k8s_sink_live.rs`, `#[ignore]`-gated, SKIPs without the variables).
* **Scenario**: full five-phase contract on Secret `acmex-live-1788709609` —
  stage (target untouched) → activate (type `kubernetes.io/tls`) → health
  `Healthy` → out-of-band tamper via `kubectl patch` (leaf replaced by the
  previous certificate) → health `Unhealthy("active secret serves a different
  certificate")` → rollback (snapshot restored) → health `Healthy` → cleanup
  `Cleaned`/`AlreadyClean` (idempotent). Every phase cross-checked with
  `kubectl get secret -o json`: leaf SHA-256 `541c77d4…` → `aedd58b8…` →
  (tamper) `541c77d4…` matched the sink's fingerprints exactly.
* **Result**: PASS (`test result: ok. 1 passed`, ~0.5s). The token resolved
  via the `file:` SecretRef path, so the resolved-auth branch is covered too.
  No residue: namespace empty after the run. Evidence log:
  `target/live-infra/k8s-final/{run.log,cluster.txt}` (untracked).
* **Bugs found**: none — `src/delivery/k8s_sink.rs` behaved to contract
  against the real API server without modification.

### 2026-09-06 — sink-vault (Vault KV v2 sink, dev server)

* **Environment**: Vault 1.20.0 (`darwin_arm64`), zip verified against the
  published `vault_1.20.0_SHA256SUMS` (`shasum -a 256 -c` → OK) before
  unpacking. Throwaway in-memory dev server on `127.0.0.1:8210`
  (`vault server -dev -dev-listen-address=127.0.0.1:8210`, disposable root
  token passed via `file:` SecretRef), KV v2 enabled at `acmex-live/`.
* **Command**: `ACMEX_LIVE_VAULT_ENDPOINT=http://127.0.0.1:8210 \
  ACMEX_LIVE_VAULT_TOKEN=file:... ACMEX_LIVE_VAULT_MOUNT=acmex-live \
  cargo test --test vault_sink_live -- --ignored --nocapture`
  (`tests/vault_sink_live.rs`, `#[ignore]`-gated, SKIPs without the variables).
* **Scenario**: full five-phase contract on `acmex-live-1788710039` — stage
  (active path verified 404 by raw `GET /v1/acmex-live/data/...`) → activate
  (raw read: version 1, leaf SHA `188985a5…`) → stage+activate new version
  (CAS base = version observed at stage time; raw read: version 2, leaf SHA
  `88473141…`) → health `Healthy` → out-of-band raw `PUT` of the old
  certificate (version 3) → health `Unhealthy("active vault entry serves a
  different certificate")` → rollback (raw read: version 4 restored the
  stage-time fingerprint via KV v2 history) → health `Healthy` → cleanup
  `Cleaned` (second handle also `Cleaned`: Vault answers 204 for a metadata
  DELETE even when the path is already gone, so `AlreadyClean` is
  unobservable on KV v2 — the raw read 404 proves the slot is absent, which
  satisfies the "absent counts as clean" contract) → metadata hard-delete
  leaves the mount empty.
* **Result**: PASS (`test result: ok. 1 passed`, ~0.6s). Mount verified as
  KV v2 through `GET /v1/sys/mounts/acmex-live` before staging. No residue.
  Evidence log: `target/live-infra/vault-final/run.log` plus the
  server identity record `target/live-infra/vault-20260906-154805/server.txt`
  (untracked).
* **Finding (documented, no behavior change)**: Vault answers `204` for a
  metadata DELETE whether or not the path existed, so
  `VaultKvSink::cleanup` cannot distinguish `Cleaned` from `AlreadyClean` on
  this engine. A read-before-delete fix was tried to restore the stronger
  outcome, but the mock-based wire contract (`tests/remote_sink_contract.rs`)
  pins the protocol to a bare DELETE, so the fix was reverted in favor of
  documenting the limitation in `src/delivery/vault_sink.rs` and asserting
  the observable property (slot really absent, raw 404) in the live test.
  Behavior and protocol are unchanged.
