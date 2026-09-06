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

### 2026-09-06 — dual-process-fencing (two instances, Redis repository)

* **Environment**: local `redis-server` 8.10.1 on `127.0.0.1:6405`, disposable
  DB 15 (`--save ''`, flushed before the run), reached via
  `ACMEX_TEST_REDIS_URL=redis://127.0.0.1:6405/15`. Two "instances" each hold
  their own `RedisRepository` connection (every state transition crosses the
  wire like two separate processes sharing one repository).
* **Command**: `ACMEX_TEST_REDIS_URL=redis://127.0.0.1:6405/15 \
  cargo test --features redis --test dual_instance_fencing_live -- --ignored \
  --nocapture` (`tests/dual_instance_fencing_live.rs`, `#[ignore]`-gated,
  SKIPs without the variable).
* **Scenario 1 (renewal mutual exclusion)**: one tenant seeded with a due
  lineage (issued 80 days ago, expires in 2 days → `LifetimeFraction` window,
  priority `Critical`); both instances scan concurrently via `tokio::join!`.
  Reports: instance-a `operations_created: 0, leases_skipped: 1`, instance-b
  `operations_created: 1` — sum exactly 1. The persisted operation
  (`op_5eca0454…`, kind `Renew`, subject lineage matches) is unique across all
  active statuses when read back through *both* connections.
* **Scenario 2 (lease contention + fencing tokens)**: three rounds of both
  instances acquiring the same `renewal/lineage/<id>` lease: loser always
  `HeldByOther`; after injected expiry the takeover grant draws a strictly
  higher fencing token (1→2, 3→4, 5→6), the stale owner cannot renew, the
  current owner can.
* **Result**: PASS (`test result: ok. 2 passed`). Keys live under the
  `acmex:v1:` prefix with run-unique ids in DB 15. Evidence log:
  `target/live-infra/fencing-final/run.log` (untracked).
* **Bug found and fixed** (separate commit): on a fresh database the renewal
  scan crashed with `redis MGET failed: empty command - Client` —
  `RedisEntityStore::env_list` built a zero-command pipeline when the
  aggregate (here: operations) had no keys, and the redis client rejects
  empty pipelines. Live-exposed; both `env_list` and the identically-shaped
  migration-manifest `entries()` now return early on an empty SCAN result.
  Until this fix, *any* Redis-backed renewal scan on an empty operations
  table failed, which is the default state of a fresh deployment.

