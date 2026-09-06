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
