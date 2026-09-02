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
