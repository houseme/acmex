# Live Infrastructure Evidence Scope

This document is the executable scope companion for roadmap T20. It does not
claim any live evidence by itself; a skipped or preflight-only run is not a release pass.

## Gate Matrix

| Scenario | Asset contract | Evidence artifact |
|---|---|---|
| dns-cloudflare | `RUN_LIVE_DNS_CLOUDFLARE=1`, `ACMEX_LIVE_DNS_CLOUDFLARE_ZONE`, `ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN` | `live-dns-cloudflare.log` |
| dns-route53 | `RUN_LIVE_DNS_ROUTE53=1`, `ACMEX_LIVE_DNS_ROUTE53_ZONE`, `ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID`, AWS default credentials chain | `live-dns-route53.log` |
| redis | `ACMEX_LIVE_REDIS_URL` plus an operator note describing AOF/RDB and timeout behavior | `redis-repository-contract.log` |
| reference-http-agent | none beyond `RUN_LIVE_INFRA=1`; runs the real `acmex agent serve` child-process contract | `reference-http-agent.log` |
| sink-http-agent | `ACMEX_LIVE_HTTP_AGENT_URL`, `ACMEX_LIVE_HTTP_AGENT_TOKEN_REF` (`env:`/`file:` SecretRef) | `sink-http-agent.log` |
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

### 2026-09-07 — notifications-smtp (email delivery, local SMTP relay)

* **Environment**: `axllent/mailpit` container on `127.0.0.1:1025` (SMTP) /
  `127.0.0.1:1825` (REST API), SMTP AUTH PLAIN enabled via an auth file with
  throwaway credentials (password passed to AcmeX only through an `env:`
  SecretRef; never recorded here). Run executed on the main line
  (c167f38) where `src/notifications/email.rs` lives.
* **Command**: `ACMEX_LIVE_SMTP_HOST=… ACMEX_LIVE_SMTP_PORT=… … cargo test
  --test smtp_live -- --ignored --nocapture` (`tests/smtp_live.rs`,
  `#[ignore]`-gated, SKIPs without the variables).
* **Scenario**: real SMTP transaction (AUTH PLAIN → MAIL FROM → RCPT TO →
  DATA) through the production email client, then the mailpit REST API
  observed exactly one message with matching From/To/Subject
  (`id="107f0ysF6VMGNw8fu6Ty8s"`); store cleaned via
  `DELETE /api/v1/messages` with `total == 0` asserted afterwards.
* **Result**: PASS (`test result: ok. 1 passed`). This upgrades the email
  path from fake-SMTP contract evidence to a live relay round-trip,
  including authenticated delivery. Evidence log under
  `/tmp/acmex-mainline-staging` (untracked); the test itself is repeatable
  against any local relay.

### 2026-09-07 — sink-http-agent (reference remote agent, real subprocess)

* **Environment**: the new reference agent `acmex agent serve` (server side
  of the `HttpAgentSink` protocol, in `src/delivery/agent_server.rs`) run as
  a real subprocess spawned by the test via `CARGO_BIN_EXE_acmex` on a
  random 127.0.0.1 port; bearer token passed through an `env:` SecretRef
  (bare-string refs are rejected and redacted in Debug output).
* **Command**: `cargo test --test agent_live` (self-contained, not
  `#[ignore]`-gated: it starts and stops its own agent process).
* **Scenario**: full stage/activate/health/rollback/cleanup contract over
  real HTTP with token auth — stage (201, active untouched), activate
  (204), health `Healthy`, staged-but-not-active reports unhealthy
  ("route exists but is not active"), rollback deactivates, cleanup is
  idempotent (404 → `AlreadyClean`); plus `kill -9` of the agent process
  mid-lifetime with the sink observing `DeploymentHealth::Unknown` (PR
  #208 semantics) instead of a transport error; concurrent activation
  keeps exactly one active version (16-way, unit-tested).
* **Result**: PASS (`test result: ok. 3 passed`), together with the 7
  in-process unit tests (`delivery::agent_server`) and the pre-existing
  fake-agent contract suite (`tests/http_agent_sink_test.rs`, 4 passed).
  This replaces the last "remote agent has only fake evidence" limitation
  with a reproducible real-process run; a production agent with persistent
  state can substitute the reference binary without wire changes.

