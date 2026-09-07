# v0.9.0 E2E Release Gates

T12 establishes the release-gate harness. The current branch adds repeatable
L2/L3 checks and scripts for L4/L5, but Pebble and external provider runs are
not a release pass until executed in an environment with those services.

## Local Gates

- `scripts/run_feature_matrix.sh`
- `scripts/run_restart_matrix.sh`
- `scripts/verify_docs_and_openapi.sh`
- `scripts/run_performance_baseline.sh`

These gates are local and deterministic except the ignored performance baseline,
which prints measured numbers for the host where it runs.

## Restart Matrix

`tests/e2e_restart_matrix.rs` covers every current issuance spine step in three
restart windows:

- before the external call starts;
- after the external effect succeeds but before the repository save;
- after the repository save before the next process resumes.

The second window uses an idempotent fake external ledger to prove that a
retried in-flight step does not create duplicate logical resources.

## Fault Injection

`tests/fault_injection_matrix.rs` covers representative CA rate limiting,
challenge cleanup retry, and authorization invalid paths over in-memory
repositories and fake executors.

## T10 Key And Sink Boundary

Current `origin/main` includes `src/key`, `src/delivery`,
`tests/key_provider_test.rs`, and `tests/certificate_sink_contract.rs`. Those
are local contract gates for managed keys, external CSR validation, File Sink,
and a fake agent sink. `tests/http_agent_sink_test.rs` (PR #206) additionally covers the HTTP agent
sink against a live local fake agent. These are not yet live L4/L5 deployment
evidence.

## L4/L5 Gates

`scripts/run_pebble_e2e.sh` is intentionally environment-gated. Without
`RUN_PEBBLE_E2E=1` and a prepared Pebble/challenge-test-server environment it
exits with code 77 and prints a skip reason. A skipped run is not a release pass.

**Update (2026-09-02)**: the Pebble gate is now a real harness. The script
brings up pebble + challtestsrv via `scripts/docker-compose.pebble.yml` (pebble
resolves through challtestsrv's DNS) and runs
`tests/live_pebble_e2e.rs` — the full production executor set
(`server::worker::register_executors`) over real HTTPS (TLS verification
disabled; Pebble's certificate is invalid by design), with DNS-01, HTTP-01
and TLS-ALPN-01 programmed through the challtestsrv admin API, driving
intent → order → challenge → CSR → finalize → download → strict verification
→ File sink deploy → activation. The DNS-01 lifecycle scenario also covers
renewal replacement and CA revocation. First executed green on 2026-09-06 and re-executed on 2026-09-07: the
2026-09-07 evidence pass recorded two consecutive 6/6 greens (all scenarios)
after one archived transient 2/6 failure; see `VALIDATION_EVIDENCE.md`
(2026-09-07 section). The terminal `VALIDATION_CHALLENGE_INCOMPATIBLE` error
now records per-challenge status and the CA problem summary, so any
recurrence is directly diagnosable. Artifacts: `target/pebble-e2e/<ts>/`.

**Update (2026-09-07/08)**: the harness now covers RFC 8738 IP identifiers
(scenario count 6 → 9). For IP identifiers Pebble's VA dials the identifier
address:port directly (no DNS), so the new scenarios are:

- `pebble_full_issuance_ip_http01` — IPv4 identifier = challtestsrv's static
  address (`ACMEX_CHALLTESTSRV_IPV4`, default 10.30.50.3); challtestsrv
  answers HTTP-01 token-keyed on its own address.
- `pebble_full_issuance_ip_tlsalpn01` — IPv4 identifier with TLS-ALPN-01.
  challtestsrv only mints dNSName-SAN certificates, which Pebble correctly
  rejects for IP identifiers (RFC 8737 requires exactly one iPAddress SAN
  under the `in-addr.arpa` SNI), so this scenario is served by acmex's own
  production `LocalTlsListener` + `TlsAlpn01Presenter` — the same edge the
  worker assembly binds — over an address routable from pebble's container
  (`PEBBLE_E2E_HOST_IPV4`).
- `pebble_full_issuance_ip_http01_v6` — IPv6 identifier = challtestsrv's
  static IPv6 (`ACMEX_CHALLTESTSRV_IPV6`); the compose network enables IPv6
  with a ULA subnet. Requires a runtime that honours `enable_ipv6` with
  static container addresses (verified on the local OrbStack/docker 29.4.0
  host); absent that support the scenario fails rather than fakes success.

Supporting changes: the compose file gained a fixed project name
(`acmex-pebble-e2e`) and overridable host ports/subnets so coexisting local
stacks do not collide; `AcmeCaBackend::with_identifier_types` declares
identifier types the ACME directory cannot advertise (previously the
pre-order capability gate rejected every IP order for real CAs). Two
consecutive 9/9 greens recorded 2026-09-07 UTC; see `VALIDATION_EVIDENCE.md`
(2026-09-07/08 section). These are local Pebble (RFC 8738) evidence only —
external CA IP validation is still not a release pass.

Successful runs archive `environment.txt`, `cargo-test-live-pebble-e2e.log`,
and `compose.log` under `target/pebble-e2e/<timestamp>/`; CI uploads the
`target/pebble-e2e` tree as the `pebble-e2e-evidence` artifact.
