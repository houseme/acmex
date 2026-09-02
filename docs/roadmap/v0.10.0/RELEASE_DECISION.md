# v0.9.0 / v0.10.0 Release Decision

**Date**: 2026-09-02  
**Status**: provisional; pending external evidence; do not tag or publish yet  
**Decision owner**: release maintainer

## Decision

Prefer a single v0.10.0 release once T13, T19 and T20 all have reproducible
evidence. Keep the option to cut v0.9.0 first only if the Pebble L4 gate is
green substantially earlier than the live CA and live infrastructure gates.

This decision record is not a release pass; it exists to prevent unrun L4/L5
gates from being treated as completed release evidence.

## Rationale

- The v0.9.0 code line establishes the durable lifecycle architecture, but its
  public release checklist still has unchecked E2E and external evidence rows.
- The v0.10.0 line removes the remaining code-level stubs and adds the evidence
  harnesses needed to make those architecture claims credible.
- Cutting two close releases without independent user value would increase
  support and migration burden.
- The project is still in the 0.x series, so a single minor release can carry
  the lifecycle model and the closeout work as long as release notes explicitly
  describe the behavioral changes.

## Release Blockers

- T13 Pebble HTTP-01, DNS-01, TLS-ALPN-01, renewal, revocation and restart
  evidence must be executed and archived.
- T19 Let's Encrypt staging evidence must be executed and archived.
- T20 live DNS, Redis, Kubernetes, Vault, remote agent and dual-instance
  fencing evidence must be executed and archived.
- `scripts/run_performance_baseline.sh` must be rerun on the declared release
  reference platform and recorded.
- The semver compatibility gate must pass or have an explicit release-manager
  waiver.

## Legacy API Sunset

The current legacy API Sunset date is formalized as
`Wed, 31 Mar 2027 23:59:59 GMT`. It is intentionally later than the planned
0.10.0 cut to give operators at least one release cycle to migrate from
legacy `/api` to `/api/v1`.

## Follow-Up At Release Cut

- If v0.9.0 is skipped, mark the v0.9.0 roadmap as merged into v0.10.0 and keep
  v0.9.0 release notes as historical architecture notes.
- If v0.9.0 is cut first, remove the v0.9.0 "not cut" status and keep all
  remaining T19/T20 limits in v0.10.0 release notes.
- Bump `Cargo.toml`, create the tag, publish artifacts and update README only
  after the blockers above are closed.
