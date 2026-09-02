# AcmeX v0.10.0 Release Notes

**Release date**: not cut  
**Status**: pending T13/T19/T20 external evidence  
**Package version**: `Cargo.toml` remains `0.8.0` until release gates pass

## Overview

v0.10.0 is the evidence and closeout line for the v0.9 lifecycle control
plane. It removes the remaining code-level stubs, adds the missing API and
configuration surfaces, and prepares the project to cut a release only after
reproducible L4/L5 evidence exists.

## Added

- SecretRef-backed External Account Binding and account key rollover.
- Certificate verification reports persisted with certificate versions.
- Configurable DNS propagation policy through `[dns.propagation]` plus
  provider-level overrides.
- API v1 PATCH for certificate intents, challenge observation resources and
  challenge cleanup retry resources.
- Repository error metrics, expanded workflow spans, webhook signature replay
  windows and release observability assets.
- Release engineering documents for 0.8 to 0.10 migration, release decision
  recording, changelog maintenance and semver checking.

## Changed

- CLI order inspection now reads durable `/api/v1/operations`.
- Legacy `/api` has a documented migration path and only shrinks from here.
- The preferred release plan is to cut one v0.10.0 release once the Pebble,
  live CA and live infrastructure evidence lands together. A separate v0.9.0
  release remains available only if the Pebble evidence is ready materially
  earlier than T19/T20.

## Not Yet Release-Validated

- T13: Pebble L4 evidence for HTTP-01, DNS-01, TLS-ALPN-01, renewal,
  revocation and real executor restart runs is still pending.
- T19: Let's Encrypt staging, ARI `replaces`, profile behavior and IP
  identifier behavior are still pending.
- T20: live DNS zones, Redis, Kubernetes, Vault, remote agent and dual-instance
  fencing evidence are still pending.
- T21: performance baseline rerun, version bump, tag, GitHub release and
  crates.io publish are intentionally not performed until the evidence above
  exists.

## Validation Required Before Tagging

Run the full local release gate, semver gate, Pebble gate, Let's Encrypt
staging gate, live infrastructure gate, secret scan and performance baseline.
Attach raw artifacts or CI links to the roadmap evidence files before tagging.
