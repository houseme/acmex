# AcmeX v0.9.0 Release Notes

**Release date**: not cut  
**Status**: pending release decision  
**Package version**: `Cargo.toml` remains `0.8.0` until release gates pass

## Overview

v0.9.0 is the architecture release line. It moves AcmeX from mostly
request-scoped ACME operations toward a durable certificate lifecycle control
plane: intent, lineage, version, operation, workflow step, challenge lease,
repository, renewal and deployment are represented as explicit domain objects.

The code for this line has been merged to `main`, but the version is not a
release pass. The required E2E and external evidence rows remain unchecked.

## User-Visible Changes

- New `/api/v1` lifecycle resources separate desired state from execution:
  certificate intents describe what should exist, while operations expose
  restartable issuance, renewal, deployment and revocation progress.
- Legacy `/api` routes are compatibility-only. They carry `Deprecation: true`,
  `Sunset: Wed, 31 Mar 2027 23:59:59 GMT`, and a link to
  `docs/API_V1_MIGRATION.md`.
- Repository-backed operation state survives process restarts instead of
  relying on transient in-memory task records.
- Certificate versions are immutable and do not serialize private key material.
- Renewal, deployment, audit and metrics are modeled as first-class control
  plane behaviors instead of ad hoc side effects.

## Operator Notes

- Configure management API keys with `ACMEX_API_KEYS`; the example
  configuration intentionally does not ship a default secret.
- Use `acmex init` to scaffold repository, certificate and secret directories.
- Use API v1 operation ids (`op_...`) for polling and CLI inspection.
- Keep real DNS, EAB, webhook and sink credentials behind SecretRef values such
  as `env:NAME` or `file:path`.

## Not Yet Release-Validated

- Pebble HTTP-01, DNS-01 and TLS-ALPN-01 evidence has not been executed green.
- Restart recovery with real T04/T05/T10 executors has not been executed green.
- File sink stage/activate/health/rollback and required failure rollback need
  attached release artifacts.
- IPv4/IPv6 external CA behavior, Let's Encrypt staging, live DNS providers,
  Redis failover scope and Kubernetes/Vault/agent sink scope are not yet
  validated as release evidence.

## Validation Required Before Tagging

Run and attach the complete checklist from
`docs/roadmap/v0.9.0/RELEASE_CHECKLIST.md`. Any unchecked row must stay visible
in these release notes.
