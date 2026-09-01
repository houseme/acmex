# AcmeX E2E Fixtures

This directory holds local-only fixtures for v0.9.0 release gates.

The current branch provides reusable structure and scripts, but it does not
claim Pebble, Let's Encrypt staging, Redis, Kubernetes, Vault, or real DNS
provider E2E success unless the corresponding script prints a completed run.

Expected environment for future L4/L5 runs:

- Pebble or ACME staging directory URL.
- Challenge test server for HTTP-01 and TLS-ALPN-01.
- Isolated DNS zone for DNS-01, preferably under a disposable delegated zone.
- Dedicated repository root under a temporary directory.
- No production CA or production DNS zone for routine CI.
