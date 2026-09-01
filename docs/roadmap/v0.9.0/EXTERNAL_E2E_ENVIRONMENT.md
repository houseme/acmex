# v0.9.0 External E2E Environment

This document preserves provider, webhook, and staging examples without putting
default secrets into `acmex.toml.example`.

## API Credentials

Management endpoints require explicit API keys:

```bash
ACMEX_API_KEYS="local-dev-key,ci-release-gate-key"
```

Do not commit real keys to configuration files or release evidence.

## DNS Provider Shape

Use a disposable delegated zone for DNS-01 release gates. Example shape:

```toml
[challenge.dns01]
propagation_timeout_secs = 300

[[challenge.dns01.providers]]
name = "cloudflare-release-gate"
api_token = "${CF_API_TOKEN}"
zone_id = "${CF_ZONE_ID}"
```

Equivalent live-zone runs are required before marking a DNS provider release
gate as passed. A compile-only provider feature check is not a release pass.

## Webhook Shape

Webhook endpoints are useful for L5 integration, but they should stay out of the
default example because URLs and auth tokens are operational secrets.

```toml
[[notifications.webhooks]]
name = "release-gate"
url = "${ACMEX_RELEASE_WEBHOOK_URL}"
events = ["renewal_success", "renewal_failed", "deployment_failed"]
format = "json"
auth_token = "${ACMEX_RELEASE_WEBHOOK_TOKEN}"
timeout_secs = 30
```

Live webhook delivery is not yet validated on this branch.

## Pebble

`scripts/run_pebble_e2e.sh` expects:

```bash
RUN_PEBBLE_E2E=1
PEBBLE_DIRECTORY_URL="https://127.0.0.1:14000/dir"
```

The script exits 77 when the environment is absent; that skip is not a release
pass.
