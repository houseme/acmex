# v0.9.0 Feature Matrix

This matrix is a release-gate inventory, not a claim that every optional
provider has live external validation.

| Feature | Type | CI gate | External evidence |
|---|---|---|---|
| `default` | feature set | `cargo test` and `cargo check` | not required |
| `aws-lc-rs` | crypto backend | default build | not required |
| `ring-crypto` | crypto backend | `cargo check --all-features` | not required |
| `redis` | repository/storage backend | `cargo check --all-features`; `ACMEX_TEST_REDIS_URL=... cargo test --features redis --test repository_redis_contract -- --ignored`; live contract `cargo test --features redis --test repository_redis_live -- --ignored` | local Redis repository contract and live contract passed 2026-09-07 (dual-engine reproducibility); HA/failover mode not yet validated |
| `kms-aws` | key provider backend | `cargo test --features kms-aws --test kms_key_provider_contract` | contract-tested against a mock KMS endpoint; live AWS KMS/IAM not yet validated |
| `google-ca` | CA integration | `cargo check --all-features` | not yet validated against Google staging |
| `zerossl-ca` | CA integration | `cargo check --all-features` | not yet validated against ZeroSSL staging |
| `dns-cloudflare` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-route53` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-digitalocean` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-linode` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-azure` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-google` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-alibaba` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-godaddy` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-tencent` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-huawei` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
| `dns-cloudns` | DNS provider | `cargo check --all-features` | not yet validated against a live zone |
