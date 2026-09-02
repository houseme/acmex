//! Real DNS provider contract tests (roadmap T06 residual) — `#[ignore]`
//! gated because they talk to a live provider and mutate a real zone.
//!
//! Configuration (all via environment):
//!
//! ```text
//! ACMEX_LIVE_DNS_TYPE=cloudflare          # provider type (cargo feature must be enabled)
//! ACMEX_LIVE_DNS_ZONE=example.com         # a zone you control (TEST zone!)
//! ACMEX_LIVE_DNS_TOKEN=...                # provider API token
//! ACMEX_LIVE_DNS_EXTRA_hosted_zone_id=... # provider-specific `extra` entries
//! ```
//!
//! Run: `cargo test --test dns_provider_live -- --ignored`
//! Every `extra.<key>` the provider factory needs is read from
//! `ACMEX_LIVE_DNS_EXTRA_<key>`; values that look like `env:`/`file:`
//! references are resolved as SecretRefs (the factory convention), plain
//! values pass through as non-secret extras.

use acmex::dns::factory::{DefaultDnsProviderFactory, DnsProviderFactory};
use acmex::dns::record::{PresentTxt, RecordCleanupOutcome};
use acmex::dns::spec::{DnsProviderSpec, EnvFileSecretResolver, SecretRef};
use std::collections::HashMap;

struct LiveDnsConfig {
    provider_type: String,
    zone: String,
    token: Option<String>,
    extra: HashMap<String, String>,
}

fn config() -> Option<LiveDnsConfig> {
    let provider_type = std::env::var("ACMEX_LIVE_DNS_TYPE").ok()?;
    let zone = std::env::var("ACMEX_LIVE_DNS_ZONE").ok()?;
    let token = std::env::var("ACMEX_LIVE_DNS_TOKEN").ok();
    let mut extra = HashMap::new();
    for (key, value) in std::env::vars() {
        if let Some(suffix) = key.strip_prefix("ACMEX_LIVE_DNS_EXTRA_") {
            extra.insert(suffix.to_lowercase(), value);
        }
    }
    Some(LiveDnsConfig {
        provider_type,
        zone,
        token,
        extra,
    })
}

fn skip_reason() -> String {
    "SKIP: set ACMEX_LIVE_DNS_TYPE / ACMEX_LIVE_DNS_ZONE plus provider credentials \
     (use a TEST zone — this creates and deletes TXT records in it)"
        .to_string()
}

/// Present two values under one record name, then remove them one at a
/// time: the live equivalent of the in-CI provider contract suite.
#[tokio::test]
#[ignore = "talks to a real DNS provider and mutates a live zone"]
async fn live_provider_present_and_cleanup_txt() {
    let Some(config) = config() else {
        eprintln!("{}", skip_reason());
        return;
    };
    if config.provider_type != "route53" && config.token.is_none() {
        panic!(
            "provider `{}` requires ACMEX_LIVE_DNS_TOKEN; Route53 uses the AWS SDK default credentials chain",
            config.provider_type
        );
    }

    // The token becomes a `file:` SecretRef (a temp file), so nothing
    // secret ever lands in the spec struct itself.
    let token_file = std::env::temp_dir().join(format!("acmex-live-dns-{}", std::process::id()));
    if let Some(token) = &config.token {
        std::fs::write(&token_file, token).unwrap();
    }
    let spec = DnsProviderSpec {
        id: "live-contract".to_string(),
        provider_type: config.provider_type,
        credential: config.token.as_ref().map(|_| SecretRef::File {
            path: token_file.clone(),
        }),
        zones: vec![config.zone.clone()],
        zone_suffixes: Vec::new(),
        endpoint: None,
        timeout_secs: 30,
        extra: config.extra,
    };

    let provider = match DefaultDnsProviderFactory
        .create(&spec, &EnvFileSecretResolver)
        .await
    {
        Ok(provider) => provider,
        Err(err) => panic!(
            "factory could not create `{}` — feature enabled? credentials present? ({err})",
            spec.provider_type
        ),
    };

    let name = format!("_acme-challenge.acmex-live.{}", config.zone);
    let one = provider
        .present_txt(PresentTxt {
            zone: config.zone.clone(),
            record_name: name.clone(),
            value: "acmex-live-contract-a".to_string(),
            idempotency_key: "live-a".to_string(),
        })
        .await
        .expect("present value a");
    assert_eq!(one.record_name, name);

    let two = provider
        .present_txt(PresentTxt {
            zone: config.zone.clone(),
            record_name: name.clone(),
            value: "acmex-live-contract-b".to_string(),
            idempotency_key: "live-b".to_string(),
        })
        .await
        .expect("present value b");
    assert_ne!(one.value_hash, two.value_hash, "two values, two hashes");

    // Cleanup is per-locator: each removal targets exactly its own record.
    provider.cleanup_txt(&one).await.expect("cleanup a");
    provider.cleanup_txt(&two).await.expect("cleanup b");
    match provider
        .cleanup_txt(&one)
        .await
        .expect("idempotent cleanup")
    {
        RecordCleanupOutcome::Removed | RecordCleanupOutcome::AlreadyAbsent => {}
    }

    let _ = std::fs::remove_file(&token_file);
    println!(
        "✅ live contract passed against `{}` zone `{}`",
        spec.provider_type, config.zone
    );
}
