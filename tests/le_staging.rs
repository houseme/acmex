//! Controlled Let's Encrypt staging evidence gate (roadmap T19).
//!
//! This test is intentionally `#[ignore]`: it reaches a public staging CA and
//! requires caller-owned validation assets. The gate does not issue by default;
//! it verifies that a real run has the minimum safe inputs and records a
//! non-secret preflight manifest next to the run artifacts.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_DIRECTORY_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

const ALL_SCENARIOS: &[&str] = &[
    "directory",
    "http-01",
    "dns-01",
    "renewal",
    "profile",
    "ip-http-01",
    "ip-tls-alpn-01",
    "eab-ca",
];

fn parse_scenarios(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .flat_map(|s| {
            if s == "all" {
                ALL_SCENARIOS.to_vec()
            } else {
                vec![s]
            }
        })
        .map(str::to_string)
        .collect()
}

fn scenarios_from_env() -> BTreeSet<String> {
    let raw = std::env::var("ACMEX_LE_STAGING_SCENARIOS").unwrap_or_else(|_| "all".to_string());
    parse_scenarios(&raw)
}

fn unknown_scenarios(scenarios: &BTreeSet<String>) -> Vec<String> {
    scenarios
        .iter()
        .filter(|scenario| !ALL_SCENARIOS.contains(&scenario.as_str()))
        .cloned()
        .collect()
}

fn has_issuance_scenario(scenarios: &BTreeSet<String>) -> bool {
    scenarios.iter().any(|scenario| scenario != "directory")
}

fn missing_required_env(scenarios: &BTreeSet<String>) -> Vec<&'static str> {
    let mut required = BTreeSet::from(["ACMEX_LE_STAGING_ARTIFACT_DIR"]);
    if has_issuance_scenario(scenarios) {
        required.extend([
            "ACMEX_LE_STAGING_ACCOUNT_EMAIL",
            "ACMEX_LE_STAGING_DOMAIN",
            "ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE",
        ]);
    }
    if scenarios.contains("dns-01") {
        required.extend([
            "ACMEX_LIVE_DNS_TYPE",
            "ACMEX_LIVE_DNS_ZONE",
            "ACMEX_LIVE_DNS_TOKEN",
        ]);
    }
    if scenarios.contains("ip-http-01") || scenarios.contains("ip-tls-alpn-01") {
        required.extend(["ACMEX_LE_STAGING_IPV4", "ACMEX_LE_STAGING_IPV6"]);
    }
    if scenarios.contains("eab-ca") {
        required.extend([
            "ACMEX_EAB_CA_DIRECTORY_URL",
            "ACMEX_EAB_KEY_ID",
            "ACMEX_EAB_HMAC_KEY_REF",
        ]);
    }
    required
        .into_iter()
        .filter(|name| {
            std::env::var(name)
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
        })
        .collect()
}

fn artifact_dir() -> PathBuf {
    std::env::var("ACMEX_LE_STAGING_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("acmex-le-staging-{}", std::process::id()))
        })
}

#[test]
fn le_staging_gate_names_do_not_embed_secret_values() {
    for name in [
        "ACMEX_LE_STAGING_ACCOUNT_EMAIL",
        "ACMEX_LIVE_DNS_TOKEN",
        "ACMEX_EAB_HMAC_KEY_REF",
    ] {
        assert!(
            name.starts_with("ACMEX_"),
            "gate env names must be explicit project-scoped names"
        );
        assert!(
            !name.contains("VALUE"),
            "gate env names document references, not literal secret values"
        );
    }
}

#[test]
fn le_staging_all_scenarios_are_named_in_the_roadmap() {
    let task = include_str!("../docs/roadmap/v0.10.0/T19_LETSENCRYPT_STAGING_VALIDATION.md");
    let task_compact = task.replace(['-', '_'], "").to_ascii_lowercase();
    for (scenario, aliases) in [
        ("directory", &["directory", "目录"][..]),
        ("http-01", &["http01"][..]),
        ("dns-01", &["dns01"][..]),
        ("renewal", &["renewal", "续签"][..]),
        ("profile", &["profile", "profiles"][..]),
        ("ip-http-01", &["ipv4", "ipv6"][..]),
        ("ip-tls-alpn-01", &["tlsalpn01"][..]),
        ("eab-ca", &["eab", "zerossl", "google"][..]),
    ] {
        assert!(
            aliases.iter().any(|needle| task_compact.contains(needle)),
            "T19 roadmap should describe scenario `{scenario}`"
        );
    }
}

#[test]
fn le_staging_scenario_parser_expands_all_and_rejects_unknown_names() {
    let scenarios = parse_scenarios("directory, profile, all, made-up");
    for scenario in ALL_SCENARIOS {
        assert!(
            scenarios.contains(*scenario),
            "`all` should include {scenario}"
        );
    }
    assert_eq!(unknown_scenarios(&scenarios), vec!["made-up".to_string()]);
}

#[tokio::test]
#[ignore = "talks to Let's Encrypt staging and requires caller-owned validation assets"]
async fn le_staging_preflight_and_manifest_gate() {
    if std::env::var("RUN_LE_STAGING").as_deref() != Ok("1") {
        eprintln!("SKIP: RUN_LE_STAGING=1 not set; a skipped LE staging run is not a release pass");
        return;
    }

    let scenarios = scenarios_from_env();
    let unknown = unknown_scenarios(&scenarios);
    assert!(
        unknown.is_empty(),
        "ACMEX_LE_STAGING_SCENARIOS contains unknown entries: {unknown:?}; known scenarios: {ALL_SCENARIOS:?}"
    );
    let issuance_assets_required = has_issuance_scenario(&scenarios);
    let missing = missing_required_env(&scenarios);
    assert!(
        missing.is_empty(),
        "RUN_LE_STAGING=1 requires external validation assets: missing {missing:?}"
    );

    let directory_url = std::env::var("ACMEX_LE_STAGING_DIRECTORY_URL")
        .unwrap_or_else(|_| DEFAULT_DIRECTORY_URL.to_string());
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("staging client")
        .get(&directory_url)
        .send()
        .await
        .expect("fetch LE staging directory");
    assert!(
        response.status().is_success(),
        "LE staging directory returned {}",
        response.status()
    );
    let directory: serde_json::Value = response.json().await.expect("directory JSON");
    for key in ["newNonce", "newAccount", "newOrder"] {
        assert!(
            directory
                .get(key)
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "directory must advertise `{key}`"
        );
    }
    let profiles = directory
        .get("profiles")
        .and_then(serde_json::Value::as_object)
        .map(|profiles| profiles.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let supports_ari = directory
        .get("renewalInfo")
        .and_then(serde_json::Value::as_str)
        .is_some();

    let out_dir = artifact_dir();
    std::fs::create_dir_all(&out_dir).expect("artifact dir");
    let manifest = serde_json::json!({
        "gate": "le-staging",
        "directory_url": directory_url,
        "directory_keys": ["newNonce", "newAccount", "newOrder"],
        "directory_supports_ari": supports_ari,
        "profiles_advertised": profiles,
        "requested_scenarios": scenarios.into_iter().collect::<Vec<_>>(),
        "issuance_assets_required": issuance_assets_required,
        "secret_values_recorded": false,
    });
    let manifest_path = out_dir.join("preflight-manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("write manifest");
    println!("LE staging preflight manifest: {}", manifest_path.display());
}

// ---------------------------------------------------------------------------
// Live account lifecycle against the REAL Let's Encrypt staging CA. Requires
// no validation assets: only a contact email you control. Exercises directory
// discovery, newAccount (flattened JWS envelope, ES256), newOrder,
// authorization fetch and account key rollover against a public CA.
// ---------------------------------------------------------------------------

use std::sync::Arc;

use acmex::account::KeyPair;
use acmex::ca_backend::AcmeCaBackend;
use acmex::ca_backend::{AccountRef, CaBackend, OrderRequest, ReqwestAcmeTransport};
use acmex::domain::Identifier;
use acmex::repository::MemoryRepository;

#[tokio::test]
#[ignore = "talks to the real Let's Encrypt staging CA over the network"]
async fn le_staging_account_create_new_order_and_key_rollover_live() {
    let Some(email) = std::env::var("ACMEX_LE_STAGING_ACCOUNT_EMAIL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!(
            "SKIP: ACMEX_LE_STAGING_ACCOUNT_EMAIL is required for the live \
             staging account scenario (any mailto you control — staging only)"
        );
        return;
    };
    let artifact_dir = artifact_dir();
    std::fs::create_dir_all(&artifact_dir).unwrap();

    let account_key = Arc::new(KeyPair::generate().unwrap());
    let repositories = MemoryRepository::new().into_set();
    let backend: Arc<dyn CaBackend> = Arc::new(AcmeCaBackend::new(
        "le-staging",
        DEFAULT_DIRECTORY_URL.to_string(),
        Arc::new(ReqwestAcmeTransport::new()),
        account_key.clone(),
        repositories.clone(),
    ));

    // 1. newAccount against the real CA: flattened JWS envelope, ES256.
    let account_ref = AccountRef {
        tenant_id: "ten_default".to_string(),
        contacts: vec![format!("mailto:{email}")],
        terms_of_service_agreed: true,
        external_account_binding: None,
    };
    let account = backend.ensure_account(&account_ref).await.unwrap();
    assert!(
        account
            .account_url
            .starts_with("https://acme-staging-v02.api.letsencrypt.org/acme/acct/"),
        "unexpected LE staging account URL: {}",
        account.account_url
    );
    println!("✅ LE staging account registered: {}", account.account_url);

    // 2. newOrder for a caller-owned domain. Validation is NOT attempted —
    // the order simply stays pending — but the full order/authorization
    // protocol surface runs against the real CA.
    // example.com is policy-blocked by LE; any non-blocked name works for
    // ORDER CREATION (validation is not attempted by this scenario).
    let order_domain = format!(
        "acmex-e2e-{}.staging-test.houseme.dev",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let identifiers = vec![Identifier::try_dns(&order_domain).unwrap()];
    let order = backend
        .create_order(
            &account,
            &OrderRequest::for_identifiers(identifiers.clone()),
        )
        .await
        .unwrap();
    assert!(
        order
            .url
            .starts_with("https://acme-staging-v02.api.letsencrypt.org/acme/order/")
    );
    println!("✅ LE staging order created: {}", order.url);

    // 3. Fetch the authorizations the CA created for the order.
    let authzs = backend.get_authorizations(&account, &order).await.unwrap();
    assert!(!authzs.is_empty(), "LE staging returned authorizations");
    for authz in &authzs {
        assert!(
            !authz.authorization.challenges.is_empty(),
            "authorization offers challenge types"
        );
    }
    println!(
        "✅ LE staging authorizations fetched: {} (status {}, challenge types offered: {})",
        authzs.len(),
        authzs[0].authorization.status,
        authzs[0]
            .authorization
            .challenges
            .iter()
            .map(|c| c.challenge_type.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // 4. Account key rollover against the real CA (RFC 8555 §7.3.5
    // double-JWS): the new key must be accepted for subsequent requests.
    let new_key = Arc::new(KeyPair::generate().unwrap());
    backend.roll_account_key(&account, new_key).await.unwrap();
    println!("✅ LE staging account key rolled over");

    let reordered = backend
        .create_order(&account, &OrderRequest::for_identifiers(identifiers))
        .await
        .expect("order creation with the rolled-over key (LE accepted the new key)");
    println!("✅ LE staging order after rollover: {}", reordered.url);

    let manifest = serde_json::json!({
        "scenario": "account-create-order-rollover",
        "directory": DEFAULT_DIRECTORY_URL,
        "account_url": account.account_url,
        "order_url": order.url,
        "post_rollover_order_url": reordered.url,
        "authorizations": authzs.len(),
        "recorded_at": jiff::Timestamp::now().to_string(),
    });
    std::fs::write(
        artifact_dir.join("account-lifecycle-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!(
        "✅ manifest written to {}",
        artifact_dir
            .join("account-lifecycle-manifest.json")
            .display()
    );
}
