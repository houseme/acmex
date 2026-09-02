//! Live infrastructure evidence preflight (roadmap T20).
//!
//! The actual infrastructure checks are environment-specific and ignored by
//! default. This gate makes the asset contract executable so a live run cannot
//! silently shrink scope without changing `ACMEX_LIVE_INFRA_SCENARIOS`.

use std::collections::BTreeSet;
use std::path::PathBuf;

const ALL_SCENARIOS: &[&str] = &[
    "dns-cloudflare",
    "dns-route53",
    "redis",
    "sink-http-agent",
    "sink-kubernetes",
    "sink-vault",
    "dual-process-fencing",
];

fn scenarios_from_env() -> BTreeSet<String> {
    let raw = std::env::var("ACMEX_LIVE_INFRA_SCENARIOS").unwrap_or_else(|_| "all".to_string());
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .flat_map(|s| {
            if s == "all" {
                ALL_SCENARIOS.iter().copied().collect::<Vec<_>>()
            } else {
                vec![s]
            }
        })
        .map(str::to_string)
        .collect()
}

fn require_var(missing: &mut Vec<String>, name: &'static str) {
    if std::env::var(name)
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        missing.push(name.to_string());
    }
}

fn require_aws_credentials(missing: &mut Vec<String>) {
    let has_profile = std::env::var("AWS_PROFILE")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let has_keypair = std::env::var("AWS_ACCESS_KEY_ID")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
        && std::env::var("AWS_SECRET_ACCESS_KEY")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
    if !has_profile && !has_keypair {
        missing.push("AWS_PROFILE or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY".to_string());
    }
}

fn missing_required_env(scenarios: &BTreeSet<String>) -> Vec<String> {
    let mut missing = Vec::new();
    require_var(&mut missing, "ACMEX_LIVE_INFRA_ARTIFACT_DIR");
    if scenarios.contains("dns-cloudflare") {
        require_var(&mut missing, "RUN_LIVE_DNS_CLOUDFLARE");
        require_var(&mut missing, "ACMEX_LIVE_DNS_CLOUDFLARE_ZONE");
        require_var(&mut missing, "ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN");
    }
    if scenarios.contains("dns-route53") {
        require_var(&mut missing, "RUN_LIVE_DNS_ROUTE53");
        require_var(&mut missing, "ACMEX_LIVE_DNS_ROUTE53_ZONE");
        require_var(&mut missing, "ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID");
        require_aws_credentials(&mut missing);
    }
    if scenarios.contains("redis") {
        require_var(&mut missing, "ACMEX_LIVE_REDIS_URL");
    }
    if scenarios.contains("sink-http-agent") {
        require_var(&mut missing, "ACMEX_LIVE_HTTP_AGENT_URL");
        require_var(&mut missing, "ACMEX_LIVE_HTTP_AGENT_TOKEN_REF");
    }
    if scenarios.contains("sink-kubernetes") {
        require_var(&mut missing, "ACMEX_LIVE_KUBECONFIG");
        require_var(&mut missing, "ACMEX_LIVE_K8S_NAMESPACE");
    }
    if scenarios.contains("sink-vault") {
        require_var(&mut missing, "ACMEX_LIVE_VAULT_ADDR");
        require_var(&mut missing, "ACMEX_LIVE_VAULT_TOKEN_REF");
    }
    if scenarios.contains("dual-process-fencing") {
        require_var(&mut missing, "ACMEX_LIVE_FENCING_REPOSITORY");
        require_var(&mut missing, "ACMEX_LIVE_FENCING_WORKERS");
    }
    missing
}

fn artifact_dir() -> PathBuf {
    std::env::var("ACMEX_LIVE_INFRA_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("acmex-live-infra-{}", std::process::id()))
        })
}

#[test]
fn live_infra_scenarios_are_unique() {
    let unique: BTreeSet<_> = ALL_SCENARIOS.iter().copied().collect();
    assert_eq!(unique.len(), ALL_SCENARIOS.len());
}

#[test]
fn live_infra_scope_doc_lists_every_gate() {
    let doc = include_str!("../docs/roadmap/v0.9.0/LIVE_INFRASTRUCTURE_EVIDENCE.md");
    for scenario in ALL_SCENARIOS {
        assert!(doc.contains(scenario), "scope doc missing `{scenario}`");
    }
    assert!(
        doc.contains("not a release pass"),
        "scope doc must keep skipped evidence distinct from release evidence"
    );
}

#[tokio::test]
#[ignore = "requires real DNS, Redis, sink, and dual-process validation assets"]
async fn live_infra_preflight_manifest_gate() {
    if std::env::var("RUN_LIVE_INFRA").as_deref() != Ok("1") {
        eprintln!("SKIP: RUN_LIVE_INFRA=1 not set; a skipped live infra run is not a release pass");
        return;
    }

    let scenarios = scenarios_from_env();
    let missing = missing_required_env(&scenarios);
    assert!(
        missing.is_empty(),
        "RUN_LIVE_INFRA=1 requires live validation assets: missing {missing:?}"
    );

    let out_dir = artifact_dir();
    std::fs::create_dir_all(&out_dir).expect("artifact dir");
    let manifest = serde_json::json!({
        "gate": "live-infra",
        "requested_scenarios": scenarios.into_iter().collect::<Vec<_>>(),
        "evidence_files_expected": [
            "live-dns-cloudflare.log",
            "live-dns-route53.log",
            "redis-scope.md",
            "sink-scope.md",
            "dual-process-fencing.log"
        ],
        "secret_values_recorded": false,
    });
    let manifest_path = out_dir.join("preflight-manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("write manifest");
    println!("live infra preflight manifest: {}", manifest_path.display());
}
