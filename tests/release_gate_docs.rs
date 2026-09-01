use std::collections::BTreeSet;

use acmex::Config;

#[test]
fn example_config_parses_validates_and_exercises_v09_sections() {
    let config: Config = include_str!("../acmex.toml.example").parse().unwrap();
    config.validate().unwrap();

    assert_eq!(config.acme.ca_environment, "staging");
    assert_eq!(config.repository.backend, "file");
    assert_eq!(
        config.repository.file.as_ref().unwrap().path,
        ".acmex/repository"
    );
    assert_eq!(
        config.server.as_ref().unwrap().listen_addr,
        "127.0.0.1:8080"
    );
    assert!(
        !include_str!("../acmex.toml.example").contains("your-secret-api-key"),
        "example config must not ship a default API secret"
    );
}

#[test]
fn openapi_paths_match_api_v1_router_surface() {
    let openapi = include_str!("../docs/api/openapi.yaml");
    let router = include_str!("../src/server/api_v1.rs");
    let expected_paths = [
        "/certificate-intents",
        "/certificate-intents/{id}",
        "/certificate-intents/{id}/issue",
        "/certificate-lineages/{id}",
        "/certificate-lineages/{id}/renew",
        "/certificate-lineages/{id}/versions",
        "/certificate-versions/{id}",
        "/certificate-versions/{id}/chain",
        "/certificate-versions/{id}/deploy",
        "/certificate-versions/{id}/revoke",
        "/operations",
        "/operations/{id}",
        "/operations/{id}/cancel",
    ];

    for path in expected_paths {
        assert!(
            openapi.contains(&format!("  {path}:")),
            "OpenAPI is missing path {path}"
        );
        assert!(
            router.contains(&format!("\"{path}\"")),
            "api_v1 router is missing path {path}"
        );
    }

    assert!(
        openapi.contains("application/problem+json"),
        "OpenAPI must keep RFC 7807 problem responses visible"
    );
    assert!(
        openapi.contains("name: X-API-Key"),
        "OpenAPI must document the API key header"
    );
}

#[test]
fn feature_matrix_lists_every_cargo_feature() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    let features = manifest["features"].as_table().unwrap();
    let matrix = include_str!("../docs/roadmap/v0.9.0/FEATURE_MATRIX.md");
    let documented: BTreeSet<_> = matrix
        .lines()
        .filter_map(|line| line.split('|').nth(1))
        .map(str::trim)
        .filter(|cell| cell.starts_with('`') && cell.ends_with('`'))
        .map(|cell| cell.trim_matches('`').to_string())
        .collect();

    for feature in features.keys() {
        assert!(
            documented.contains(feature),
            "FEATURE_MATRIX.md must document Cargo feature `{feature}`"
        );
    }
}

#[test]
fn release_documents_are_explicit_about_unverified_external_gates() {
    let checklist = include_str!("../docs/roadmap/v0.9.0/RELEASE_CHECKLIST.md");
    let limitations = include_str!("../docs/roadmap/v0.9.0/KNOWN_LIMITATIONS.md");
    let e2e = include_str!("../docs/roadmap/v0.9.0/E2E_RELEASE_GATES.md");

    for (name, doc) in [
        ("RELEASE_CHECKLIST.md", checklist),
        ("KNOWN_LIMITATIONS.md", limitations),
        ("E2E_RELEASE_GATES.md", e2e),
    ] {
        assert!(
            doc.contains("not a release pass") || doc.contains("not yet validated"),
            "{name} must not imply unrun L4/L5 gates have passed"
        );
    }
}
