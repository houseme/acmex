use std::collections::BTreeSet;

use acmex::Config;

#[test]
fn release_gate_example_config_parses_validates_and_exercises_v09_sections() {
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
fn release_gate_openapi_paths_match_api_v1_router_surface() {
    let openapi = include_str!("../docs/api/openapi.yaml");
    let router = include_str!("../src/server/api_v1.rs");
    let openapi_paths = openapi_paths(openapi);
    let router_paths = api_v1_router_paths(router);

    assert_eq!(
        openapi_paths, router_paths,
        "OpenAPI paths and api_v1 router paths must stay in lock-step"
    );

    assert!(
        openapi.contains("application/problem+json"),
        "OpenAPI must keep RFC 7807 problem responses visible"
    );
    assert!(
        openapi.contains("name: X-API-Key"),
        "OpenAPI must document the API key header"
    );
}

fn openapi_paths(openapi: &str) -> BTreeSet<String> {
    openapi
        .lines()
        .filter_map(|line| {
            let line = line.strip_prefix("  /")?;
            line.split_once(':').map(|(path, _)| format!("/{path}"))
        })
        .collect()
}

fn api_v1_router_paths(router: &str) -> BTreeSet<String> {
    router
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix(".route(\"") {
                return rest.split_once('"').map(|(path, _)| path.to_string());
            }
            trimmed
                .strip_prefix("\"/")
                .and_then(|rest| rest.split_once('"'))
                .map(|(path, _)| format!("/{path}"))
        })
        .collect()
}

#[test]
fn release_gate_openapi_documents_challenge_observation_fields() {
    let openapi = include_str!("../docs/api/openapi.yaml");
    for field in [
        "last_propagation_check_at",
        "last_propagation_status",
        "last_ca_poll_at",
        "last_ca_status",
    ] {
        assert!(
            openapi.contains(field),
            "ChallengeSessionView schema must document {field}"
        );
    }
    assert!(
        openapi.contains("reads never query the CA"),
        "challenge status documentation must state that GET is side-effect free"
    );
}

#[test]
fn release_gate_legacy_api_migration_doc_matches_deprecation_contract() {
    let doc = include_str!("../docs/API_V1_MIGRATION.md");
    assert!(
        doc.contains(acmex::server::api::LEGACY_API_SUNSET_HTTP_DATE),
        "migration doc must mirror the legacy Sunset header"
    );
    for route in [
        "POST /api/orders",
        "GET /api/orders",
        "POST /api/certificates/{id}/revoke",
        "GET /api/v1/operations/{id}/challenges",
    ] {
        assert!(doc.contains(route), "migration doc missing `{route}`");
    }
    assert!(
        doc.contains("only shrinks"),
        "migration doc must record that legacy /api only shrinks"
    );
}

#[test]
fn release_gate_feature_matrix_lists_every_cargo_feature() {
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
fn release_gate_release_documents_are_explicit_about_unverified_external_gates() {
    let checklist = include_str!("../docs/roadmap/v0.9.0/RELEASE_CHECKLIST.md");
    let limitations = include_str!("../docs/roadmap/v0.9.0/KNOWN_LIMITATIONS.md");
    let e2e = include_str!("../docs/roadmap/v0.9.0/E2E_RELEASE_GATES.md");
    let changelog = include_str!("../CHANGELOG.md");
    let release_09 = include_str!("../docs/RELEASE_NOTES_v0.9.0.md");
    let release_10 = include_str!("../docs/RELEASE_NOTES_v0.10.0.md");
    let migration_09 = include_str!("../docs/MIGRATION_v0.9.0.md");
    let migration_10 = include_str!("../docs/MIGRATION_v0.10.0.md");
    let decision = include_str!("../docs/roadmap/v0.10.0/RELEASE_DECISION.md");

    for (name, doc) in [
        ("RELEASE_CHECKLIST.md", checklist),
        ("KNOWN_LIMITATIONS.md", limitations),
        ("E2E_RELEASE_GATES.md", e2e),
        ("CHANGELOG.md", changelog),
        ("RELEASE_NOTES_v0.9.0.md", release_09),
        ("RELEASE_NOTES_v0.10.0.md", release_10),
        ("MIGRATION_v0.9.0.md", migration_09),
        ("MIGRATION_v0.10.0.md", migration_10),
        ("RELEASE_DECISION.md", decision),
    ] {
        assert!(
            doc.contains("not a release pass")
                || doc.contains("not yet validated")
                || doc.contains("Not Yet Release-Validated")
                || doc.contains("pending external evidence"),
            "{name} must not imply unrun L4/L5 gates have passed"
        );
    }

    for doc in [migration_09, migration_10, decision] {
        assert!(
            doc.contains(acmex::server::api::LEGACY_API_SUNSET_HTTP_DATE),
            "release migration and decision docs must mirror the legacy Sunset header"
        );
    }
}
