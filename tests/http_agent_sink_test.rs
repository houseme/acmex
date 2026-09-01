//! HttpAgentSink contract tests against a live fake agent (roadmap T10).
//!
//! A local axum server implements the agent contract; the sink exercises
//! the full stage → activate → health → rollback → cleanup lifecycle,
//! including stage idempotency, unhealthy reporting, cleanup absence and
//! spec-kind validation.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use tokio::sync::Mutex;

use acmex::delivery::http_sink::HttpAgentSink;
use acmex::{
    CertificateMaterialBuilder, CertificateMaterialRef, CertificateSink, CertificateVersion,
    CleanupOutcome, DeliveryRequirement, DeliveryTargetKind, DeploymentHealth, DeploymentSpec,
    IdentifierSet, KeyAlgorithm, KeyId, KeyRef, LineageId, SecretBytes, TargetId, VersionId,
    VersionState,
};

/// The fake agent's view of one staged route.
#[derive(Clone)]
#[allow(dead_code)] // leaf_sha256 kept for faithful agent state; asserted via the sink's health
struct AgentRoute {
    leaf_sha256: String,
    active: bool,
    healthy: bool,
}

#[derive(Default)]
struct AgentState {
    routes: HashMap<String, AgentRoute>,
    /// Activate fails for these version ids (fault injection).
    fail_activate_for: Vec<String>,
}

fn agent_router(state: Arc<Mutex<AgentState>>, token: &'static str) -> Router {
    let stage = |State(state): State<Arc<Mutex<AgentState>>>, body: String| async move {
        let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
        let version_id = payload["version_id"].as_str().unwrap().to_string();
        let leaf_sha256 = payload["leaf_sha256"].as_str().unwrap().to_string();
        let mut state = state.lock().await;
        // Idempotent per version: staging the same version twice succeeds.
        state
            .routes
            .entry(version_id.clone())
            .or_insert(AgentRoute {
                leaf_sha256,
                active: false,
                healthy: true,
            });
        (
            StatusCode::CREATED,
            axum::Json(serde_json::json!({
                "staged_ref": version_id,
                "resource_version": 1u64,
            })),
        )
    };
    let activate = |State(state): State<Arc<Mutex<AgentState>>>, Path(version_id): Path<String>| async move {
        let mut state = state.lock().await;
        if !state.routes.contains_key(&version_id) {
            return StatusCode::NOT_FOUND;
        }
        if state.fail_activate_for.contains(&version_id) {
            return StatusCode::BAD_GATEWAY;
        }
        // Exactly one route stays active: a faithful agent switches.
        for route in state.routes.values_mut() {
            route.active = false;
        }
        if let Some(route) = state.routes.get_mut(&version_id) {
            route.active = true;
        }
        StatusCode::NO_CONTENT
    };
    let health = |State(state): State<Arc<Mutex<AgentState>>>, Path(version_id): Path<String>| async move {
        let state = state.lock().await;
        match state.routes.get(&version_id) {
            Some(route) if route.active => axum::Json(serde_json::json!({
                "healthy": route.healthy,
                "detail": if route.healthy { serde_json::Value::Null } else { serde_json::json!("fingerprint mismatch") },
            }))
            .into_response(),
            Some(_) => axum::Json(serde_json::json!({
                "healthy": false,
                "detail": "route exists but is not active",
            }))
            .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    };
    let rollback = |State(state): State<Arc<Mutex<AgentState>>>, Path(version_id): Path<String>| async move {
        let mut state = state.lock().await;
        if let Some(route) = state.routes.get_mut(&version_id) {
            route.active = false;
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    };
    let cleanup = |State(state): State<Arc<Mutex<AgentState>>>, Path(version_id): Path<String>| async move {
        let mut state = state.lock().await;
        if state.routes.remove(&version_id).is_some() {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    };

    Router::new()
        .route("/stages", post(stage))
        .route("/stages/{version}/activate", post(activate))
        .route("/stages/{version}/health", get(health))
        .route("/stages/{version}/rollback", post(rollback))
        .route("/stages/{version}", delete(cleanup))
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let ok = req
                    .headers()
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value == format!("Bearer {token}"));
                if ok {
                    Ok(next.run(req).await)
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            },
        ))
        .with_state(state)
}

use axum::response::IntoResponse;

async fn spawn_agent(state: Arc<Mutex<AgentState>>) -> (String, &'static str) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = agent_router(state, "agent-secret-token");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), "agent-secret-token")
}

fn sample_version(domain: &str) -> (CertificateVersion, String) {
    let certified = rcgen::generate_simple_self_signed([domain.to_string()]).unwrap();
    let version = CertificateVersion {
        id: VersionId::generate(),
        lineage_id: LineageId::generate(),
        identifiers: IdentifierSet::parse([domain]).unwrap(),
        certificate_chain_pem: certified.cert.pem(),
        serial: "01".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2026-04-01T00:00:00Z".into(),
        issued_by: "contract-ca".into(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        state: VersionState::Issued,
    };
    (version, certified.signing_key.serialize_pem())
}

fn webhook_spec() -> DeploymentSpec {
    DeploymentSpec {
        target_id: TargetId::new("edge").unwrap(),
        kind: DeliveryTargetKind::Webhook,
        reference: "edge-1".to_string(),
        requirement: DeliveryRequirement::Required,
    }
}

#[tokio::test]
async fn http_agent_full_lifecycle() {
    let state = Arc::new(Mutex::new(AgentState::default()));
    let (base_url, token) = spawn_agent(state).await;
    let sink = HttpAgentSink::new("edge-1", base_url, token);

    let (version, key) = sample_version("agent.example.com");
    let material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&version, Some(SecretBytes::new(key.into_bytes())))
        .unwrap();

    // Stage is idempotent.
    let staged = sink
        .stage(
            &webhook_spec(),
            &version,
            CertificateMaterialRef {
                material: &material,
            },
        )
        .await
        .unwrap();
    sink.stage(
        &webhook_spec(),
        &version,
        CertificateMaterialRef {
            material: &material,
        },
    )
    .await
    .unwrap();

    // Before activation the route is not serving → Unhealthy (not Unknown:
    // the agent is reachable and answered).
    assert!(matches!(
        sink.health_check(&staged).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));

    // Activate; only one route serves.
    let (other_version, other_key) = sample_version("other.example.com");
    let other_material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(
            &other_version,
            Some(SecretBytes::new(other_key.into_bytes())),
        )
        .unwrap();
    let other_staged = sink
        .stage(
            &webhook_spec(),
            &other_version,
            CertificateMaterialRef {
                material: &other_material,
            },
        )
        .await
        .unwrap();
    sink.activate(&staged).await.unwrap();
    sink.activate(&other_staged).await.unwrap();
    assert_eq!(
        sink.health_check(&other_staged).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // Rollback deactivates.
    sink.rollback(&other_staged).await.unwrap();
    assert!(matches!(
        sink.health_check(&other_staged).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));

    // Cleanup; repeated cleanup reports AlreadyClean.
    assert_eq!(
        sink.cleanup(&staged).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert_eq!(
        sink.cleanup(&staged).await.unwrap(),
        CleanupOutcome::AlreadyClean
    );
}

#[tokio::test]
async fn http_agent_activate_failure_surfaces_as_error() {
    let state = Arc::new(Mutex::new(AgentState {
        fail_activate_for: vec!["will-fail".to_string()],
        ..AgentState::default()
    }));
    let (base_url, token) = spawn_agent(state).await;
    let sink = HttpAgentSink::new("edge-1", base_url, token);

    let (mut version, key) = sample_version("broken.example.com");
    version.id = VersionId::new("will-fail").unwrap();
    let material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&version, Some(SecretBytes::new(key.into_bytes())))
        .unwrap();
    let staged = sink
        .stage(
            &webhook_spec(),
            &version,
            CertificateMaterialRef {
                material: &material,
            },
        )
        .await
        .unwrap();
    let err = sink.activate(&staged).await.unwrap_err();
    assert!(err.to_string().contains("activate"), "got: {err}");
}

#[tokio::test]
async fn http_agent_unreachable_is_unknown_health() {
    // Bind then drop a port to get an address nothing listens on.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let sink = HttpAgentSink::new("edge-1", format!("http://{addr}"), "token");
    let staged = acmex::StagedDeployment {
        kind: DeliveryTargetKind::Webhook,
        target_id: TargetId::new("edge").unwrap(),
        version_id: VersionId::generate(),
        staged_ref: String::new(),
        previous_active_ref: None,
        leaf_sha256: "00".to_string(),
        resource_version: 0,
    };
    // Transient outages are Unknown, never Unhealthy (no rollback trigger).
    assert!(matches!(
        sink.health_check(&staged).await.unwrap(),
        DeploymentHealth::Unknown(_)
    ));
}

#[tokio::test]
async fn http_agent_rejects_non_webhook_specs() {
    let state = Arc::new(Mutex::new(AgentState::default()));
    let (base_url, token) = spawn_agent(state).await;
    let sink = HttpAgentSink::new("edge-1", base_url, token);

    let (version, key) = sample_version("typed.example.com");
    let material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&version, Some(SecretBytes::new(key.into_bytes())))
        .unwrap();
    let spec = DeploymentSpec {
        target_id: TargetId::new("fs").unwrap(),
        kind: DeliveryTargetKind::File,
        reference: "/tmp".to_string(),
        requirement: DeliveryRequirement::Required,
    };
    let err = sink
        .stage(
            &spec,
            &version,
            CertificateMaterialRef {
                material: &material,
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("webhook"), "got: {err}");
}
