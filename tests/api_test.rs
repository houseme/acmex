use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use jiff::Timestamp;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

use acmex::application::Permission;
use acmex::application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, CertificateQuery,
    CreateCertificateIntent, IssueCertificate,
};
use acmex::challenge::{ChallengeSession, ChallengeSessionState};
use acmex::config::Config;
use acmex::domain::{
    ChallengeLease, ChallengeLeaseId, ChallengeLeaseLocator, ChallengeLeaseState, Identifier,
    TenantId,
};
use acmex::notifications::WebhookManager;
use acmex::orchestrator::OrchestrationStatus;
use acmex::repository::RepositorySet;
use acmex::server::api::{AppState, TaskInfo};
use acmex::server::auth::{ApiKeyCredential, ApiKeySet, PermissionAuthorizer, api_key_auth};
use acmex::types::ChallengeType;

fn test_webhook() -> Arc<acmex::server::WebhookHandler> {
    Arc::new(acmex::server::WebhookHandler::new(Arc::new(
        WebhookManager::new(vec![]),
    )))
}

fn legacy_state(tasks: Arc<RwLock<HashMap<String, TaskInfo>>>) -> AppState {
    AppState {
        config: Arc::new(Config::default()),
        client: None,
        storage: None,
        health: Arc::new(acmex::server::HealthCheck::new()),
        webhook: test_webhook(),
        tasks,
        api_keys: Arc::new(ApiKeySet::from_plaintext_keys(["test-key"])),
        authorizer: Arc::new(PermissionAuthorizer),
        scheduler: None,
        repositories: None,
        application: None,
        query: None,
    }
}

/// Assembles an application-backed state from already-built service parts so
/// tests can seed repositories before mounting the router.
fn app_state_from_parts(
    application: Arc<dyn CertificateApplication>,
    query: Arc<dyn CertificateQuery>,
    repositories: Option<RepositorySet>,
) -> AppState {
    let config = r#"
[acme]
ca = "letsencrypt"
ca_environment = "staging"
"#
    .parse::<Config>()
    .unwrap();
    AppState {
        config: Arc::new(config),
        client: None,
        storage: None,
        health: Arc::new(acmex::server::HealthCheck::new()),
        webhook: test_webhook(),
        tasks: Arc::new(RwLock::new(HashMap::new())),
        api_keys: Arc::new(ApiKeySet::from_plaintext_keys(["test-key"])),
        authorizer: Arc::new(PermissionAuthorizer),
        scheduler: None,
        repositories,
        application: Some(application),
        query: Some(query),
    }
}

fn application_state() -> AppState {
    let (service, repositories) = ApplicationServiceBuilder::new().build().unwrap();
    let query: Arc<dyn CertificateQuery> = service.clone();
    let application: Arc<dyn CertificateApplication> = service;
    app_state_from_parts(application, query, Some(repositories))
}

fn read_only_application_state() -> AppState {
    let mut state = application_state();
    let credential = ApiKeyCredential::from_plaintext(
        "reader",
        TenantId::default_tenant(),
        "read-key",
        vec![Permission::IntentRead],
    )
    .unwrap();
    state.api_keys = Arc::new(ApiKeySet::from_credentials(vec![credential]));
    state
}

#[tokio::test]
async fn test_api_renew_all() {
    let state = legacy_state(Arc::new(RwLock::new(HashMap::new())));

    let app = axum::Router::new()
        .route(
            "/api/orders/renew-all",
            axum::routing::post(acmex::server::order::trigger_full_renewal),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/orders/renew-all")
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn test_api_list_orders() {
    let tasks = Arc::new(RwLock::new(HashMap::new()));

    {
        let mut t = tasks.write().await;
        t.insert(
            "task-1".to_string(),
            TaskInfo {
                status: OrchestrationStatus::Completed,
                domains: vec!["example.com".to_string()],
            },
        );
    }

    let state = legacy_state(tasks);

    let app = axum::Router::new()
        .route(
            "/api/orders",
            axum::routing::get(acmex::server::order::list_orders),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/orders")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let orders: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(orders.is_array());
    assert_eq!(orders[0]["id"], "task-1");
}

#[tokio::test]
async fn api_v1_issue_returns_operation_with_location() {
    let app = axum::Router::new()
        .nest("/api/v1", acmex::server::api_v1::routes())
        .with_state(application_state());

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/certificate-intents")
                .header("Idempotency-Key", "create-intent-key")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "identifiers": ["Example.COM"] }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body = axum::body::to_bytes(create_response.into_body(), 4096)
        .await
        .unwrap();
    let intent: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
    assert_eq!(intent["identifiers"][0], "example.com");

    let issue_uri = format!(
        "/api/v1/certificate-intents/{}/issue",
        intent["id"].as_str().unwrap()
    );
    let issue_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(issue_uri)
                .header("Idempotency-Key", "issue-intent-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(issue_response.status(), StatusCode::ACCEPTED);
    assert!(
        issue_response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .starts_with("/api/v1/operations/op_")
    );
    let issue_body = axum::body::to_bytes(issue_response.into_body(), 4096)
        .await
        .unwrap();
    let operation: serde_json::Value = serde_json::from_slice(&issue_body).unwrap();
    assert_eq!(operation["kind"], "issue");
    assert_eq!(operation["status"], "queued");
}

#[tokio::test]
async fn api_v1_mutations_require_idempotency_key() {
    let app = axum::Router::new()
        .nest("/api/v1", acmex::server::api_v1::routes())
        .with_state(application_state());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/certificate-intents")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "identifiers": ["example.com"] }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["error_code"], "INVALID_INPUT");
}

#[tokio::test]
async fn api_v1_replays_same_idempotency_payload_and_rejects_conflict() {
    let app = axum::Router::new()
        .nest("/api/v1", acmex::server::api_v1::routes())
        .with_state(application_state());
    let body = serde_json::json!({ "identifiers": ["Example.COM"] }).to_string();

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/certificate-intents")
                .header("Idempotency-Key", "replay-key")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = axum::body::to_bytes(first.into_body(), 4096).await.unwrap();
    let first_json: serde_json::Value = serde_json::from_slice(&first_body).unwrap();

    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/certificate-intents")
                .header("Idempotency-Key", "replay-key")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    let replay_body = axum::body::to_bytes(replay.into_body(), 4096)
        .await
        .unwrap();
    let replay_json: serde_json::Value = serde_json::from_slice(&replay_body).unwrap();
    assert_eq!(first_json["id"], replay_json["id"]);

    let conflict = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/certificate-intents")
                .header("Idempotency-Key", "replay-key")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "identifiers": ["example.org"] }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}

/// Seeded PATCH fixture: a real intent behind an application-backed state,
/// mirroring the challenge test setup.
async fn patch_fixture() -> (axum::Router, acmex::application::IntentView, RepositorySet) {
    let (service, repositories) = ApplicationServiceBuilder::new().build().unwrap();
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec!["example.com".to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: Default::default(),
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            idempotency_key: "patch-create-key".to_string(),
        })
        .await
        .unwrap();
    let query: Arc<dyn CertificateQuery> = service.clone();
    let application: Arc<dyn CertificateApplication> = service;
    let app = axum::Router::new()
        .nest("/api/v1", acmex::server::api_v1::routes())
        .with_state(app_state_from_parts(
            application,
            query,
            Some(repositories.clone()),
        ));
    (app, intent, repositories)
}

fn patch_request(id: &str, headers: &[(&'static str, &'static str)], body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/certificate-intents/{id}"))
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn api_v1_patch_intent_updates_mutable_fields_and_bumps_generation() {
    let (app, intent, repositories) = patch_fixture().await;
    assert_eq!(intent.generation, 1);

    // renewal_policy is fully replaced and the generation is bumped.
    let patched = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-key-1")],
            &serde_json::json!({ "renewal_policy": { "prefer_ari": false } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::OK);
    let view = json_body(patched).await;
    assert_eq!(view["id"], intent.id.as_str());
    assert_eq!(view["generation"], 2);

    let stored = repositories
        .intents
        .get(&intent.id)
        .await
        .unwrap()
        .expect("intent must still exist");
    assert!(!stored.value.renewal_policy.prefer_ari);
    assert_eq!(stored.value.generation, 2);
    // Immutable parts are untouched.
    assert_eq!(stored.value.identifiers.len(), 1);

    // delivery_targets are fully replaced too; omitted fields keep theirs.
    let targets = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-key-2")],
            &serde_json::json!({
                "delivery_targets": [
                    { "id": "web", "type": "file", "reference": "/etc/certs" }
                ]
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(targets.status(), StatusCode::OK);
    assert_eq!(json_body(targets).await["generation"], 3);
    let stored = repositories.intents.get(&intent.id).await.unwrap().unwrap();
    assert_eq!(stored.value.delivery_targets.len(), 1);
    assert_eq!(stored.value.delivery_targets[0].id.as_str(), "web");
    assert!(!stored.value.renewal_policy.prefer_ari);

    // Identical replay is a no-op: the current view is returned and the
    // generation is NOT bumped again (v1 idempotency behavior).
    let replay = app
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-key-2-replay")],
            &serde_json::json!({
                "delivery_targets": [
                    { "id": "web", "type": "file", "reference": "/etc/certs" }
                ]
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(json_body(replay).await["generation"], 3);
}

#[tokio::test]
async fn api_v1_patch_intent_rejects_immutable_fields_and_empty_body() {
    let (app, intent, _) = patch_fixture().await;

    // Immutable fields are rejected with a 400 naming them.
    let immutable = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-immutable")],
            &serde_json::json!({ "ca_policy": { "ca_id": "other-ca" } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(immutable.status(), StatusCode::BAD_REQUEST);
    let problem = json_body(immutable).await;
    assert_eq!(problem["error_code"], "INVALID_INPUT");
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("immutable"),
        "detail must say immutable: {detail}"
    );
    assert!(
        detail.contains("ca_policy"),
        "detail must name ca_policy: {detail}"
    );

    // An empty patch body has nothing to apply.
    let empty = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-empty")],
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
    let problem = json_body(empty).await;
    assert_eq!(problem["error_code"], "INVALID_INPUT");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("renewal_policy"),
        "detail must name the mutable fields"
    );

    // Neither rejection mutated the intent.
    let stored_intent = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/certificate-intents/{}", intent.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stored_intent.status(), StatusCode::OK);
    assert_eq!(json_body(stored_intent).await["generation"], 1);
}

#[tokio::test]
async fn api_v1_patch_intent_enforces_if_match_and_idempotency_key() {
    let (app, intent, repositories) = patch_fixture().await;

    // A stale If-Match generation is a 409 CAS conflict.
    let stale = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-ifmatch"), ("If-Match", "99")],
            &serde_json::json!({ "renewal_policy": { "prefer_ari": false } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let problem = json_body(stale).await;
    assert_eq!(problem["error_code"], "IDEMPOTENCY_OR_CAS_CONFLICT");

    // A matching generation (quoted ETag form) applies.
    let applied = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-ifmatch"), ("If-Match", "\"1\"")],
            &serde_json::json!({ "renewal_policy": { "prefer_ari": false } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(applied.status(), StatusCode::OK);
    assert_eq!(json_body(applied).await["generation"], 2);

    // The previously valid generation is now stale.
    let now_stale = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-ifmatch"), ("If-Match", "1")],
            &serde_json::json!({ "renewal_policy": { "prefer_ari": false } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(now_stale.status(), StatusCode::CONFLICT);

    // A non-generation If-Match value never reaches the CAS loop.
    let malformed = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[("Idempotency-Key", "patch-ifmatch"), ("If-Match", "abc")],
            &serde_json::json!({ "renewal_policy": { "prefer_ari": true } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

    // Missing Idempotency-Key is rejected by the shared mutating guard.
    let no_key = app
        .clone()
        .oneshot(patch_request(
            intent.id.as_str(),
            &[],
            &serde_json::json!({ "renewal_policy": { "prefer_ari": false } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(no_key.status(), StatusCode::BAD_REQUEST);
    let problem = json_body(no_key).await;
    assert_eq!(problem["error_code"], "INVALID_INPUT");

    // Unknown intents are 404, consistent with the GET route.
    let missing = app
        .clone()
        .oneshot(patch_request(
            "int_missing",
            &[("Idempotency-Key", "patch-missing")],
            &serde_json::json!({ "renewal_policy": { "prefer_ari": false } }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    // Only the effective patch was applied: one generation bump.
    let stored = repositories.intents.get(&intent.id).await.unwrap().unwrap();
    assert_eq!(stored.value.generation, 2);
}

#[tokio::test]
async fn api_v1_challenge_sessions_and_cleanup_retry() {
    let (service, repositories) = ApplicationServiceBuilder::new().build().unwrap();

    // A real intent + operation so the lease inherits a visible subject
    // lineage, exactly like production challenge flows.
    let intent = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec!["example.com".to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: Default::default(),
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            idempotency_key: "challenge-intent-key".to_string(),
        })
        .await
        .unwrap();
    let op = service
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id,
            idempotency_key: "challenge-issue-key".to_string(),
        })
        .await
        .unwrap();

    // Seed one challenge session and one cleanup_failed lease directly
    // through the repositories (no presenter needed for the API surface).
    // A prepared session always references its lease; that reference is how
    // leases outside the scanner queue are discovered.
    let lease_id = ChallengeLeaseId::generate();
    repositories
        .challenge_sessions
        .create(ChallengeSession {
            id: "chs_api_1".to_string(),
            operation_id: op.id.clone(),
            authorization_url: "https://acme.example/authz/1".to_string(),
            challenge_url: "https://acme.example/challenge/1".to_string(),
            identifier: Identifier::try_dns("example.com").unwrap(),
            challenge_type: ChallengeType::Dns01,
            token_hash: ChallengeSession::hash_token("raw-challenge-token"),
            state: ChallengeSessionState::Prepared,
            lease_id: Some(lease_id.clone()),
            deadline: Timestamp::now()
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap(),
            last_error: None,
        })
        .await
        .unwrap();

    repositories
        .challenge_leases
        .create(ChallengeLease {
            id: lease_id.clone(),
            operation_id: op.id.clone(),
            identifier: Identifier::try_dns("example.com").unwrap(),
            challenge_type: ChallengeType::Dns01,
            locator: ChallengeLeaseLocator::Dns {
                provider_id: "dns-test".to_string(),
                zone: "example.com".to_string(),
                record_name: "_acme-challenge.example.com".to_string(),
                record_id: None,
                value_hash: "deadbeef".to_string(),
            },
            created_at: Timestamp::now(),
            expires_at: Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .unwrap(),
            state: ChallengeLeaseState::CleanupFailed,
            cleanup_attempts: 5,
            last_cleanup_error: Some("provider unavailable".to_string()),
            cleaned_at: None,
        })
        .await
        .unwrap();

    let query: Arc<dyn CertificateQuery> = service.clone();
    let application: Arc<dyn CertificateApplication> = service;
    let app = axum::Router::new()
        .nest("/api/v1", acmex::server::api_v1::routes())
        .with_state(app_state_from_parts(
            application,
            query,
            Some(repositories.clone()),
        ));

    // GET /operations/{id}/challenges returns the session with no token
    // material anywhere in the serialized body.
    let sessions_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/operations/{}/challenges", op.id))
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sessions_response.status(), StatusCode::OK);
    let sessions_body = axum::body::to_bytes(sessions_response.into_body(), 8192)
        .await
        .unwrap();
    let sessions_text = String::from_utf8(sessions_body.to_vec()).unwrap();
    assert!(
        !sessions_text.contains("token"),
        "session views must not leak token material: {sessions_text}"
    );
    let sessions: serde_json::Value = serde_json::from_str(&sessions_text).unwrap();
    assert_eq!(sessions.as_array().map(Vec::len), Some(1));
    assert_eq!(sessions[0]["id"], "chs_api_1");
    assert_eq!(sessions[0]["identifier"], "example.com");
    assert_eq!(sessions[0]["challenge_type"], "dns-01");
    assert_eq!(sessions[0]["state"], "prepared");
    assert_eq!(sessions[0]["operation_id"], op.id.as_str());

    // Unknown operation → 404, consistent with GET /operations/{id}.
    let missing_op = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/operations/op_missing/challenges")
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_op.status(), StatusCode::NOT_FOUND);

    // GET /challenge-cleanup lists the cleanup_failed lease (redacted).
    let pending_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/challenge-cleanup")
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pending_response.status(), StatusCode::OK);
    let pending_body = axum::body::to_bytes(pending_response.into_body(), 8192)
        .await
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&pending_body).unwrap();
    let lease_view = pending
        .as_array()
        .unwrap()
        .iter()
        .find(|view| view["id"] == lease_id.as_str())
        .expect("cleanup_failed lease must be listed")
        .clone();
    assert_eq!(lease_view["state"], "cleanup_failed");
    assert_eq!(lease_view["cleanup_attempts"], 5);
    assert!(
        lease_view["locator_summary"]
            .as_str()
            .unwrap()
            .contains("_acme-challenge.example.com")
    );
    assert!(
        !String::from_utf8(pending_body.to_vec())
            .unwrap()
            .contains("deadbeef")
    );

    // pending=false is not a supported view in v1.
    let not_pending = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/challenge-cleanup?pending=false")
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_pending.status(), StatusCode::BAD_REQUEST);

    // POST retry: cleanup_failed → cleanup_pending, audit trail preserved.
    let retry_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/challenge-cleanup/{}/retry", lease_id))
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_body = axum::body::to_bytes(retry_response.into_body(), 8192)
        .await
        .unwrap();
    let retried: serde_json::Value = serde_json::from_slice(&retry_body).unwrap();
    assert_eq!(retried["state"], "cleanup_pending");
    assert_eq!(retried["cleanup_attempts"], 5, "attempts must not reset");
    assert_eq!(retried["last_cleanup_error"], "provider unavailable");

    let stored = repositories
        .challenge_leases
        .get(&lease_id)
        .await
        .unwrap()
        .expect("lease must still exist");
    assert_eq!(stored.value.state, ChallengeLeaseState::CleanupPending);
    assert_eq!(stored.value.cleanup_attempts, 5);

    // Retrying a non-failed lease → 409.
    let conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/challenge-cleanup/{}/retry", lease_id))
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict_body = axum::body::to_bytes(conflict.into_body(), 4096)
        .await
        .unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&conflict_body).unwrap();
    assert_eq!(problem["error_code"], "IDEMPOTENCY_OR_CAS_CONFLICT");

    // Unknown lease → 404.
    let missing = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/challenge-cleanup/chl_missing/retry")
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_key_auth_enforces_route_permissions() {
    let app = axum::Router::new()
        .nest(
            "/api/v1",
            acmex::server::api_v1::routes().layer(axum::middleware::from_fn_with_state(
                read_only_application_state(),
                api_key_auth,
            )),
        )
        .with_state(read_only_application_state());

    let allowed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/operations")
                .header("X-API-Key", "read-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);

    let forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/certificate-versions/ver_test/revoke")
                .header("X-API-Key", "read-key")
                .header("Idempotency-Key", "revoke-key")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    // Manual cleanup retry is an admin-tier remediation (T05): read-only
    // keys may inspect the queue but must not requeue leases.
    let cleanup_read = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/challenge-cleanup")
                .header("X-API-Key", "read-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cleanup_read.status(), StatusCode::OK);

    let cleanup_retry_forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/challenge-cleanup/chl_test/retry")
                .header("X-API-Key", "read-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cleanup_retry_forbidden.status(), StatusCode::FORBIDDEN);

    // Intent patches mutate the aggregate in place (T08) and stay in the
    // intent.write tier: read-only keys must not patch policies.
    let patch_forbidden = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/certificate-intents/int_test")
                .header("X-API-Key", "read-key")
                .header("Idempotency-Key", "patch-key")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "renewal_policy": { "prefer_ari": false } }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patch_forbidden.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn readiness_reports_missing_management_credentials() {
    let mut state = application_state();
    state.api_keys = Arc::new(ApiKeySet::default());
    let app = axum::Router::new()
        .route(
            "/ready",
            axum::routing::get(acmex::server::health::ready_handler),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let ready: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ready["status"], "not_ready");
    assert_eq!(ready["checks"]["management_credentials"], "missing");
}

#[tokio::test]
async fn diagnostics_are_available_behind_api_key_auth() {
    let state = application_state();
    let app = axum::Router::new()
        .route(
            "/api/diagnostics",
            axum::routing::get(acmex::server::health::diagnostics_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api_key_auth,
        ))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/diagnostics")
                .header("X-API-Key", "test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let diagnostics: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(diagnostics["configured_metrics"].is_array());
    assert_eq!(diagnostics["pending_outbox"], 0);
}

#[tokio::test]
async fn legacy_revoke_creates_operation_instead_of_silent_success() {
    let state = application_state();
    let app = axum::Router::new()
        .route(
            "/api/certificates/{id}/revoke",
            axum::routing::post(acmex::server::certificate::revoke_certificate),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/certificates/ver_legacy/revoke")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // The legacy route must no longer fake success with 204: it either
    // creates a durable revoke operation (202) or explains why not.
    assert_ne!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        response.status() == StatusCode::ACCEPTED
            || response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::BAD_REQUEST,
        "unexpected status {}",
        response.status()
    );
}

#[tokio::test]
async fn rate_limited_responses_carry_retry_after_header() {
    // Verify the error→response mapping (header behavior is not reachable
    // through a scripted handler failure).
    let err = acmex::error::AcmeError::RateLimited(Some(std::time::Duration::from_secs(37)));
    let response = acmex::server::api_v1::error_response_for_tests(err);
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok());
    assert_eq!(retry_after, Some("37"));
}
