use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

use acmex::application::{ApplicationServiceBuilder, CertificateApplication, CertificateQuery};
use acmex::config::Config;
use acmex::notifications::WebhookManager;
use acmex::orchestrator::OrchestrationStatus;
use acmex::server::api::{AppState, TaskInfo};
use acmex::server::auth::ApiKeySet;

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
        scheduler: None,
        repositories: None,
        application: None,
        query: None,
    }
}

fn application_state() -> AppState {
    let (service, repositories) = ApplicationServiceBuilder::new().build().unwrap();
    let query: Arc<dyn CertificateQuery> = service.clone();
    let application: Arc<dyn CertificateApplication> = service;
    AppState {
        config: Arc::new(Config::default()),
        client: None,
        storage: None,
        health: Arc::new(acmex::server::HealthCheck::new()),
        webhook: test_webhook(),
        tasks: Arc::new(RwLock::new(HashMap::new())),
        api_keys: Arc::new(ApiKeySet::from_plaintext_keys(["test-key"])),
        scheduler: None,
        repositories: Some(repositories),
        application: Some(application),
        query: Some(query),
    }
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
