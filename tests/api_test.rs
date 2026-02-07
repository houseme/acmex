use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

use acmex::config::Config;
use acmex::notifications::WebhookManager;
use acmex::orchestrator::OrchestrationStatus;
use acmex::server::api::{AppState, TaskInfo};

#[tokio::test]
async fn test_api_renew_all() {
    let config = Arc::new(Config::default());
    let tasks = Arc::new(RwLock::new(HashMap::new()));
    let health = Arc::new(acmex::server::HealthCheck::new());
    let webhook_manager = Arc::new(WebhookManager::new(vec![]));
    let webhook = Arc::new(acmex::server::WebhookHandler::new(webhook_manager));
    let api_keys = Arc::new(vec!["test-key".to_string()]);

    let state = AppState {
        config,
        client: None,
        storage: None,
        health,
        webhook,
        tasks,
        api_keys,
        scheduler: None,
    };

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
    let config = Arc::new(Config::default());
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

    let state = AppState {
        config,
        client: None,
        storage: None,
        health: Arc::new(acmex::server::HealthCheck::new()),
        webhook: Arc::new(acmex::server::WebhookHandler::new(Arc::new(
            WebhookManager::new(vec![]),
        ))),
        tasks,
        api_keys: Arc::new(vec!["test-key".to_string()]),
        scheduler: None,
    };

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
