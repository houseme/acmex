/// Webhook handler implementation
use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use std::sync::Arc;

use crate::notifications::WebhookManager;

/// Webhook payload
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookPayload {
    /// Event type
    pub event: String,
    /// Event data
    pub data: serde_json::Value,
}

/// Webhook handler
pub struct WebhookHandler {
    /// Webhook manager
    #[allow(dead_code)]
    manager: Arc<WebhookManager>,
}

impl WebhookHandler {
    /// Create a new webhook handler
    pub fn new(manager: Arc<WebhookManager>) -> Self {
        Self { manager }
    }
}

/// Axum handler for incoming webhooks (e.g. from external systems triggering actions)
/// Note: This is different from the WebhookManager which sends notifications OUT
/// This handler receives requests to trigger actions in AcmeX
pub async fn webhook_handler(
    axum::extract::State(_handler): axum::extract::State<Arc<WebhookHandler>>,
    Json(payload): Json<WebhookPayload>,
) -> impl IntoResponse {
    tracing::info!("Received webhook event: {}", payload.event);

    // Process the webhook based on event type
    // This is a placeholder for actual logic
    // For example, "renew_certificate" event could trigger a renewal

    match payload.event.as_str() {
        "ping" => (StatusCode::OK, Json(serde_json::json!({"status": "pong"}))),
        _ => {
            tracing::warn!("Unknown webhook event: {}", payload.event);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Unknown event type"})),
            )
        }
    }
}
