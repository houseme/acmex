/// Webhook handler implementation
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use std::sync::Arc;

use super::api::AppState;
use crate::application::{ActorContext, RenewCertificate};
use crate::domain::LineageId;
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
    State(state): State<AppState>,
    Json(payload): Json<WebhookPayload>,
) -> impl IntoResponse {
    tracing::info!("Received webhook event: {}", payload.event);

    match payload.event.as_str() {
        "ping" => (StatusCode::OK, Json(serde_json::json!({"status": "pong"}))),
        "renew_certificate" | "certificate.renew_requested" => {
            let Some(application) = state.application.as_ref() else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "certificate lifecycle service is not available"
                    })),
                );
            };
            let Some(lineage) = payload.data.get("lineage_id").and_then(|v| v.as_str()) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "lineage_id is required for renew_certificate"
                    })),
                );
            };
            let lineage_id = match LineageId::new(lineage) {
                Ok(id) => id,
                Err(err) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": err.to_string()})),
                    );
                }
            };
            let idempotency_key = payload
                .data
                .get("idempotency_key")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("webhook-renew-{lineage_id}"));
            let force = payload
                .data
                .get("force")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            match application
                .renew(RenewCertificate {
                    context: ActorContext::default(),
                    lineage_id: Some(lineage_id),
                    identifiers: Vec::new(),
                    force,
                    idempotency_key,
                })
                .await
            {
                Ok(operation) => (
                    StatusCode::ACCEPTED,
                    Json(serde_json::json!({
                        "status": "accepted",
                        "operation_id": operation.id,
                        "operation_kind": operation.kind,
                    })),
                ),
                Err(err) => {
                    let problem = err.to_problem_details();
                    (
                        StatusCode::from_u16(problem.status)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        Json(serde_json::json!({"error": problem.detail})),
                    )
                }
            }
        }
        _ => {
            tracing::warn!("Unknown webhook event: {}", payload.event);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Unknown event type",
                    "supported_events": [
                        "ping",
                        "renew_certificate",
                        "certificate.renew_requested"
                    ]
                })),
            )
        }
    }
}
