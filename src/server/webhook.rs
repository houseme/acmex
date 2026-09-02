/// Webhook handler implementation
use axum::{
    Json,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;

use super::api::AppState;
use crate::application::{ActorContext, RenewCertificate};
use crate::domain::LineageId;
use crate::error::AcmeError;
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
) -> Response {
    tracing::info!("Received webhook event: {}", payload.event);

    match payload.event.as_str() {
        "ping" => (StatusCode::OK, Json(serde_json::json!({"status": "pong"}))).into_response(),
        "renew_certificate" | "certificate.renew_requested" => {
            let Some(application) = state.application.as_ref() else {
                return problem_response(AcmeError::configuration(
                    "certificate lifecycle service is not available",
                ));
            };
            let Some(lineage) = payload.data.get("lineage_id").and_then(|v| v.as_str()) else {
                return problem_response(AcmeError::invalid_input(
                    "lineage_id is required for renew_certificate",
                ));
            };
            let lineage_id = match LineageId::new(lineage) {
                Ok(id) => id,
                Err(err) => return problem_response(err),
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
                )
                    .into_response(),
                Err(err) => problem_response(err),
            }
        }
        _ => {
            tracing::warn!("Unknown webhook event: {}", payload.event);
            problem_response(AcmeError::invalid_input(
                "Unknown event type. Supported events: ping, renew_certificate, certificate.renew_requested",
            ))
        }
    }
}

fn problem_response(err: AcmeError) -> Response {
    let problem = err.to_problem_details();
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, Json(problem)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}
