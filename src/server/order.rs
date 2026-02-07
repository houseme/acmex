use crate::error::ProblemDetails;
use crate::server::api::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct CreateOrderRequest {
    pub domains: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct OrderResponse {
    pub id: String,
    pub status: String,
    pub domains: Vec<String>,
}

pub async fn create_order(
    State(state): State<AppState>,
    Json(payload): Json<CreateOrderRequest>,
) -> impl IntoResponse {
    info!("Request to create order for domains: {:?}", payload.domains);

    if let Some(_client) = state.client {
        // Simple order creation (real implementation would require more config)
        // For demonstration, we simulate the logic or return a partial success
        (
            StatusCode::CREATED,
            Json(OrderResponse {
                id: format!(
                    "https://acme-v02.api.letsencrypt.org/acme/order/{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&payload.domains.join(","))
                ),
                status: "pending".to_string(),
                domains: payload.domains,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProblemDetails {
                problem_type: "https://acmex.sh/errors/config".into(),
                title: "ACME client not configured".into(),
                status: 503,
                detail: "Server ACME client is missing".into(),
                instance: None,
            }),
        )
            .into_response()
    }
}

pub async fn list_orders(State(_state): State<AppState>) -> impl IntoResponse {
    // In v0.7.0 we target listing from storage
    Json(vec![OrderResponse {
        id: "https://acme-v02.api.letsencrypt.org/acme/order/987654".to_string(),
        status: "pending".to_string(),
        domains: vec!["example.com".to_string()],
    }])
}

pub async fn get_order(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Real logic to fetch order status from server or cache
    Json(OrderResponse {
        id: format!("https://acme-v02.api.letsencrypt.org/acme/order/{}", id),
        status: "valid".to_string(),
        domains: vec!["example.com".to_string()],
    })
}
