use crate::error::ProblemDetails;
use crate::server::api::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub id: String,
    pub serial: String,
    pub expiry: String,
}

pub async fn list_certificates(State(_state): State<AppState>) -> impl IntoResponse {
    // Real implementation would list from StorageBackend via CertificateStore
    Json(vec![CertificateResponse {
        id: "cert_123".to_string(),
        serial: "0123456789abcdef".to_string(),
        expiry: "2026-05-08T00:00:00Z".to_string(),
    }])
}

pub async fn get_certificate(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    Json(CertificateResponse {
        id,
        serial: "0123456789abcdef".to_string(),
        expiry: "2026-05-08T00:00:00Z".to_string(),
    })
}

pub async fn renew_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    info!("Triggering manual renewal for certificate: {}", id);

    if let Some(client) = state.client {
        // In v0.7.0 we integrate with CertificateRenewer orchestrator
        // For demonstration, returning a simulated response
        (
            StatusCode::ACCEPTED,
            Json(CertificateResponse {
                id,
                serial: "renewing...".to_string(),
                expiry: "pending".to_string(),
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

pub async fn revoke_certificate(
    State(_state): State<AppState>,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    StatusCode::NO_CONTENT
}
