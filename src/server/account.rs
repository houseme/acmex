use crate::metrics::AcmeEvent;
use crate::metrics::events::EventAuditor;
use crate::server::api::AppState;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub email: String,
    pub tos_agreed: bool,
}

#[derive(Debug, Serialize)]
pub struct AccountResponse {
    pub id: String,
    pub status: String,
    pub contact: Vec<String>,
}

pub async fn create_account(
    State(state): State<AppState>,
    Json(payload): Json<CreateAccountRequest>,
) -> impl IntoResponse {
    info!("Request to create account for email: {}", payload.email);

    // Track event
    EventAuditor::track_event(AcmeEvent::AccountCreated {
        email: payload.email.clone(),
    });

    if let Some(client) = state.client {
        // Clone the client from Arc to get a mutable instance
        let mut client = (*client).clone();
        match client.register_account().await {
            Ok(account_id) => {
                return (
                    StatusCode::CREATED,
                    Json(AccountResponse {
                        id: account_id,
                        status: "valid".to_string(),
                        contact: vec![format!("mailto:{}", payload.email)],
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to register account: {}", e),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        "ACME client not configured on server",
    )
        .into_response()
}

pub async fn get_account(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    Json(AccountResponse {
        id: format!("https://acme-v02.api.letsencrypt.org/acme/acct/{}", id),
        status: "valid".to_string(),
        contact: vec!["mailto:admin@example.com".to_string()],
    })
}

pub async fn update_account(
    State(_state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateAccountRequest>,
) -> impl IntoResponse {
    Json(AccountResponse {
        id: format!("https://acme-v02.api.letsencrypt.org/acme/acct/{}", id),
        status: "valid".to_string(),
        contact: vec![format!("mailto:{}", payload.email)],
    })
}

pub async fn deactivate_account(
    State(_state): State<AppState>,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    StatusCode::NO_CONTENT
}
