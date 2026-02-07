use crate::server::api::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Middleware for API Key authentication
pub async fn api_key_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("X-API-Key").and_then(|h| h.to_str().ok());

    match auth_header {
        Some(key) if state.api_keys.contains(&key.to_string()) => Ok(next.run(req).await),
        _ => {
            tracing::warn!("Unauthorized access attempt to API");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
