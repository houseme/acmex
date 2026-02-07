use crate::server::api::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Middleware for API Key authentication
pub async fn api_key_auth(
    State(_state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("X-API-Key").and_then(|h| h.to_str().ok());

    // In a real scenario, we would check against a configured key in AppState
    // For now, we'll use a placeholder logic or ignore if not configured
    match auth_header {
        Some(key) if key == "secret-admin-key" => Ok(next.run(req).await),
        _ => {
            tracing::warn!("Unauthorized access attempt to API");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
