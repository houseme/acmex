use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::application::{
    ActorContext, CancelOperation, CertificateApplication, CertificateQuery,
    CreateCertificateIntent, DeployCertificate, IssueCertificate, RenewCertificate,
    RevokeCertificate,
};
use crate::domain::{IntentId, LineageId, OperationId, TargetId, VersionId};
use crate::error::{AcmeError, Result};
use crate::server::api::AppState;

/// Builds the v1 certificate lifecycle API.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/certificate-intents",
            post(create_intent).get(list_intents),
        )
        .route(
            "/certificate-intents/{id}",
            get(get_intent).patch(update_intent),
        )
        .route("/certificate-intents/{id}/issue", post(issue_intent))
        .route("/certificate-lineages/{id}", get(get_lineage))
        .route("/certificate-lineages/{id}/renew", post(renew_lineage))
        .route("/certificate-lineages/{id}/versions", get(list_versions))
        .route("/certificate-versions/{id}", get(get_version))
        .route("/certificate-versions/{id}/chain", get(get_version_chain))
        .route("/certificate-versions/{id}/deploy", post(deploy_version))
        .route("/certificate-versions/{id}/revoke", post(revoke_version))
        .route("/operations", get(list_operations))
        .route("/operations/{id}", get(get_operation))
        .route("/operations/{id}/cancel", post(cancel_operation))
}

#[derive(Debug, Deserialize)]
pub struct CreateIntentRequest {
    pub identifiers: Vec<String>,
    #[serde(default)]
    pub ca_policy: crate::domain::CaPolicy,
    #[serde(default)]
    pub validation_policy: crate::domain::ValidationPolicy,
    #[serde(default)]
    pub key_policy: crate::domain::KeyPolicy,
    #[serde(default)]
    pub renewal_policy: crate::domain::RenewalPolicy,
    #[serde(default)]
    pub delivery_targets: Vec<crate::domain::DeliveryTarget>,
}

#[derive(Debug, Deserialize)]
pub struct RenewRequest {
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    #[serde(default)]
    pub target_ids: Vec<TargetId>,
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct ApiProblem {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub error_code: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl ApiProblem {
    fn from_error(err: &AcmeError) -> Self {
        let problem = err.to_problem_details();
        let (code, retryable) = match err {
            AcmeError::InvalidInput(_) => ("INVALID_INPUT", false),
            AcmeError::NotFound(_) => ("RESOURCE_NOT_FOUND", false),
            AcmeError::Conflict(_) => ("IDEMPOTENCY_OR_CAS_CONFLICT", false),
            AcmeError::Configuration(_) => ("CONFIGURATION_ERROR", false),
            AcmeError::RateLimited(_) => ("RATE_LIMITED", true),
            AcmeError::Timeout(_) => ("TIMEOUT", true),
            AcmeError::Transport(_) => ("UPSTREAM_TRANSPORT_ERROR", true),
            _ => ("INTERNAL", false),
        };
        Self {
            problem_type: problem.problem_type,
            title: problem.title,
            status: problem.status,
            detail: problem.detail,
            error_code: code.to_string(),
            retryable,
            operation_id: None,
        }
    }
}

fn error_response(err: AcmeError) -> Response {
    let body = ApiProblem::from_error(&err);
    let status = StatusCode::from_u16(body.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(body)).into_response()
}

fn idempotency_key(headers: &HeaderMap) -> Result<String> {
    headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AcmeError::invalid_input(
                "Idempotency-Key is required for mutating certificate requests",
            )
        })
}

fn actor_context(actor: Option<Extension<ActorContext>>) -> ActorContext {
    actor.map(|Extension(actor)| actor).unwrap_or_default()
}

fn location(path: String) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&path) {
        headers.insert(header::LOCATION, value);
    }
    headers
}

fn application(state: &AppState) -> Result<&std::sync::Arc<dyn CertificateApplication>> {
    state.application.as_ref().ok_or_else(|| {
        AcmeError::configuration("certificate application service is not configured")
    })
}

fn query(state: &AppState) -> Result<&std::sync::Arc<dyn CertificateQuery>> {
    state
        .query
        .as_ref()
        .ok_or_else(|| AcmeError::configuration("certificate query service is not configured"))
}

pub async fn create_intent(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    headers: HeaderMap,
    Json(payload): Json<CreateIntentRequest>,
) -> Response {
    let result = async {
        let view = application(&state)?
            .create_intent(CreateCertificateIntent {
                context: actor_context(actor),
                identifiers: payload.identifiers,
                ca_policy: payload.ca_policy,
                validation_policy: payload.validation_policy,
                key_policy: payload.key_policy,
                renewal_policy: payload.renewal_policy,
                delivery_targets: payload.delivery_targets,
                idempotency_key: idempotency_key(&headers)?,
            })
            .await?;
        Ok::<_, AcmeError>(view)
    }
    .await;
    match result {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn list_intents(State(state): State<AppState>) -> Response {
    let result = async { query(&state)?.list_intents().await }.await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn get_intent(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let parsed = IntentId::new(id);
    let result = async {
        let id = parsed?;
        query(&state)?
            .get_intent(&id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("intent `{id}` not found")))
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn update_intent() -> Response {
    error_response(AcmeError::invalid_input(
        "intent patch is not implemented in v0.9.0 M3",
    ))
}

pub async fn issue_intent(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let result = async {
        let intent_id = IntentId::new(id)?;
        let op = application(&state)?
            .issue(IssueCertificate {
                context: actor_context(actor),
                intent_id,
                idempotency_key: idempotency_key(&headers)?,
            })
            .await?;
        let view = query(&state)?
            .get_operation(&op.id)
            .await?
            .ok_or_else(|| AcmeError::storage("created operation is missing"))?;
        Ok::<_, AcmeError>(view)
    }
    .await;
    match result {
        Ok(view) => (
            StatusCode::ACCEPTED,
            location(format!("/api/v1/operations/{}", view.id)),
            Json(view),
        )
            .into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn get_lineage(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let result = async {
        let id = LineageId::new(id)?;
        query(&state)?
            .get_lineage(&id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("lineage `{id}` not found")))
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn renew_lineage(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<RenewRequest>,
) -> Response {
    let result = async {
        let lineage_id = LineageId::new(id)?;
        let op = application(&state)?
            .renew(RenewCertificate {
                context: actor_context(actor),
                lineage_id: Some(lineage_id),
                identifiers: Vec::new(),
                force: payload.force,
                idempotency_key: idempotency_key(&headers)?,
            })
            .await?;
        query(&state)?
            .get_operation(&op.id)
            .await?
            .ok_or_else(|| AcmeError::storage("created operation is missing"))
    }
    .await;
    match result {
        Ok(view) => (
            StatusCode::ACCEPTED,
            location(format!("/api/v1/operations/{}", view.id)),
            Json(view),
        )
            .into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn list_versions(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let result = async {
        let id = LineageId::new(id)?;
        query(&state)?.list_versions(&id).await
    }
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn get_version(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let result = async {
        let id = VersionId::new(id)?;
        query(&state)?
            .get_version(&id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("version `{id}` not found")))
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn get_version_chain(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let result = async {
        let id = VersionId::new(id)?;
        let stored = state
            .repositories
            .as_ref()
            .ok_or_else(|| AcmeError::configuration("repository is not configured"))?
            .versions
            .get(&id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("version `{id}` not found")))?;
        Ok::<_, AcmeError>(serde_json::json!({
            "version_id": id.as_str(),
            "certificate_chain_pem": stored.value.certificate_chain_pem,
        }))
    }
    .await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn deploy_version(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<DeployRequest>,
) -> Response {
    let result = async {
        let version_id = VersionId::new(id)?;
        let op = application(&state)?
            .deploy(DeployCertificate {
                context: actor_context(actor),
                version_id,
                target_ids: payload.target_ids,
                idempotency_key: idempotency_key(&headers)?,
            })
            .await?;
        query(&state)?
            .get_operation(&op.id)
            .await?
            .ok_or_else(|| AcmeError::storage("created operation is missing"))
    }
    .await;
    match result {
        Ok(view) => (
            StatusCode::ACCEPTED,
            location(format!("/api/v1/operations/{}", view.id)),
            Json(view),
        )
            .into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn revoke_version(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<RevokeRequest>,
) -> Response {
    let result = async {
        let version_id = VersionId::new(id)?;
        let op = application(&state)?
            .revoke(RevokeCertificate {
                context: actor_context(actor),
                version_id,
                reason: payload.reason,
                idempotency_key: idempotency_key(&headers)?,
            })
            .await?;
        query(&state)?
            .get_operation(&op.id)
            .await?
            .ok_or_else(|| AcmeError::storage("created operation is missing"))
    }
    .await;
    match result {
        Ok(view) => (
            StatusCode::ACCEPTED,
            location(format!("/api/v1/operations/{}", view.id)),
            Json(view),
        )
            .into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn list_operations(
    State(state): State<AppState>,
    Query(page): Query<PageQuery>,
) -> Response {
    let result = async { query(&state)?.list_operations(page.limit.min(500)).await }.await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn get_operation(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let result = async {
        let id = OperationId::new(id)?;
        query(&state)?
            .get_operation(&id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("operation `{id}` not found")))
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(err) => error_response(err),
    }
}

pub async fn cancel_operation(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    Path(id): Path<String>,
) -> Response {
    let result = async {
        let operation_id = OperationId::new(id)?;
        application(&state)?
            .cancel_operation(CancelOperation {
                context: actor_context(actor),
                operation_id,
            })
            .await
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(err) => error_response(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_details_include_stable_code_and_retryability() {
        let problem = ApiProblem::from_error(&AcmeError::conflict("same key, different body"));
        assert_eq!(problem.status, 409);
        assert_eq!(problem.error_code, "IDEMPOTENCY_OR_CAS_CONFLICT");
        assert!(!problem.retryable);
    }
}
