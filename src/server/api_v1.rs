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
use crate::domain::{ChallengeLeaseId, IntentId, LineageId, OperationId, TargetId, VersionId};
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
        .route(
            "/operations/{id}/challenges",
            get(list_operation_challenges),
        )
        .route("/challenge-cleanup", get(list_challenge_cleanup))
        .route(
            "/challenge-cleanup/{id}/retry",
            post(retry_challenge_cleanup),
        )
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

/// PATCH /certificate-intents/{id} body.
///
/// Only the mutable policy fields are modeled; immutable fields are
/// captured as raw values purely so attempts can be rejected with a 400
/// naming them (serde would otherwise silently drop unknown keys).
#[derive(Debug, Deserialize)]
pub struct PatchIntentRequest {
    /// Full replacement of the renewal policy; omitted keeps the current.
    #[serde(default)]
    pub renewal_policy: Option<crate::domain::RenewalPolicy>,
    /// Full replacement of the delivery target list; omitted keeps the
    /// current list.
    #[serde(default)]
    pub delivery_targets: Option<Vec<crate::domain::DeliveryTarget>>,
    #[serde(default)]
    ca_policy: Option<serde_json::Value>,
    #[serde(default)]
    validation_policy: Option<serde_json::Value>,
    #[serde(default)]
    key_policy: Option<serde_json::Value>,
    #[serde(default)]
    identifiers: Option<serde_json::Value>,
    #[serde(default)]
    idempotency_key: Option<serde_json::Value>,
}

impl PatchIntentRequest {
    /// Immutable intent fields present in the patch body, in stable order.
    fn immutable_fields(&self) -> Vec<&'static str> {
        [
            ("identifiers", self.identifiers.is_some()),
            ("ca_policy", self.ca_policy.is_some()),
            ("validation_policy", self.validation_policy.is_some()),
            ("key_policy", self.key_policy.is_some()),
            ("idempotency_key", self.idempotency_key.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect()
    }
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

#[derive(Debug, Deserialize)]
pub struct CleanupQuery {
    /// Whether to list the pending cleanup queue. Defaults to `true`;
    /// `false` is rejected because v1 exposes no non-pending lease view.
    #[serde(default = "default_pending")]
    pub pending: bool,
}

fn default_pending() -> bool {
    true
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
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    // A rate-limited response carries the server-provided hint as an HTTP
    // header, not only inside the problem body.
    if let AcmeError::RateLimited(Some(retry_after)) = &err {
        let value = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string());
        if let Ok(value) = value {
            response.headers_mut().insert("Retry-After", value);
        }
    }
    response
}

/// Test-only exposure of the error→response mapping (header behavior is not
/// reachable through a scripted handler failure).
#[doc(hidden)]
pub fn error_response_for_tests(err: AcmeError) -> Response {
    error_response(err)
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

/// Parses the optional `If-Match` header as the expected intent generation.
///
/// Accepts the bare generation (`2`) and the quoted ETag form (`"2"`);
/// anything else is rejected as invalid input. Unconditional
/// (last-write-wins) patches omit the header entirely.
fn if_match_generation(headers: &HeaderMap) -> Result<Option<u64>> {
    headers
        .get("If-Match")
        .map(|value| {
            let raw = value
                .to_str()
                .map_err(|_| AcmeError::invalid_input("If-Match must carry the intent generation"))?
                .trim();
            raw.trim_matches('"').parse::<u64>().map_err(|_| {
                AcmeError::invalid_input(format!(
                    "If-Match `{raw}` is not a valid intent generation"
                ))
            })
        })
        .transpose()
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

pub async fn list_intents(
    State(state): State<AppState>,
    Query(page): Query<PageQuery>,
) -> Response {
    let result = async { query(&state)?.list_intents(page.limit).await }.await;
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

/// PATCH /certificate-intents/{id}
///
/// Synchronous mutable-policy patch (T08 residual): `renewal_policy` and
/// `delivery_targets` are fully replaced when present, omitted fields keep
/// their current values. `identifiers`, `ca_policy`, `validation_policy`,
/// `key_policy` and `idempotency_key` are immutable for v1 (a certificate's
/// SAN set cannot change in place — create a new intent instead); naming
/// any of them is a 400 that lists the offending fields.
///
/// Optimistic concurrency: an `If-Match` header carrying the previously
/// observed generation rejects stale writers with 409; without it the patch
/// applies last-write-wins. Every effective patch bumps the intent
/// generation by one; a patch that changes no stored value is an idempotent
/// no-op returning the current view without a bump.
///
/// Returns 200 with the updated IntentView. No operation is created, so
/// there is nothing to poll (no 202); an `Idempotency-Key` is still
/// required, like every mutating certificate route.
pub async fn update_intent(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<PatchIntentRequest>,
) -> Response {
    let result = async {
        let intent_id = IntentId::new(id)?;
        let immutable = payload.immutable_fields();
        if !immutable.is_empty() {
            return Err(AcmeError::invalid_input(format!(
                "intent fields are immutable: {} (create a new intent instead)",
                immutable.join(", ")
            )));
        }
        if payload.renewal_policy.is_none() && payload.delivery_targets.is_none() {
            return Err(AcmeError::invalid_input(
                "patch requires at least one mutable field: renewal_policy or delivery_targets",
            ));
        }
        application(&state)?
            .update_intent(
                (
                    actor_context(actor),
                    intent_id,
                    payload.renewal_policy,
                    payload.delivery_targets,
                    if_match_generation(&headers)?,
                    idempotency_key(&headers)?,
                )
                    .into(),
            )
            .await
    }
    .await;
    match result {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(err) => error_response(err),
    }
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

/// GET /operations/{id}/challenges
///
/// Token-safe challenge sessions of one operation (T05): the serialized
/// views never contain the token, its hash or a key authorization. Returns
/// 404 when the operation is unknown, consistent with GET /operations/{id}.
pub async fn list_operation_challenges(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let result = async {
        let id = OperationId::new(id)?;
        query(&state)?
            .get_operation(&id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("operation `{id}` not found")))?;
        query(&state)?.list_challenge_sessions(&id).await
    }
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(err) => error_response(err),
    }
}

/// GET /challenge-cleanup?pending=true
///
/// The operator's cleanup queue (T05): `active`, `cleanup_pending` and
/// `cleanup_failed` leases as redacted lease views. `cleanup_failed` is
/// what the manual retry entry acts on. Views never contain token or key
/// authorization material.
pub async fn list_challenge_cleanup(
    State(state): State<AppState>,
    Query(page): Query<CleanupQuery>,
) -> Response {
    let result = async {
        if !page.pending {
            return Err(AcmeError::invalid_input(
                "challenge-cleanup only exposes the pending cleanup queue; set pending=true or omit it",
            ));
        }
        query(&state)?.list_cleanup_pending().await
    }
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(err) => error_response(err),
    }
}

/// POST /challenge-cleanup/{id}/retry
///
/// Manual retry entry for a stuck cleanup (T05): requeues a
/// `cleanup_failed` lease back to `cleanup_pending` through a guarded CAS
/// transition without resetting `cleanup_attempts` (the audit trail of the
/// failed attempts is preserved). The background `ChallengeCleanupScanner`
/// picks the lease up on its next pass. Returns 409 when the lease is not
/// `cleanup_failed` and 404 when it is unknown. No Idempotency-Key is
/// required: the state-guarded CAS transition is naturally idempotent.
pub async fn retry_challenge_cleanup(
    State(state): State<AppState>,
    actor: Option<Extension<ActorContext>>,
    Path(id): Path<String>,
) -> Response {
    let result = async {
        let lease_id = ChallengeLeaseId::new(id)?;
        application(&state)?
            .retry_challenge_cleanup(actor_context(actor), lease_id)
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

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("If-Match", HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn if_match_accepts_bare_and_quoted_generations() {
        assert_eq!(if_match_generation(&headers_with("2")).unwrap(), Some(2));
        assert_eq!(
            if_match_generation(&headers_with("\"2\"")).unwrap(),
            Some(2)
        );
        assert_eq!(if_match_generation(&HeaderMap::new()).unwrap(), None);
    }

    #[test]
    fn if_match_rejects_non_generation_values() {
        assert!(if_match_generation(&headers_with("*")).is_err());
        assert!(if_match_generation(&headers_with("abc")).is_err());
        assert!(if_match_generation(&headers_with("-1")).is_err());
    }
}
