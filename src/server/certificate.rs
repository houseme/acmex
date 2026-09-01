use crate::application::{ActorContext, RenewCertificate};
use crate::domain::{LineageId, VersionId};
use crate::error::ProblemDetails;
use crate::server::api::AppState;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use tracing::info;

#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub id: String,
    pub serial: String,
    pub expiry: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp_status: Option<String>,
}

pub async fn list_certificates(State(state): State<AppState>) -> impl IntoResponse {
    let Some(repositories) = &state.repositories else {
        return Json(Vec::<CertificateResponse>::new()).into_response();
    };
    let mut response = Vec::new();
    let lineages = match repositories.lineages.list().await {
        Ok(lineages) => lineages,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err.to_problem_details()),
            )
                .into_response();
        }
    };
    for lineage in lineages {
        let Ok(versions) = repositories
            .versions
            .list_by_lineage(&lineage.value.id)
            .await
        else {
            continue;
        };
        response.extend(versions.into_iter().map(|version| CertificateResponse {
            id: version.value.id.to_string(),
            serial: version.value.serial,
            expiry: version.value.not_after,
            ocsp_status: None,
        }));
    }
    Json(response).into_response()
}

pub async fn get_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(repositories) = &state.repositories
        && let Ok(version_id) = VersionId::new(id.clone())
    {
        match repositories.versions.get(&version_id).await {
            Ok(Some(stored)) => {
                return Json(CertificateResponse {
                    id,
                    serial: stored.value.serial,
                    expiry: stored.value.not_after,
                    ocsp_status: None,
                })
                .into_response();
            }
            Ok(None) => {}
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(err.to_problem_details()),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(ProblemDetails {
            problem_type: "https://acmex.sh/errors/not-found".into(),
            title: "Certificate Not Found".into(),
            status: 404,
            detail: format!("No certificate version found with ID: {id}"),
            instance: None,
        }),
    )
        .into_response()
}

pub async fn renew_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    info!("Triggering manual renewal for certificate: {}", id);

    let Some(application) = &state.application else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProblemDetails {
                problem_type: "https://acmex.sh/errors/config".into(),
                title: "Server poorly configured".into(),
                status: 503,
                detail: "Application Service is not configured".into(),
                instance: None,
            }),
        )
            .into_response();
    };

    let lineage_id = match LineageId::new(id.clone()) {
        Ok(id) => id,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(err.to_problem_details())).into_response();
        }
    };

    match application
        .renew(RenewCertificate {
            context: ActorContext::default(),
            lineage_id: Some(lineage_id),
            identifiers: Vec::new(),
            force: true,
            idempotency_key: format!("legacy-renew-{id}"),
        })
        .await
    {
        Ok(op) => (StatusCode::ACCEPTED, Json(op)).into_response(),
        Err(err) => {
            let problem = err.to_problem_details();
            (
                StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(problem),
            )
                .into_response()
        }
    }
}

pub async fn revoke_certificate(
    State(_state): State<AppState>,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    StatusCode::NO_CONTENT
}
