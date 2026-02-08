use crate::certificate::OcspVerifier;
use crate::error::ProblemDetails;
use crate::orchestrator::OrchestrationStatus;
use crate::server::api::{AppState, TaskInfo};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use rand::RngExt;
use rand::distr::Alphanumeric;
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

pub async fn list_certificates(State(_state): State<AppState>) -> impl IntoResponse {
    // Real implementation would list from StorageBackend via CertificateStore
    Json(vec![CertificateResponse {
        id: "cert_123".to_string(),
        serial: "0123456789abcdef".to_string(),
        expiry: "2026-05-08T00:00:00Z".to_string(),
        ocsp_status: None,
    }])
}

pub async fn get_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // In a real implementation, we'd load the cert from state.storage
    // and then check OCSP status.

    let mut ocsp_status = None;
    if let Some(storage) = &state.storage
        && let Ok(Some(cert_data)) = storage.load(&format!("cert:{}", id)).await
            && let Ok(status) = OcspVerifier::verify_status(&cert_data).await {
                ocsp_status = Some(format!("{:?}", status));
            }

    Json(CertificateResponse {
        id,
        serial: "0123456789abcdef".to_string(),
        expiry: "2026-05-08T00:00:00Z".to_string(),
        ocsp_status,
    })
}

pub async fn renew_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    info!("Triggering manual renewal for certificate: {}", id);

    // 1. Check if client and storage are configured
    if state.client.is_none() || state.storage.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProblemDetails {
                problem_type: "https://acmex.sh/errors/config".into(),
                title: "Server poorly configured".into(),
                status: 503,
                detail: "ACME client or Storage backend missing".into(),
                instance: None,
            }),
        )
            .into_response();
    }

    // 2. Generate task ID
    let task_id: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let state_clone = state.clone();
    let task_id_clone = task_id.clone();
    let cert_id = id.clone();

    // 3. Spawn background renewal task
    tokio::spawn(async move {
        // Initial status
        {
            let mut tasks = state_clone.tasks.write().await;
            tasks.insert(
                task_id_clone.clone(),
                TaskInfo {
                    status: OrchestrationStatus::InProgress {
                        progress: 0.1,
                        message: format!("Renewal started for cert {}", cert_id),
                    },
                    domains: vec![], // Domains unknown at this trigger point
                },
            );
        }

        // Real renewal logic would use CertificateRenewer or directly call Provisioner
        // For demonstration, we simulate success
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let mut tasks = state_clone.tasks.write().await;
        if let Some(task) = tasks.get_mut(&task_id_clone) {
            task.status = OrchestrationStatus::Completed;
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(CertificateResponse {
            id: task_id,
            serial: "renewal_in_progress".to_string(),
            expiry: "pending".to_string(),
            ocsp_status: None,
        }),
    )
        .into_response()
}

pub async fn revoke_certificate(
    State(_state): State<AppState>,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    StatusCode::NO_CONTENT
}
