use crate::error::ProblemDetails;
use crate::metrics::AcmeEvent;
use crate::metrics::events::EventAuditor;
use crate::orchestrator::{CertificateProvisioner, OrchestrationStatus, Orchestrator};
use crate::server::api::{AppState, TaskInfo};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use rand::RngExt;
use rand::distr::Alphanumeric;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

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

    // Track event
    EventAuditor::track_event(AcmeEvent::OrderCreated {
        domains: payload.domains.clone(),
    });

    // Generate a task ID
    let task_id: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let provisioner = CertificateProvisioner::new(payload.domains.clone());
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();

    // Initial status
    {
        let mut tasks = state.tasks.write().await;
        tasks.insert(
            task_id.clone(),
            TaskInfo {
                status: OrchestrationStatus::InProgress {
                    progress: 0.0,
                    message: "Starting order process".to_string(),
                },
                domains: payload.domains.clone(),
            },
        );
    }

    // Spawn the background task
    tokio::spawn(async move {
        match provisioner.execute(&state_clone.config).await {
            Ok(_) => {
                let mut tasks = state_clone.tasks.write().await;
                if let Some(task) = tasks.get_mut(&task_id_clone) {
                    task.status = OrchestrationStatus::Completed;
                }
                info!("Order task {} completed successfully", task_id_clone);
            }
            Err(e) => {
                let mut tasks = state_clone.tasks.write().await;
                if let Some(task) = tasks.get_mut(&task_id_clone) {
                    task.status = OrchestrationStatus::Failed(e.to_string());
                }
                error!("Order task {} failed: {}", task_id_clone, e);
            }
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(OrderResponse {
            id: task_id,
            status: "accepted".to_string(),
            domains: payload.domains,
        }),
    )
        .into_response()
}

pub async fn list_orders(State(state): State<AppState>) -> impl IntoResponse {
    let tasks = state.tasks.read().await;
    let response: Vec<OrderResponse> = tasks
        .iter()
        .map(|(id, info)| OrderResponse {
            id: id.clone(),
            status: format!("{:?}", info.status),
            domains: info.domains.clone(),
        })
        .collect();

    Json(response)
}

pub async fn trigger_full_renewal(State(state): State<AppState>) -> impl IntoResponse {
    info!("Manual trigger of full certificate renewal");

    if let Some(scheduler) = &state.scheduler {
        let scheduler_clone = scheduler.clone();
        tokio::spawn(async move {
            if let Err(e) = scheduler_clone.run_once().await {
                error!("Manual renewal run failed: {}", e);
            }
        });

        (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "triggered",
                "message": "Full renewal process started in background"
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "Renewal scheduler not initialized"
            })),
        )
            .into_response()
    }
}

pub async fn get_order(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let tasks = state.tasks.read().await;

    if let Some(info) = tasks.get(&id) {
        (
            StatusCode::OK,
            Json(OrderResponse {
                id,
                status: format!("{:?}", info.status),
                domains: info.domains.clone(),
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ProblemDetails {
                problem_type: "https://acmex.sh/errors/not-found".into(),
                title: "Task Not Found".into(),
                status: 404,
                detail: format!("No task found with ID: {}", id),
                instance: None,
            }),
        )
            .into_response()
    }
}
