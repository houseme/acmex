use crate::application::{ActorContext, CreateCertificateIntent, IssueCertificate};
use crate::error::ProblemDetails;
use crate::metrics::AcmeEvent;
use crate::metrics::events::EventAuditor;
use crate::server::api::AppState;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
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

    let request_key: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

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

    let intent = match application
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: payload.domains.clone(),
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: Default::default(),
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            idempotency_key: format!("legacy-order-intent-{request_key}"),
        })
        .await
    {
        Ok(intent) => intent,
        Err(err) => {
            let problem = err.to_problem_details();
            return (
                StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(problem),
            )
                .into_response();
        }
    };

    let op = match application
        .issue(IssueCertificate {
            context: ActorContext::default(),
            intent_id: intent.id,
            idempotency_key: format!("legacy-order-issue-{request_key}"),
        })
        .await
    {
        Ok(op) => op,
        Err(err) => {
            let problem = err.to_problem_details();
            return (
                StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(problem),
            )
                .into_response();
        }
    };

    (
        StatusCode::ACCEPTED,
        Json(OrderResponse {
            id: op.id.to_string(),
            status: "accepted".to_string(),
            domains: payload.domains,
        }),
    )
        .into_response()
}

pub async fn list_orders(State(state): State<AppState>) -> Response {
    if let Some(query) = &state.query
        && let Ok(operations) = query.list_operations(100).await
    {
        let response: Vec<OrderResponse> = operations
            .into_iter()
            .filter(|op| op.kind == "issue" || op.kind == "renew")
            .map(|op| OrderResponse {
                id: op.id.to_string(),
                status: op.status,
                domains: Vec::new(),
            })
            .collect();
        return Json(response).into_response();
    }

    let tasks = state.tasks.read().await;
    let response: Vec<OrderResponse> = tasks
        .iter()
        .map(|(id, info)| OrderResponse {
            id: id.clone(),
            status: format!("{:?}", info.status),
            domains: info.domains.clone(),
        })
        .collect();

    Json(response).into_response()
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
    if let Some(query) = &state.query
        && let Ok(operation_id) = crate::domain::OperationId::new(id.clone())
    {
        match query.get_operation(&operation_id).await {
            Ok(Some(op)) => {
                return (
                    StatusCode::OK,
                    Json(OrderResponse {
                        id,
                        status: op.status,
                        domains: Vec::new(),
                    }),
                )
                    .into_response();
            }
            Ok(None) => {}
            Err(err) => {
                error!("Failed to read operation {id}: {err}");
            }
        }
    }

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
