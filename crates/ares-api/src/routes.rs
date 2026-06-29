use crate::state::{AppState, WebhookConfig};
use ares_core::{Finding, Severity};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct FindingsQuery {
    pub program_id: Option<String>,
    pub severity: Option<String>,
    pub class: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct FindingsResponse {
    pub count: usize,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct RiskResponse {
    pub program_id: String,
    pub risk: ares_core::RiskScore,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/findings", get(list_findings))
        .route("/findings/:id", get(get_finding))
        .route("/programs/:id/risk", get(get_risk))
        .route("/families", get(list_families))
        .route("/webhooks/register", post(register_webhook))
        .route("/eval/metrics", get(eval_metrics))
        .with_state(std::sync::Arc::new(state))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: "0.1.0".to_string(),
    })
}

async fn list_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(query): Query<FindingsQuery>,
) -> Json<FindingsResponse> {
    let findings = state
        .get_findings(
            query.program_id.as_deref(),
            query.severity.as_deref(),
            query.class.as_deref(),
        )
        .await;

    Json(FindingsResponse {
        count: findings.len(),
        findings,
    })
}

async fn get_finding(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Finding>, (StatusCode, String)> {
    state
        .get_finding_by_id(&id)
        .await
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, format!("Finding {} not found", id)))
}

async fn get_risk(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<RiskResponse>, (StatusCode, String)> {
    let scores = state.risk_scores.read().await;
    match scores.get(&id) {
        Some(risk) => Ok(Json(RiskResponse {
            program_id: id,
            risk: risk.clone(),
        })),
        None => Err((StatusCode::NOT_FOUND, format!("No risk score for {}", id))),
    }
}

async fn list_families(
    State(_state): State<std::sync::Arc<AppState>>,
) -> Json<serde_json::Value> {
    // TODO: Integrate with Python ares_family service
    Json(serde_json::json!({
        "families": [],
        "message": "Family clustering service not yet connected. Start python/ares_family service."
    }))
}

#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
    pub min_severity: Option<String>,
    pub event_types: Option<Vec<String>>,
}

async fn register_webhook(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<RegisterWebhookRequest>,
) -> Result<Json<WebhookConfig>, (StatusCode, String)> {
    let config = WebhookConfig {
        id: Uuid::new_v4().to_string(),
        url: req.url,
        min_severity: req.min_severity.unwrap_or_else(|| "high".to_string()),
        event_types: req.event_types.unwrap_or_else(|| vec!["finding".to_string()]),
    };

    let mut webhooks = state.webhooks.write().await;
    webhooks.push(config.clone());

    Ok(Json(config))
}

async fn eval_metrics(
    State(_state): State<std::sync::Arc<AppState>>,
) -> Json<serde_json::Value> {
    // TODO: Proxy to Python ares_eval service
    Json(serde_json::json!({
        "message": "Eval lab service not yet connected. Start python/ares_eval service.",
        "metrics": {}
    }))
}
