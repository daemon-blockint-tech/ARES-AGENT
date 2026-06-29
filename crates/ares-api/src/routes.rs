use crate::auth::require_api_key;
use crate::ssrf::validate_webhook_url;
use crate::state::{AppState, WebhookConfig};
use ares_core::{CVEEntry, Finding};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
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
    let api_key = state.api_key.clone();
    let shared_state = std::sync::Arc::new(state);

    // Public routes (no auth required)
    let public_routes = Router::new().route("/health", get(health));

    // Protected routes (require API key if configured)
    let protected_routes = Router::new()
        .route("/findings", get(list_findings))
        .route("/findings/:id", get(get_finding))
        .route("/programs/:id/risk", get(get_risk))
        .route("/families", get(list_families))
        .route("/webhooks/register", post(register_webhook))
        .route("/cve/search", get(search_cves))
        .route("/eval/metrics", get(eval_metrics))
        .with_state(shared_state)
        .layer(middleware::from_fn(move |req, next| {
            require_api_key(api_key.clone(), req, next)
        }));

    Router::new().merge(public_routes).merge(protected_routes)
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

async fn list_families(State(_state): State<std::sync::Arc<AppState>>) -> Json<serde_json::Value> {
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
    validate_webhook_url(&req.url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let config = WebhookConfig {
        id: Uuid::new_v4().to_string(),
        url: req.url,
        min_severity: req.min_severity.unwrap_or_else(|| "high".to_string()),
        event_types: req
            .event_types
            .unwrap_or_else(|| vec!["finding".to_string()]),
    };

    let mut webhooks = state.webhooks.write().await;
    webhooks.push(config.clone());

    Ok(Json(config))
}

async fn eval_metrics(State(_state): State<std::sync::Arc<AppState>>) -> Json<serde_json::Value> {
    // TODO: Proxy to Python ares_eval service
    Json(serde_json::json!({
        "message": "Eval lab service not yet connected. Start python/ares_eval service.",
        "metrics": {}
    }))
}

#[derive(Debug, Deserialize)]
pub struct CVESearchQuery {
    pub keyword: String,
}

#[derive(Debug, Serialize)]
pub struct CVESearchResponse {
    pub keyword: String,
    pub count: usize,
    pub results: Vec<CVEEntry>,
}

async fn search_cves(Query(query): Query<CVESearchQuery>) -> Json<CVESearchResponse> {
    // Known Solana ecosystem CVEs for offline response
    let known: Vec<CVEEntry> = match query.keyword.to_lowercase().as_str() {
        kw if kw.contains("anchor")
            || kw.contains("authority")
            || kw.contains("cve-2026-45137") =>
        {
            vec![CVEEntry::new(
                "CVE-2026-45137",
                "Anchor framework authority bypass in account validation",
            )
            .with_cvss(9.8, "CRITICAL")
            .with_references(vec![
                "https://github.com/coral-xyz/anchor/security/advisories".to_string(),
                "https://www.sentinelone.com/vulnerability-database/cve-2026-45137/".to_string(),
            ])]
        }
        kw if kw.contains("solana") || kw.contains("web3") => {
            vec![CVEEntry::new(
                "CVE-2022-23734",
                "Solana web3.js private key leakage via error messages",
            )
            .with_cvss(7.5, "HIGH")]
        }
        _ => Vec::new(),
    };

    Json(CVESearchResponse {
        keyword: query.keyword,
        count: known.len(),
        results: known,
    })
}
