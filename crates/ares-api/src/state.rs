use ares_core::{Finding, RiskScore};
use ares_detectors::RiskEngine;
use sled::Db;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AppState {
    pub findings: Arc<RwLock<Vec<Finding>>>,
    pub risk_scores: Arc<RwLock<HashMap<String, RiskScore>>>,
    pub risk_engine: RiskEngine,
    pub webhooks: Arc<RwLock<Vec<WebhookConfig>>>,
    pub db: Option<Arc<Db>>,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebhookConfig {
    pub id: String,
    pub url: String,
    pub min_severity: String,
    pub event_types: Vec<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            findings: Arc::new(RwLock::new(Vec::new())),
            risk_scores: Arc::new(RwLock::new(HashMap::new())),
            risk_engine: RiskEngine::default(),
            webhooks: Arc::new(RwLock::new(Vec::new())),
            db: None,
            api_key: None,
        }
    }

    pub fn with_api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }

    pub async fn add_findings(&self, new_findings: Vec<Finding>) {
        let mut findings = self.findings.write().await;
        findings.extend(new_findings);
    }

    pub async fn get_findings(
        &self,
        program_id: Option<&str>,
        severity: Option<&str>,
        class: Option<&str>,
    ) -> Vec<Finding> {
        let findings = self.findings.read().await;
        findings
            .iter()
            .filter(|f| {
                if let Some(pid) = program_id {
                    if f.program_id != pid {
                        return false;
                    }
                }
                if let Some(sev) = severity {
                    if f.severity.label() != sev {
                        return false;
                    }
                }
                if let Some(cls) = class {
                    if f.class.code() != cls {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    pub async fn get_finding_by_id(&self, id: &str) -> Option<Finding> {
        let findings = self.findings.read().await;
        findings.iter().find(|f| f.id == id).cloned()
    }

    pub async fn compute_and_store_risk(&self, program_id: &str, findings: &[Finding]) -> RiskScore {
        let score = self.risk_engine.compute(program_id, findings, None, None);
        let mut scores = self.risk_scores.write().await;
        scores.insert(program_id.to_string(), score.clone());
        score
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
