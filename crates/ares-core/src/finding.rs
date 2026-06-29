use crate::{Severity, VulnerabilityClass};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub program_id: String,
    pub detector_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub class: VulnerabilityClass,
    pub evidence_refs: Vec<String>,
    pub cve_refs: Vec<String>,
    pub exploit_scenario: Option<String>,
    pub recommendation: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub status: FindingStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Confirmed,
    Mitigated,
    FalsePositive,
    Anchored,
}

impl Finding {
    pub fn new(
        program_id: &str,
        detector_id: &str,
        title: &str,
        description: &str,
        severity: Severity,
        class: VulnerabilityClass,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            program_id: program_id.to_string(),
            detector_id: detector_id.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            severity,
            class,
            evidence_refs: Vec::new(),
            cve_refs: Vec::new(),
            exploit_scenario: None,
            recommendation: None,
            detected_at: Utc::now(),
            status: FindingStatus::Open,
        }
    }

    pub fn with_evidence(mut self, refs: Vec<String>) -> Self {
        self.evidence_refs = refs;
        self
    }

    pub fn with_exploit(mut self, scenario: &str) -> Self {
        self.exploit_scenario = Some(scenario.to_string());
        self
    }

    pub fn with_recommendation(mut self, rec: &str) -> Self {
        self.recommendation = Some(rec.to_string());
        self
    }

    pub fn merkle_leaf(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.program_id.as_bytes());
        hasher.update(self.title.as_bytes());
        hasher.update(self.severity.label().as_bytes());
        hasher.update(self.class.code().as_bytes());
        hasher.update(self.detected_at.timestamp().to_le_bytes());
        hasher.finalize().to_vec()
    }
}
