use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub program_id: String,
    pub c1_score: f64,
    pub c2_score: f64,
    pub c3_score: f64,
    pub clone_family_factor: f64,
    pub economic_exposure: f64,
    pub total: f64,
    pub computed_at: chrono::DateTime<chrono::Utc>,
}

impl RiskScore {
    /// Default weights derived from Solana ecosystem review data:
    /// - C1 (business logic) = 38.5% of high/critical findings
    /// - C2 (validation/access control) = 25.0%
    /// - C3 (low-level technical) = 19.0%
    pub const DEFAULT_W1: f64 = 0.385;
    pub const DEFAULT_W2: f64 = 0.250;
    pub const DEFAULT_W3: f64 = 0.190;
    pub const DEFAULT_W4: f64 = 0.100;
    pub const DEFAULT_W5: f64 = 0.075;

    pub fn new(
        program_id: &str,
        c1_score: f64,
        c2_score: f64,
        c3_score: f64,
        clone_family_factor: f64,
        economic_exposure: f64,
    ) -> Self {
        let total = Self::compute_total(
            c1_score,
            c2_score,
            c3_score,
            clone_family_factor,
            economic_exposure,
            Self::DEFAULT_W1,
            Self::DEFAULT_W2,
            Self::DEFAULT_W3,
            Self::DEFAULT_W4,
            Self::DEFAULT_W5,
        );

        Self {
            program_id: program_id.to_string(),
            c1_score,
            c2_score,
            c3_score,
            clone_family_factor,
            economic_exposure,
            total,
            computed_at: chrono::Utc::now(),
        }
    }

    pub fn compute_total(
        c1: f64,
        c2: f64,
        c3: f64,
        clone: f64,
        economic: f64,
        w1: f64,
        w2: f64,
        w3: f64,
        w4: f64,
        w5: f64,
    ) -> f64 {
        w1 * c1 + w2 * c2 + w3 * c3 + w4 * clone + w5 * economic
    }

    pub fn severity_label(&self) -> &'static str {
        if self.total >= 0.8 {
            "critical"
        } else if self.total >= 0.6 {
            "high"
        } else if self.total >= 0.4 {
            "medium"
        } else if self.total >= 0.2 {
            "low"
        } else {
            "info"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_computation() {
        let score = RiskScore::new("test", 0.9, 0.5, 0.1, 0.3, 0.7);
        let expected = 0.385 * 0.9 + 0.25 * 0.5 + 0.19 * 0.1 + 0.1 * 0.3 + 0.075 * 0.7;
        assert!((score.total - expected).abs() < 0.001);
    }

    #[test]
    fn test_severity_labels() {
        let critical = RiskScore::new("test", 1.0, 1.0, 1.0, 1.0, 1.0);
        assert_eq!(critical.severity_label(), "critical");

        let low = RiskScore::new("test", 0.1, 0.1, 0.1, 0.1, 0.1);
        assert_eq!(low.severity_label(), "low");
    }
}
