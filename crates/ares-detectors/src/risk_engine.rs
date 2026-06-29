use ares_core::{Finding, RiskScore, RiskWeights, Severity, VulnerabilityClass};
use std::collections::HashMap;

/// Risk scoring engine implementing the Daemon Protocol risk formula:
/// Risk(S) = w1·f_C1(S) + w2·f_C2(S) + w3·f_C3(S) + w4·g_clone(S) + w5·h_economic(S)
///
/// Weights derived from Solana ecosystem review data:
/// - C1 (business logic): 38.5% of high/critical findings
/// - C2 (validation/access control): 25.0%
/// - C3 (low-level technical): 19.0%
/// - Clone family factor: 10.0%
/// - Economic exposure: 7.5%
pub struct RiskEngine {
    w1: f64,
    w2: f64,
    w3: f64,
    w4: f64,
    w5: f64,
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl RiskEngine {
    pub fn with_defaults() -> Self {
        Self {
            w1: RiskScore::DEFAULT_W1,
            w2: RiskScore::DEFAULT_W2,
            w3: RiskScore::DEFAULT_W3,
            w4: RiskScore::DEFAULT_W4,
            w5: RiskScore::DEFAULT_W5,
        }
    }

    pub fn with_weights(w1: f64, w2: f64, w3: f64, w4: f64, w5: f64) -> Self {
        Self { w1, w2, w3, w4, w5 }
    }

    /// Compute risk score from findings + optional metadata
    pub fn compute(
        &self,
        program_id: &str,
        findings: &[Finding],
        clone_family_factor: Option<f64>,
        economic_exposure: Option<f64>,
    ) -> RiskScore {
        let (c1, c2, c3) = self.classify_and_score(findings);
        let clone = clone_family_factor.unwrap_or(0.0);
        let economic = economic_exposure.unwrap_or(0.0);

        let total = RiskScore::compute_total(
            c1,
            c2,
            c3,
            clone,
            economic,
            &RiskWeights {
                w1: self.w1,
                w2: self.w2,
                w3: self.w3,
                w4: self.w4,
                w5: self.w5,
            },
        );

        RiskScore {
            program_id: program_id.to_string(),
            c1_score: c1,
            c2_score: c2,
            c3_score: c3,
            clone_family_factor: clone,
            economic_exposure: economic,
            total,
            computed_at: chrono::Utc::now(),
        }
    }

    /// Classify findings by vulnerability class and compute severity-weighted scores
    fn classify_and_score(&self, findings: &[Finding]) -> (f64, f64, f64) {
        let mut c1_score = 0.0;
        let mut c2_score = 0.0;
        let mut c3_score = 0.0;

        for f in findings {
            let severity_weight = match f.severity {
                Severity::Critical => 1.0,
                Severity::High => 0.75,
                Severity::Medium => 0.5,
                Severity::Low => 0.25,
                Severity::Info => 0.1,
            };

            match f.class {
                VulnerabilityClass::C1 => c1_score += severity_weight,
                VulnerabilityClass::C2 => c2_score += severity_weight,
                VulnerabilityClass::C3 => c3_score += severity_weight,
            }
        }

        // Normalize to 0.0-1.0 range (cap at 5 findings per class)
        let normalize = |score: f64| (score / 5.0).min(1.0);

        (
            normalize(c1_score),
            normalize(c2_score),
            normalize(c3_score),
        )
    }

    /// Batch compute risk scores for multiple programs
    pub fn compute_batch(
        &self,
        programs: &[(String, Vec<Finding>)],
        clone_factors: &HashMap<String, f64>,
        economic_exposures: &HashMap<String, f64>,
    ) -> Vec<RiskScore> {
        programs
            .iter()
            .map(|(pid, findings)| {
                self.compute(
                    pid,
                    findings,
                    clone_factors.get(pid).copied(),
                    economic_exposures.get(pid).copied(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::Finding;

    #[test]
    fn test_empty_findings() {
        let engine = RiskEngine::default();
        let score = engine.compute("test", &[], None, None);
        assert_eq!(score.total, 0.0);
    }

    #[test]
    fn test_c2_findings_weighted() {
        let engine = RiskEngine::default();
        let findings = vec![
            Finding::new(
                "test",
                "d",
                "t1",
                "d",
                Severity::Critical,
                VulnerabilityClass::C2,
            ),
            Finding::new(
                "test",
                "d",
                "t2",
                "d",
                Severity::High,
                VulnerabilityClass::C2,
            ),
        ];
        let score = engine.compute("test", &findings, None, None);
        // c2 = (1.0 + 0.75) / 5.0 = 0.35
        assert!((score.c2_score - 0.35).abs() < 0.001);
        assert!(score.total > 0.0);
    }
}
