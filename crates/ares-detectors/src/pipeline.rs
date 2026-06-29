use ares_core::{Detector, DetectionContext, DetectorMetadata, Finding};
use async_trait::async_trait;
use std::sync::Arc;

pub struct DetectorPipeline {
    detectors: Vec<Arc<dyn Detector>>,
}

impl DetectorPipeline {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn add(&mut self, detector: Arc<dyn Detector>) -> &mut Self {
        self.detectors.push(detector);
        self
    }

    pub fn detectors(&self) -> &[Arc<dyn Detector>] {
        &self.detectors
    }

    pub async fn run(&self, ctx: &DetectionContext) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        for detector in &self.detectors {
            let meta = detector.metadata();
            tracing::info!("Running detector: {} v{}", meta.name, meta.version);

            let findings = detector.detect(ctx).await;
            tracing::info!(
                "Detector {} found {} findings",
                meta.name,
                findings.len()
            );

            all_findings.extend(findings);
        }

        self.deduplicate(all_findings)
    }

    fn deduplicate(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut seen: Vec<(String, String, String)> = Vec::new();
        let mut unique = Vec::new();

        for f in findings {
            let key = (f.program_id.clone(), f.title.clone(), f.class.code().to_string());
            if !seen.contains(&key) {
                seen.push(key);
                unique.push(f);
            }
        }

        unique
    }
}

impl Default for DetectorPipeline {
    fn default() -> Self {
        Self::new()
    }
}
