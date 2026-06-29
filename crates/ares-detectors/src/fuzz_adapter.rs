use ares_core::{Detector, DetectionContext, DetectorMetadata, Finding};
use async_trait::async_trait;

/// Fuzz adapter detector — stub interface for FuzzDelSol integration.
/// FuzzDelSol is a binary-only coverage-guided fuzzer for Solana SBF bytecode
/// with bug oracles: Missing Signer, Missing Owner, Lamports, Arbitrary CPI,
/// Missing Key, Integer Bugs.
pub struct FuzzAdapterDetector {
    fuzzdelsol_path: Option<String>,
}

impl FuzzAdapterDetector {
    pub fn new() -> Self {
        Self {
            fuzzdelsol_path: None,
        }
    }

    pub fn with_path(path: &str) -> Self {
        Self {
            fuzzdelsol_path: Some(path.to_string()),
        }
    }
}

impl Default for FuzzAdapterDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for FuzzAdapterDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "fuzz_adapter".to_string(),
            name: "FuzzDelSol Adapter".to_string(),
            version: "0.1.0".to_string(),
            description: "Binary-only coverage-guided fuzzer adapter for Solana SBF bytecode. \
                          Bug oracles: missing signer/owner/key, arbitrary CPI, integer bugs. \
                          Currently a stub — requires FuzzDelSol installation.".to_string(),
            supported_classes: vec!["C2".to_string(), "C3".to_string()],
        }
    }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<Finding> {
        if self.fuzzdelsol_path.is_none() {
            tracing::warn!(
                "FuzzDelSol adapter not configured — skipping. Set path with FuzzAdapterDetector::with_path()"
            );
            return Vec::new();
        }

        tracing::info!(
            "FuzzDelSol adapter stub: would fuzz program {} ({} bytes)",
            ctx.program.program_id,
            ctx.program.bytecode.len()
        );

        // TODO: Implement actual FuzzDelSol integration:
        // 1. Write bytecode to temp file
        // 2. Run FuzzDelSol with bug oracles
        // 3. Parse output for findings
        // 4. Convert to Finding structs

        Vec::new()
    }
}
