use ares_core::{DetectionContext, Detector, DetectorMetadata, Finding};
use async_trait::async_trait;

/// Symbolic adapter detector — stub interface for SseRex integration.
/// SseRex is the first practical symbolic execution engine for Solana,
/// targeting: missing owner checks, missing signer checks, missing key checks,
/// arbitrary CPIs. Models CPI depth limit and privilege rules.
pub struct SymbolicAdapterDetector {
    sserex_path: Option<String>,
}

impl SymbolicAdapterDetector {
    pub fn new() -> Self {
        Self { sserex_path: None }
    }

    pub fn with_path(path: &str) -> Self {
        Self {
            sserex_path: Some(path.to_string()),
        }
    }
}

impl Default for SymbolicAdapterDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for SymbolicAdapterDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "symbolic_adapter".to_string(),
            name: "SseRex Symbolic Execution Adapter".to_string(),
            version: "0.1.0".to_string(),
            description: "Symbolic execution engine for Solana bytecode. \
                          Targets missing owner/signer/key checks, arbitrary CPIs. \
                          Models CPI depth limit and privilege rules. \
                          Currently a stub — requires SseRex installation."
                .to_string(),
            supported_classes: vec!["C2".to_string()],
        }
    }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<Finding> {
        if self.sserex_path.is_none() {
            tracing::warn!(
                "SseRex adapter not configured — skipping. Set path with SymbolicAdapterDetector::with_path()"
            );
            return Vec::new();
        }

        tracing::info!(
            "SseRex adapter stub: would symbolically execute program {} ({} bytes)",
            ctx.program.program_id,
            ctx.program.bytecode.len()
        );

        // TODO: Implement actual SseRex integration:
        // 1. Load bytecode into SseRex
        // 2. Configure symbolic execution parameters (CPI depth, account model)
        // 3. Run execution with bug oracles
        // 4. Parse counterexamples and convert to Finding structs

        Vec::new()
    }
}
