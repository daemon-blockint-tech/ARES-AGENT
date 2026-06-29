use ares_core::{Evidence, EvidenceBundle, Finding};
use std::collections::HashMap;

/// Bundles findings into evidence bundles with Merkle tree roots
/// for on-chain anchoring.
pub struct EvidenceBundler {
    pending: HashMap<String, Evidence>,
}

impl EvidenceBundler {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Add a finding's evidence to the pending bundle
    pub fn add(&mut self, finding: &Finding) {
        let evidence = Evidence::new(finding);
        self.pending.insert(finding.id.clone(), evidence);
    }

    /// Add multiple findings
    pub fn add_many(&mut self, findings: &[Finding]) {
        for f in findings {
            self.add(f);
        }
    }

    /// Finalize the pending evidence into a bundle with a Merkle root
    pub fn finalize(&mut self, batch_id: &str) -> Option<EvidenceBundle> {
        if self.pending.is_empty() {
            return None;
        }

        let evidence: Vec<Evidence> = self.pending.drain().map(|(_, v)| v).collect();
        let bundle = EvidenceBundle::new(batch_id, evidence).ok()?;

        tracing::info!(
            "Finalized evidence bundle {} with {} findings, merkle_root={}",
            bundle.batch_id,
            bundle.findings.len(),
            bundle.merkle_root
        );

        Some(bundle)
    }

    /// Pending evidence count
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for EvidenceBundler {
    fn default() -> Self {
        Self::new()
    }
}
