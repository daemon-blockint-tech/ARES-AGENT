use ares_core::{
    Detector, DetectionContext, DetectorMetadata, Finding, Severity, VulnerabilityClass,
};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};

/// CPI Graph Tracer: extracts and verifies CPI interaction graphs,
/// detects missing validation patterns in cross-program invocations.
pub struct CpiTracerDetector;

#[derive(Debug, Clone)]
struct CpiEdge {
    from_program: String,
    to_program: String,
    accounts_passed: Vec<String>,
    signers_passed: Vec<bool>,
    has_program_id_check: bool,
    has_owner_check: bool,
    depth: u32,
}

impl CpiTracerDetector {
    pub fn new() -> Self {
        Self
    }

    fn build_cpi_graph(traces: &[ares_core::TransactionTrace]) -> Vec<CpiEdge> {
        let mut edges = Vec::new();

        for trace in traces {
            for ix in &trace.instructions {
                Self::extract_cpi_edges(ix, &ix.program_id, 0, &mut edges);
            }
        }

        edges
    }

    fn extract_cpi_edges(
        ix: &ares_core::InstructionTrace,
        parent_program: &str,
        depth: u32,
        edges: &mut Vec<CpiEdge>,
    ) {
        if depth > 5 {
            return; // CPI depth limit
        }

        for inner in &ix.inner_instructions {
            if inner.is_cpi {
                let edge = CpiEdge {
                    from_program: parent_program.to_string(),
                    to_program: inner.program_id.clone(),
                    accounts_passed: inner.accounts.clone(),
                    signers_passed: vec![true; inner.accounts.len()],
                    has_program_id_check: false,
                    has_owner_check: false,
                    depth,
                };
                edges.push(edge);

                Self::extract_cpi_edges(inner, &inner.program_id, depth + 1, edges);
            }
        }
    }

    fn analyze_edges(edges: &[CpiEdge]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for edge in edges {
            // Check: CPI without program_id verification
            if !edge.has_program_id_check {
                findings.push(
                    Finding::new(
                        &edge.from_program,
                        "cpi_tracer",
                        &format!(
                            "CPI to {} without program_id verification (depth {})",
                            edge.to_program, edge.depth
                        ),
                        &format!(
                            "Program {} invokes {} via CPI but does not verify the target program_id. \
                             An attacker could substitute a malicious program at this CPI site.",
                            edge.from_program, edge.to_program
                        ),
                        if edge.depth == 0 {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        VulnerabilityClass::C2,
                    )
                    .with_exploit(&format!(
                        "Attacker deploys a fake program with the same interface. When {} invokes CPI, \
                         the fake program executes instead of {}, potentially draining accounts.",
                        edge.from_program, edge.to_program
                    )),
                );
            }

            // Check: CPI passing accounts without owner verification
            if !edge.has_owner_check && !edge.accounts_passed.is_empty() {
                findings.push(
                    Finding::new(
                        &edge.from_program,
                        "cpi_tracer",
                        &format!(
                            "CPI to {} passes accounts without owner verification",
                            edge.to_program
                        ),
                        &format!(
                            "Program {} passes {} accounts to {} via CPI without verifying account ownership. \
                             Forged accounts could be substituted.",
                            edge.from_program,
                            edge.accounts_passed.len(),
                            edge.to_program
                        ),
                        Severity::High,
                        VulnerabilityClass::C2,
                    )
                    .with_recommendation(
                        "Verify account.owner == expected_program_id for all accounts before CPI.",
                    ),
                );
            }
        }

        // Check for CPI depth approaching limit
        let max_depth = edges.iter().map(|e| e.depth).max().unwrap_or(0);
        if max_depth >= 4 {
            findings.push(
                Finding::new(
                    "unknown",
                    "cpi_tracer",
                    "CPI depth approaching runtime limit",
                    &format!(
                        "Maximum CPI depth observed: {} (runtime limit is 4-5). \
                         Deep CPI chains increase risk of privilege escalation and state inconsistency.",
                        max_depth
                    ),
                    Severity::Medium,
                    VulnerabilityClass::C3,
                ),
            );
        }

        // Compute CPI risk score
        let total_edges = edges.len();
        let unverified_edges = edges.iter().filter(|e| !e.has_program_id_check).count();
        if total_edges > 0 {
            let risk_ratio = unverified_edges as f64 / total_edges as f64;
            if risk_ratio > 0.5 {
                findings.push(
                    Finding::new(
                        "unknown",
                        "cpi_tracer",
                        "High CPI risk score: majority of CPI edges unverified",
                        &format!(
                            "{}/{} CPI edges lack program_id verification ({:.0}%). \
                             This program has elevated CPI risk.",
                            unverified_edges,
                            total_edges,
                            risk_ratio * 100.0
                        ),
                        Severity::High,
                        VulnerabilityClass::C2,
                    ),
                );
            }
        }

        findings
    }

    /// Compute a CPI risk score (0.0 to 1.0) for a program
    pub fn compute_cpi_risk(edges: &[CpiEdge]) -> f64 {
        if edges.is_empty() {
            return 0.0;
        }

        let total = edges.len() as f64;
        let unverified_pid = edges.iter().filter(|e| !e.has_program_id_check).count() as f64;
        let unverified_owner = edges.iter().filter(|e| !e.has_owner_check).count() as f64;
        let max_depth = edges.iter().map(|e| e.depth).max().unwrap_or(0) as f64;

        let pid_factor = unverified_pid / total;
        let owner_factor = unverified_owner / total;
        let depth_factor = (max_depth / 5.0).min(1.0);

        // Weighted: program_id verification is most critical
        0.5 * pid_factor + 0.3 * owner_factor + 0.2 * depth_factor
    }
}

impl Default for CpiTracerDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for CpiTracerDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "cpi_tracer".to_string(),
            name: "CPI Graph Tracer".to_string(),
            version: "0.1.0".to_string(),
            description: "Extracts and verifies CPI interaction graphs, detects missing validation \
                          in cross-program invocations, computes CPI risk scores".to_string(),
            supported_classes: vec!["C2".to_string(), "C3".to_string()],
        }
    }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<Finding> {
        if ctx.transaction_traces.is_empty() {
            return Vec::new();
        }

        let edges = Self::build_cpi_graph(&ctx.transaction_traces);
        let mut findings = Self::analyze_edges(&edges);

        // Set program_id for findings that don't have it
        let program_id = &ctx.program.program_id;
        for f in &mut findings {
            if f.program_id == "unknown" {
                f.program_id = program_id.clone();
            }
        }

        findings
    }
}
