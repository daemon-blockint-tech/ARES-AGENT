use ares_core::{CVEEntry, FindingEnrichment};
use serde::Deserialize;
use std::process::Stdio;
use tokio::process::Command;

/// Bridge to the Python ares_cve package for CVE enrichment.
///
/// Calls `python -m ares_cve.cli` as a subprocess to perform offline CVE lookups.
/// Falls back gracefully if Python or the package is not installed.
pub struct CveBridge {
    python_cmd: String,
}

#[derive(Debug, Deserialize)]
struct CveSearchResult {
    cve_id: String,
    description: String,
    cvss_v3_score: Option<f64>,
    cvss_v3_severity: Option<String>,
    references: Vec<String>,
    cpe_matches: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EnrichResponse {
    enriched_findings: Vec<EnrichedFinding>,
    summary: EnrichSummary,
}

#[derive(Debug, Deserialize)]
struct EnrichedFinding {
    finding_id: String,
    finding_title: String,
    cve_refs: Vec<CveSearchResult>,
}

#[derive(Debug, Deserialize)]
struct EnrichSummary {
    total_findings: usize,
    findings_with_cve: usize,
    total_cve_refs: usize,
}

impl CveBridge {
    pub fn new() -> Self {
        Self {
            python_cmd: std::env::var("ARES_PYTHON").unwrap_or_else(|_| "python3".to_string()),
        }
    }

    pub fn with_python(python_cmd: &str) -> Self {
        Self {
            python_cmd: python_cmd.to_string(),
        }
    }

    /// Search CVEs by keyword via the Python ares_cve CLI.
    pub async fn search(&self, keyword: &str) -> Vec<CVEEntry> {
        let output = Command::new(&self.python_cmd)
            .args(["-m", "ares_cve.cli", "search", keyword, "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                match serde_json::from_slice::<Vec<CveSearchResult>>(&out.stdout) {
                    Ok(results) => results.into_iter().map(|r| r.into()).collect(),
                    Err(e) => {
                        tracing::warn!("Failed to parse CVE search results: {}", e);
                        Vec::new()
                    }
                }
            }
            Ok(out) => {
                tracing::debug!(
                    "ares_cve search failed (exit {}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                );
                Vec::new()
            }
            Err(e) => {
                tracing::debug!("Python ares_cve not available: {}", e);
                Vec::new()
            }
        }
    }

    /// Enrich findings with CVE references via the Python ares_cve CLI.
    /// Takes a JSON array of findings and returns enrichment results.
    pub async fn enrich_findings(&self, findings_json: &str) -> Vec<FindingEnrichment> {
        let mut child = match Command::new(&self.python_cmd)
            .args(["-m", "ares_cve.cli", "enrich", "-", "--json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("Python ares_cve not available: {}", e);
                return Vec::new();
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(findings_json.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }

        let output = match child.wait_with_output().await {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!("ares_cve enrich process error: {}", e);
                return Vec::new();
            }
        };

        if !output.status.success() {
            tracing::debug!(
                "ares_cve enrich failed (exit {}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return Vec::new();
        }

        match serde_json::from_slice::<EnrichResponse>(&output.stdout) {
            Ok(resp) => {
                tracing::info!(
                    "CVE enrichment: {} of {} findings have CVE refs ({} total)",
                    resp.summary.findings_with_cve,
                    resp.summary.total_findings,
                    resp.summary.total_cve_refs
                );
                resp.enriched_findings
                    .into_iter()
                    .map(|f| FindingEnrichment {
                        finding_id: f.finding_id,
                        finding_title: f.finding_title,
                        cve_refs: f.cve_refs.into_iter().map(|r| r.into()).collect(),
                    })
                    .collect()
            }
            Err(e) => {
                tracing::warn!("Failed to parse CVE enrichment response: {}", e);
                Vec::new()
            }
        }
    }

    /// Check if the Python ares_cve package is available.
    pub async fn is_available(&self) -> bool {
        Command::new(&self.python_cmd)
            .args(["-c", "import ares_cve"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl Default for CveBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl From<CveSearchResult> for CVEEntry {
    fn from(r: CveSearchResult) -> Self {
        CVEEntry {
            cve_id: r.cve_id,
            description: r.description,
            cvss_v3_score: r.cvss_v3_score,
            cvss_v3_severity: r.cvss_v3_severity,
            references: r.references,
            cpe_matches: r.cpe_matches,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bridge_unavailable_graceful() {
        let bridge = CveBridge::with_python("nonexistent_python_bin");
        let results = bridge.search("solana").await;
        assert!(results.is_empty());
    }
}
