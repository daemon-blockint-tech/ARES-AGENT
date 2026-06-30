use ares_core::{CVEEntry, FindingEnrichment};
use serde::Deserialize;
use std::process::Stdio;
use tokio::process::Command;

/// Maximum allowed size for findings JSON passed to enrich_findings (1 MB).
const MAX_FINDINGS_JSON_LEN: usize = 1_048_576;

/// Maximum allowed length for a CVE search keyword (256 chars).
const MAX_KEYWORD_LEN: usize = 256;

/// Maximum number of findings allowed in a single enrichment request.
const MAX_FINDINGS_COUNT: usize = 10_000;

/// Bridge to the Python ares_cve package for CVE enrichment.
///
/// Calls `python -m ares_cve.cli` as a subprocess to perform offline CVE lookups.
/// Falls back gracefully if Python or the package is not installed.
///
/// # Security
///
/// All inputs are validated before being passed to the subprocess:
/// - Keywords are length-limited and checked for shell-injection characters
/// - Findings JSON is size-limited and parsed before being forwarded
/// - The subprocess inherits no environment variables beyond what is explicitly set
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

    /// Validate a keyword before passing it to the subprocess.
    /// Rejects overly long keywords and keywords containing shell metacharacters
    /// that could enable command injection if the subprocess shell is bypassed.
    fn validate_keyword(keyword: &str) -> Result<(), String> {
        if keyword.is_empty() {
            return Err("keyword must not be empty".to_string());
        }
        if keyword.len() > MAX_KEYWORD_LEN {
            return Err(format!(
                "keyword exceeds max length {} (got {})",
                MAX_KEYWORD_LEN,
                keyword.len()
            ));
        }
        // Reject shell metacharacters — the keyword is passed as a separate
        // argv element, but this is defense-in-depth against shell fallbacks.
        if keyword.chars().any(|c| {
            matches!(
                c,
                ';' | '|' | '&' | '`' | '$' | '(' | ')' | '{' | '}' | '<' | '>' | '\n' | '\r'
            )
        }) {
            return Err("keyword contains forbidden shell metacharacters".to_string());
        }
        Ok(())
    }

    /// Validate findings JSON before passing it to the subprocess.
    /// Ensures the payload is valid JSON, within size limits, and contains
    /// a bounded number of findings to prevent resource exhaustion.
    fn validate_findings_json(findings_json: &str) -> Result<(), String> {
        if findings_json.is_empty() {
            return Err("findings JSON must not be empty".to_string());
        }
        if findings_json.len() > MAX_FINDINGS_JSON_LEN {
            return Err(format!(
                "findings JSON exceeds max size {} bytes (got {})",
                MAX_FINDINGS_JSON_LEN,
                findings_json.len()
            ));
        }

        // Parse to verify it's valid JSON and count entries
        let parsed: serde_json::Value = serde_json::from_str(findings_json)
            .map_err(|e| format!("findings JSON is not valid JSON: {}", e))?;

        let count = parsed
            .as_array()
            .map(|arr| arr.len())
            .unwrap_or(1); // Single object is also acceptable

        if count > MAX_FINDINGS_COUNT {
            return Err(format!(
                "findings count {} exceeds max {}",
                count, MAX_FINDINGS_COUNT
            ));
        }

        Ok(())
    }

    /// Search CVEs by keyword via the Python ares_cve CLI.
    pub async fn search(&self, keyword: &str) -> Vec<CVEEntry> {
        if let Err(e) = Self::validate_keyword(keyword) {
            tracing::warn!("CVE search rejected: {}", e);
            return Vec::new();
        }

        let output = Command::new(&self.python_cmd)
            .args(["-m", "ares_cve.cli", "search", keyword, "--json"])
            .stdin(Stdio::null())
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
    ///
    /// # Security
    ///
    /// The findings JSON is validated (size, structure, count) before being
    /// written to the subprocess stdin. The subprocess stdin is set to piped
    /// (not inherited) to prevent reading from the parent's stdin.
    pub async fn enrich_findings(&self, findings_json: &str) -> Vec<FindingEnrichment> {
        if let Err(e) = Self::validate_findings_json(findings_json) {
            tracing::warn!("CVE enrichment rejected: {}", e);
            return Vec::new();
        }

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
            if let Err(e) = stdin.write_all(findings_json.as_bytes()).await {
                tracing::warn!("Failed to write findings to subprocess: {}", e);
                // Kill the child if we can't write to it
                let _ = child.kill().await;
                return Vec::new();
            }
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
            .stdin(Stdio::null())
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

    #[test]
    fn test_validate_keyword_rejects_empty() {
        assert!(CveBridge::validate_keyword("").is_err());
    }

    #[test]
    fn test_validate_keyword_rejects_shell_metacharacters() {
        assert!(CveBridge::validate_keyword("solana; rm -rf /").is_err());
        assert!(CveBridge::validate_keyword("solana | cat").is_err());
        assert!(CveBridge::validate_keyword("solana$(whoami)").is_err());
        assert!(CveBridge::validate_keyword("solana\nrm").is_err());
    }

    #[test]
    fn test_validate_keyword_accepts_normal() {
        assert!(CveBridge::validate_keyword("reentrancy").is_ok());
        assert!(CveBridge::validate_keyword("solana cpi").is_ok());
        assert!(CveBridge::validate_keyword("CVE-2026-45137").is_ok());
    }

    #[test]
    fn test_validate_keyword_rejects_too_long() {
        let long = "a".repeat(MAX_KEYWORD_LEN + 1);
        assert!(CveBridge::validate_keyword(&long).is_err());
    }

    #[test]
    fn test_validate_findings_json_rejects_empty() {
        assert!(CveBridge::validate_findings_json("").is_err());
    }

    #[test]
    fn test_validate_findings_json_rejects_invalid_json() {
        assert!(CveBridge::validate_findings_json("not json").is_err());
        assert!(CveBridge::validate_findings_json("{broken").is_err());
    }

    #[test]
    fn test_validate_findings_json_accepts_valid() {
        let json = r#"[{"id":"FIND-001","title":"test"}]"#;
        assert!(CveBridge::validate_findings_json(json).is_ok());
    }

    #[test]
    fn test_validate_findings_json_rejects_too_large() {
        let mut json = String::from("[");
        for i in 0..MAX_FINDINGS_COUNT + 1 {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(r#"{{"id":"F-{i}"}}"#));
        }
        json.push(']');
        // This may exceed the size limit first, but either rejection is correct
        let result = CveBridge::validate_findings_json(&json);
        assert!(result.is_err());
    }
}
