use serde::{Deserialize, Serialize};

/// A CVE entry for enrichment of findings and evidence bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVEEntry {
    pub cve_id: String,
    pub description: String,
    pub cvss_v3_score: Option<f64>,
    pub cvss_v3_severity: Option<String>,
    pub references: Vec<String>,
    pub cpe_matches: Vec<String>,
}

impl CVEEntry {
    pub fn new(cve_id: &str, description: &str) -> Self {
        Self {
            cve_id: cve_id.to_string(),
            description: description.to_string(),
            cvss_v3_score: None,
            cvss_v3_severity: None,
            references: Vec::new(),
            cpe_matches: Vec::new(),
        }
    }

    pub fn with_cvss(mut self, score: f64, severity: &str) -> Self {
        self.cvss_v3_score = Some(score);
        self.cvss_v3_severity = Some(severity.to_string());
        self
    }

    pub fn with_references(mut self, refs: Vec<String>) -> Self {
        self.references = refs;
        self
    }

    pub fn is_critical(&self) -> bool {
        self.cvss_v3_score.is_some_and(|s| s >= 9.0)
    }

    pub fn is_high(&self) -> bool {
        self.cvss_v3_score.is_some_and(|s| (7.0..9.0).contains(&s))
    }
}

/// A dependency with associated CVEs from CVEdb lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCVE {
    pub dependency_name: String,
    pub version: String,
    pub cves: Vec<CVEEntry>,
}

impl DependencyCVE {
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            dependency_name: name.to_string(),
            version: version.to_string(),
            cves: Vec::new(),
        }
    }

    pub fn has_critical(&self) -> bool {
        self.cves.iter().any(|c| c.is_critical())
    }

    pub fn has_high(&self) -> bool {
        self.cves.iter().any(|c| c.is_high())
    }

    pub fn max_cvss(&self) -> f64 {
        self.cves
            .iter()
            .filter_map(|c| c.cvss_v3_score)
            .fold(0.0_f64, f64::max)
    }
}

/// CVE enrichment result for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEnrichment {
    pub finding_id: String,
    pub finding_title: String,
    pub cve_refs: Vec<CVEEntry>,
}

impl FindingEnrichment {
    pub fn new(finding_id: &str, finding_title: &str) -> Self {
        Self {
            finding_id: finding_id.to_string(),
            finding_title: finding_title.to_string(),
            cve_refs: Vec::new(),
        }
    }

    pub fn has_cve(&self) -> bool {
        !self.cve_refs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_entry_severity() {
        let critical = CVEEntry::new("CVE-2026-45137", "Test").with_cvss(9.8, "CRITICAL");
        assert!(critical.is_critical());
        assert!(!critical.is_high());

        let high = CVEEntry::new("CVE-2022-23734", "Test").with_cvss(7.5, "HIGH");
        assert!(!high.is_critical());
        assert!(high.is_high());

        let none = CVEEntry::new("CVE-XXXX", "Test");
        assert!(!none.is_critical());
        assert!(!none.is_high());
    }

    #[test]
    fn test_dependency_cve() {
        let dep = DependencyCVE::new("anchor-lang", "0.28.0");
        assert!(!dep.has_critical());
        assert_eq!(dep.max_cvss(), 0.0);
    }
}
