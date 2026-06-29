use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub program_id: String,
    pub bytecode: Vec<u8>,
    pub source_available: bool,
    pub tvl_usd: Option<f64>,
    pub family_id: Option<String>,
    pub deployer: Option<String>,
    pub first_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    pub account_count: Option<u64>,
}

impl ProgramInfo {
    pub fn new(program_id: &str, bytecode: Vec<u8>) -> Self {
        Self {
            program_id: program_id.to_string(),
            bytecode,
            source_available: false,
            tvl_usd: None,
            family_id: None,
            deployer: None,
            first_seen: None,
            last_updated: None,
            account_count: None,
        }
    }

    pub fn with_source(mut self, available: bool) -> Self {
        self.source_available = available;
        self
    }

    pub fn with_tvl(mut self, tvl: f64) -> Self {
        self.tvl_usd = Some(tvl);
        self
    }

    pub fn with_family(mut self, family_id: &str) -> Self {
        self.family_id = Some(family_id.to_string());
        self
    }
}
