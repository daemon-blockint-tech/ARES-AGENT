use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionConfig {
    pub rpc_url: String,
    pub ws_url: String,
    pub api_key: Option<String>,
    pub provider_type: ProviderType,
    pub db_path: String,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Helius,
    Standard,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            ws_url: "wss://api.mainnet-beta.solana.com".to_string(),
            api_key: None,
            provider_type: ProviderType::Standard,
            db_path: "./ares-db".to_string(),
            poll_interval_secs: 30,
        }
    }
}

impl IngestionConfig {
    pub fn helius(api_key: &str) -> Self {
        Self {
            rpc_url: "https://mainnet.helius-rpc.com".to_string(),
            ws_url: "wss://mainnet.helius-rpc.com".to_string(),
            api_key: Some(api_key.to_string()),
            provider_type: ProviderType::Helius,
            db_path: "./ares-db".to_string(),
            poll_interval_secs: 30,
        }
    }

    /// Returns the full RPC URL with API key appended (for Helius provider)
    pub fn effective_rpc_url(&self) -> String {
        match (&self.api_key, self.provider_type) {
            (Some(key), ProviderType::Helius) => format!("{}?api-key={}", self.rpc_url, key),
            _ => self.rpc_url.clone(),
        }
    }

    /// Returns the full WS URL with API key appended (for Helius provider)
    pub fn effective_ws_url(&self) -> String {
        match (&self.api_key, self.provider_type) {
            (Some(key), ProviderType::Helius) => format!("{}?api-key={}", self.ws_url, key),
            _ => self.ws_url.clone(),
        }
    }
}
