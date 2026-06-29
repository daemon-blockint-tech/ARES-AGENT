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
            rpc_url: format!("https://mainnet.helius-rpc.com/?api-key={}", api_key),
            ws_url: format!("wss://mainnet.helius-rpc.com/?api-key={}", api_key),
            api_key: Some(api_key.to_string()),
            provider_type: ProviderType::Helius,
            db_path: "./ares-db".to_string(),
            poll_interval_secs: 30,
        }
    }
}
