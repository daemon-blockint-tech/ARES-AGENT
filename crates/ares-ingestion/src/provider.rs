use ares_core::{AresError, AresResult, ProgramInfo};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub owner: String,
    pub lamports: u64,
    pub data: Option<String>,
    pub executable: bool,
    pub rent_epoch: u64,
}

#[async_trait]
pub trait RpcProvider: Send + Sync {
    async fn get_account_info(&self, address: &str) -> AresResult<Option<AccountInfo>>;
    async fn get_program_accounts(&self, program_id: &str) -> AresResult<Vec<(String, AccountInfo)>>;
    async fn get_signatures_for_address(&self, address: &str, limit: usize) -> AresResult<Vec<TransactionSignature>>;
    async fn download_program(&self, program_id: &str) -> AresResult<ProgramInfo>;
    async fn subscribe_program(&self, program_id: &str) -> AresResult<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSignature {
    pub signature: String,
    pub slot: u64,
    pub err: Option<String>,
    pub block_time: Option<i64>,
}

pub struct HeliusProvider {
    #[allow(dead_code)]
    api_key: String,
    #[allow(dead_code)]
    ws_url: String,
    base_rpc_url: String,
    client: reqwest::Client,
}

impl HeliusProvider {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_rpc_url: "https://mainnet.helius-rpc.com".to_string(),
            ws_url: "wss://mainnet.helius-rpc.com".to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub fn with_custom_urls(api_key: &str, rpc_url: &str, ws_url: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_rpc_url: rpc_url.to_string(),
            ws_url: ws_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Returns the full RPC URL with API key appended
    fn effective_rpc_url(&self) -> String {
        format!("{}?api-key={}", self.base_rpc_url, self.api_key)
    }

    /// Returns a redacted URL safe for logging (API key replaced with ***)
    pub fn display_url(&self) -> String {
        self.base_rpc_url.replace(&self.api_key, "***")
    }

    async fn rpc_request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> AresResult<T> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .client
            .post(self.effective_rpc_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| AresError::Rpc(e.to_string()))?;

        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AresError::Rpc(e.to_string()))?;

        if let Some(error) = result.get("error") {
            return Err(AresError::Rpc(error.to_string()));
        }

        let result_value = result
            .get("result")
            .ok_or_else(|| AresError::Rpc("missing result field".to_string()))?
            .clone();

        serde_json::from_value(result_value)
            .map_err(|e| AresError::Rpc(e.to_string()))
    }
}

#[async_trait]
impl RpcProvider for HeliusProvider {
    async fn get_account_info(&self, address: &str) -> AresResult<Option<AccountInfo>> {
        let params = serde_json::json!([address, { "encoding": "base64" }]);
        let result: serde_json::Value = self.rpc_request("getAccountInfo", params).await?;

        let arr = match result.as_array() {
            Some(a) if !a.is_empty() => a,
            _ => return Ok(None),
        };
        if arr[0].is_null() {
            return Ok(None);
        }

        let value = &arr[0];
        let data = value
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|d| d.first())
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        Ok(Some(AccountInfo {
            owner: value
                .get("owner")
                .and_then(|o| o.as_str())
                .unwrap_or("")
                .to_string(),
            lamports: value
                .get("lamports")
                .and_then(|l| l.as_u64())
                .unwrap_or(0),
            data,
            executable: value
                .get("executable")
                .and_then(|e| e.as_bool())
                .unwrap_or(false),
            rent_epoch: value
                .get("rentEpoch")
                .and_then(|r| r.as_u64())
                .unwrap_or(0),
        }))
    }

    async fn get_program_accounts(
        &self,
        program_id: &str,
    ) -> AresResult<Vec<(String, AccountInfo)>> {
        let params = serde_json::json!([program_id, { "encoding": "base64" }]);
        let result: Vec<serde_json::Value> = self
            .rpc_request("getProgramAccounts", params)
            .await?;

        let accounts = result
            .into_iter()
            .filter_map(|item| {
                let pubkey = item.get("pubkey").and_then(|p| p.as_str())?.to_string();
                let account = item.get("account")?;
                let data = account
                    .get("data")
                    .and_then(|d| d.as_array())
                    .and_then(|d| d.first())
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string());

                Some((
                    pubkey,
                    AccountInfo {
                        owner: account
                            .get("owner")
                            .and_then(|o| o.as_str())
                            .unwrap_or("")
                            .to_string(),
                        lamports: account
                            .get("lamports")
                            .and_then(|l| l.as_u64())
                            .unwrap_or(0),
                        data,
                        executable: account
                            .get("executable")
                            .and_then(|e| e.as_bool())
                            .unwrap_or(false),
                        rent_epoch: account
                            .get("rentEpoch")
                            .and_then(|r| r.as_u64())
                            .unwrap_or(0),
                    },
                ))
            })
            .collect();

        Ok(accounts)
    }

    async fn get_signatures_for_address(
        &self,
        address: &str,
        limit: usize,
    ) -> AresResult<Vec<TransactionSignature>> {
        let params = serde_json::json!([address, { "limit": limit }]);
        let result: Vec<serde_json::Value> = self
            .rpc_request("getSignaturesForAddress", params)
            .await?;

        let sigs = result
            .into_iter()
            .map(|item| TransactionSignature {
                signature: item
                    .get("signature")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                slot: item
                    .get("slot")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0),
                err: item
                    .get("err")
                    .and_then(|e| if e.is_null() { None } else { Some(e.to_string()) }),
                block_time: item
                    .get("blockTime")
                    .and_then(|b| b.as_i64()),
            })
            .collect();

        Ok(sigs)
    }

    async fn download_program(&self, program_id: &str) -> AresResult<ProgramInfo> {
        let account = self.get_account_info(program_id).await?;

        match account {
            Some(acc) if acc.executable => {
                let bytecode = acc
                    .data
                    .as_ref()
                    .map(|d| {
                        base64::engine::general_purpose::STANDARD
                            .decode(d.as_bytes())
                            .map_err(|e| AresError::Ingestion(format!("Base64 decode failed: {}", e)))
                    })
                    .transpose()?
                    .unwrap_or_default();

                Ok(ProgramInfo::new(program_id, bytecode))
            }
            Some(_) => Err(AresError::InvalidProgramId(format!(
                "{} is not an executable program",
                program_id
            ))),
            None => Err(AresError::ProgramNotFound(program_id.to_string())),
        }
    }

    async fn subscribe_program(&self, _program_id: &str) -> AresResult<()> {
        tracing::info!("WebSocket subscription stub - not yet implemented");
        Ok(())
    }
}

pub struct StandardRpcProvider {
    rpc_url: String,
    client: reqwest::Client,
}

impl StandardRpcProvider {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }
}

#[async_trait]
impl RpcProvider for StandardRpcProvider {
    async fn get_account_info(&self, address: &str) -> AresResult<Option<AccountInfo>> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [address, { "encoding": "base64" }],
        });

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AresError::Rpc(e.to_string()))?;

        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AresError::Rpc(e.to_string()))?;

        let value = match result
            .get("result")
            .and_then(|r| r.get("value"))
        {
            Some(v) if !v.is_null() => v,
            _ => return Ok(None),
        };

        let data = value
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|d| d.first())
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        Ok(Some(AccountInfo {
            owner: value.get("owner").and_then(|o| o.as_str()).unwrap_or("").to_string(),
            lamports: value.get("lamports").and_then(|l| l.as_u64()).unwrap_or(0),
            data,
            executable: value.get("executable").and_then(|e| e.as_bool()).unwrap_or(false),
            rent_epoch: value.get("rentEpoch").and_then(|r| r.as_u64()).unwrap_or(0),
        }))
    }

    async fn get_program_accounts(&self, _program_id: &str) -> AresResult<Vec<(String, AccountInfo)>> {
        Err(AresError::Rpc("StandardRpcProvider: getProgramAccounts not yet implemented".to_string()))
    }

    async fn get_signatures_for_address(&self, _address: &str, _limit: usize) -> AresResult<Vec<TransactionSignature>> {
        Err(AresError::Rpc("StandardRpcProvider: getSignaturesForAddress not yet implemented".to_string()))
    }

    async fn download_program(&self, program_id: &str) -> AresResult<ProgramInfo> {
        let account = self.get_account_info(program_id).await?;
        match account {
            Some(acc) if acc.executable => {
                let bytecode = acc.data
                    .as_ref()
                    .map(|d| {
                        base64::engine::general_purpose::STANDARD
                            .decode(d.as_bytes())
                            .map_err(|e| AresError::Ingestion(format!("Base64 decode failed: {}", e)))
                    })
                    .transpose()?
                    .unwrap_or_default();
                Ok(ProgramInfo::new(program_id, bytecode))
            }
            Some(_) => Err(AresError::InvalidProgramId(format!("{} is not executable", program_id))),
            None => Err(AresError::ProgramNotFound(program_id.to_string())),
        }
    }

    async fn subscribe_program(&self, _program_id: &str) -> AresResult<()> {
        Ok(())
    }
}
