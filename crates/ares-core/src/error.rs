use thiserror::Error;

#[derive(Debug, Error)]
pub enum AresError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Ingestion error: {0}")]
    Ingestion(String),

    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Evidence error: {0}")]
    Evidence(String),

    #[error("Anchoring error: {0}")]
    Anchoring(String),

    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("Invalid program ID: {0}")]
    InvalidProgramId(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

pub type AresResult<T> = Result<T, AresError>;
