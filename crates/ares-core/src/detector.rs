use crate::{Finding, ProgramInfo};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub program: ProgramInfo,
    pub transaction_traces: Vec<TransactionTrace>,
}

#[derive(Debug, Clone)]
pub struct TransactionTrace {
    pub signature: String,
    pub instructions: Vec<InstructionTrace>,
}

#[derive(Debug, Clone)]
pub struct InstructionTrace {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub data: Vec<u8>,
    pub inner_instructions: Vec<InstructionTrace>,
    pub is_cpi: bool,
}

#[derive(Debug, Clone)]
pub struct DetectorMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_classes: Vec<String>,
}

#[async_trait]
pub trait Detector: Send + Sync {
    fn metadata(&self) -> DetectorMetadata;

    async fn detect(&self, ctx: &DetectionContext) -> Vec<Finding>;
}
