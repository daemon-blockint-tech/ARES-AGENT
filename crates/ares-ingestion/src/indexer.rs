use crate::{IngestionConfig, RpcProvider};
use ares_core::{AresError, AresResult, ProgramInfo};
use sled::Db;
use std::path::Path;

pub struct Indexer {
    db: Db,
}

impl Indexer {
    pub fn open(path: impl AsRef<Path>) -> AresResult<Self> {
        let db = sled::open(path).map_err(|e| AresError::Database(e.to_string()))?;
        Ok(Self { db })
    }

    pub fn store_program(&self, program: &ProgramInfo) -> AresResult<()> {
        let key = format!("program:{}", program.program_id);
        let value = serde_json::to_vec(program).map_err(AresError::Serde)?;
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|e| AresError::Database(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| AresError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn get_program(&self, program_id: &str) -> AresResult<Option<ProgramInfo>> {
        let key = format!("program:{}", program_id);
        match self.db.get(key.as_bytes()) {
            Ok(Some(value)) => {
                let program: ProgramInfo =
                    serde_json::from_slice(&value).map_err(AresError::Serde)?;
                Ok(Some(program))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AresError::Database(e.to_string())),
        }
    }

    pub fn list_programs(&self) -> AresResult<Vec<ProgramInfo>> {
        let mut programs = Vec::new();
        for item in self.db.scan_prefix(b"program:") {
            match item {
                Ok((_, value)) => {
                    if let Ok(program) = serde_json::from_slice::<ProgramInfo>(&value) {
                        programs.push(program);
                    }
                }
                Err(e) => return Err(AresError::Database(e.to_string())),
            }
        }
        Ok(programs)
    }

    pub async fn ingest_program(
        &self,
        provider: &dyn RpcProvider,
        program_id: &str,
    ) -> AresResult<ProgramInfo> {
        tracing::info!("Ingesting program: {}", program_id);
        let program = provider.download_program(program_id).await?;
        self.store_program(&program)?;
        tracing::info!(
            "Stored program {} ({} bytes bytecode)",
            program_id,
            program.bytecode.len()
        );
        Ok(program)
    }
}
