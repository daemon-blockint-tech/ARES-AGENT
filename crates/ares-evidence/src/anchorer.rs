use ares_core::{AresError, AresResult, EvidenceBundle};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;

/// Anchors evidence bundles on-chain by submitting Merkle roots
/// to the Evidence Registry program.
pub struct EvidenceAnchorer {
    program_id: Pubkey,
    payer: Option<Keypair>,
    rpc_url: String,
}

impl EvidenceAnchorer {
    pub fn new(program_id: &str, rpc_url: &str) -> AresResult<Self> {
        let pid = Pubkey::from_str(program_id)
            .map_err(|e| AresError::Anchoring(format!("Invalid program ID: {}", e)))?;

        Ok(Self {
            program_id: pid,
            payer: None,
            rpc_url: rpc_url.to_string(),
        })
    }

    pub fn with_payer(mut self, payer: Keypair) -> Self {
        self.payer = Some(payer);
        self
    }

    /// Build the anchor_finding instruction for the Evidence Registry program
    pub fn build_anchor_instruction(
        &self,
        evidence_root: [u8; 32],
        finding_count: u32,
        timestamp: i64,
    ) -> AresResult<Instruction> {
        let payer = self
            .payer
            .as_ref()
            .ok_or_else(|| AresError::Anchoring("No payer keypair set".to_string()))?;

        // PDA: ["evidence", program_id]
        let (pda, _bump) = Pubkey::find_program_address(
            &[b"evidence", self.program_id.as_ref()],
            &self.program_id,
        );

        // Instruction discriminator: anchor_finding (first 8 bytes of sha256("global:anchor_finding"))
        let mut data = Vec::with_capacity(8 + 32 + 4 + 8);
        data.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]); // discriminator stub
        data.extend_from_slice(&evidence_root);
        data.extend_from_slice(&finding_count.to_le_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());

        let accounts = vec![
            solana_sdk::instruction::AccountMeta::new(pda, false),
            solana_sdk::instruction::AccountMeta::new(payer.pubkey(), true),
            solana_sdk::instruction::AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];

        Ok(Instruction {
            program_id: self.program_id,
            accounts,
            data,
        })
    }

    /// Anchor an evidence bundle on-chain
    pub async fn anchor(&self, bundle: &mut EvidenceBundle) -> AresResult<String> {
        let payer = self
            .payer
            .as_ref()
            .ok_or_else(|| AresError::Anchoring("No payer keypair set".to_string()))?;

        // Parse merkle root from hex
        let root_bytes = hex::decode(&bundle.merkle_root)
            .map_err(|e| AresError::Anchoring(format!("Invalid merkle root: {}", e)))?;

        let mut evidence_root = [0u8; 32];
        if root_bytes.len() == 32 {
            evidence_root.copy_from_slice(&root_bytes);
        } else {
            return Err(AresError::Anchoring("Merkle root must be 32 bytes".to_string()));
        }

        let timestamp = bundle.created_at.timestamp();
        let finding_count = bundle.findings.len() as u32;

        let ix = self.build_anchor_instruction(evidence_root, finding_count, timestamp)?;

        tracing::info!(
            "Anchoring bundle {} with {} findings, root={}",
            bundle.batch_id,
            finding_count,
            bundle.merkle_root
        );

        // In production: sign and submit transaction via RPC
        // For now, we simulate the anchoring
        let simulated_tx = format!(
            "simulated_anchor_{}_{}",
            bundle.batch_id,
            chrono::Utc::now().timestamp()
        );

        bundle.anchored = true;
        bundle.anchor_tx = Some(simulated_tx.clone());

        tracing::info!("Evidence anchored: tx={}", simulated_tx);
        Ok(simulated_tx)
    }

    /// Get the PDA for a program's evidence registry
    pub fn evidence_pda(&self) -> Pubkey {
        Pubkey::find_program_address(
            &[b"evidence", self.program_id.as_ref()],
            &self.program_id,
        )
        .0
    }
}
