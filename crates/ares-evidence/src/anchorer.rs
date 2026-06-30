use ares_core::{AresError, AresResult, EvidenceBundle};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use std::str::FromStr;

/// Maximum number of findings allowed in a single anchor instruction.
/// The on-chain Evidence Registry program should reject values above this.
const MAX_ANCHOR_FINDING_COUNT: u32 = 65_535;

/// Maximum allowed timestamp for anchor instructions (year 2100).
/// Prevents overflow attacks via absurdly large timestamps.
const MAX_ANCHOR_TIMESTAMP: i64 = 4_102_444_800;

/// Anchors evidence bundles on-chain by submitting Merkle roots
/// to the Evidence Registry program.
///
/// # Security
///
/// All inputs to `build_anchor_instruction` are validated before being
/// serialized into the instruction data. This prevents:
/// - Integer overflow in finding_count (DoS on the on-chain program)
/// - Absurd timestamps that could corrupt on-chain state
/// - Empty/invalid merkle roots
pub struct EvidenceAnchorer {
    program_id: Pubkey,
    payer: Option<Keypair>,
    #[allow(dead_code)]
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

    /// Validate inputs to the anchor instruction before building it.
    /// Returns an error if any input is out of bounds.
    fn validate_anchor_inputs(
        evidence_root: [u8; 32],
        finding_count: u32,
        timestamp: i64,
    ) -> AresResult<()> {
        // Evidence root must not be all zeros (indicates unset/invalid merkle root)
        if evidence_root == [0u8; 32] {
            return Err(AresError::Anchoring(
                "Evidence root must not be all zeros".to_string(),
            ));
        }

        if finding_count == 0 {
            return Err(AresError::Anchoring(
                "Finding count must be greater than zero".to_string(),
            ));
        }

        if finding_count > MAX_ANCHOR_FINDING_COUNT {
            return Err(AresError::Anchoring(format!(
                "Finding count {} exceeds maximum {}",
                finding_count, MAX_ANCHOR_FINDING_COUNT
            )));
        }

        if timestamp <= 0 {
            return Err(AresError::Anchoring(
                "Timestamp must be a positive Unix timestamp".to_string(),
            ));
        }

        if timestamp > MAX_ANCHOR_TIMESTAMP {
            return Err(AresError::Anchoring(format!(
                "Timestamp {} exceeds maximum {} (year 2100)",
                timestamp, MAX_ANCHOR_TIMESTAMP
            )));
        }

        Ok(())
    }

    /// Build the anchor_finding instruction for the Evidence Registry program.
    ///
    /// All inputs are validated before being serialized into the instruction data.
    /// See `validate_anchor_inputs` for the specific checks.
    pub fn build_anchor_instruction(
        &self,
        evidence_root: [u8; 32],
        finding_count: u32,
        timestamp: i64,
    ) -> AresResult<Instruction> {
        Self::validate_anchor_inputs(evidence_root, finding_count, timestamp)?;

        let payer = self
            .payer
            .as_ref()
            .ok_or_else(|| AresError::Anchoring("No payer keypair set".to_string()))?;

        // PDA: ["evidence", program_id]
        let (pda, _bump) = Pubkey::find_program_address(
            &[b"evidence", self.program_id.as_ref()],
            &self.program_id,
        );

        // Anchor instruction discriminator: first 8 bytes of sha256("global:anchor_finding")
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"global:anchor_finding");
        let discriminator: [u8; 8] = hasher.finalize()[..8].try_into().unwrap();

        let mut data = Vec::with_capacity(8 + 32 + 4 + 8);
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(&evidence_root);
        data.extend_from_slice(&finding_count.to_le_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());

        let accounts = vec![
            solana_sdk::instruction::AccountMeta::new(pda, false),
            solana_sdk::instruction::AccountMeta::new(payer.pubkey(), true),
            solana_sdk::instruction::AccountMeta::new_readonly(
                solana_sdk::system_program::id(),
                false,
            ),
        ];

        Ok(Instruction {
            program_id: self.program_id,
            accounts,
            data,
        })
    }

    /// Anchor an evidence bundle on-chain
    pub async fn anchor(&self, bundle: &mut EvidenceBundle) -> AresResult<String> {
        let _payer = self
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
            return Err(AresError::Anchoring(
                "Merkle root must be 32 bytes".to_string(),
            ));
        }

        let timestamp = bundle.created_at.timestamp();
        let finding_count = bundle.findings.len() as u32;

        let _ix = self.build_anchor_instruction(evidence_root, finding_count, timestamp)?;

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
        Pubkey::find_program_address(&[b"evidence", self.program_id.as_ref()], &self.program_id).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_anchorer() -> EvidenceAnchorer {
        EvidenceAnchorer::new(
            "Evidencereg111111111111111111111111111111111",
            "https://api.mainnet-beta.solana.com",
        )
        .unwrap()
    }

    #[test]
    fn test_validate_rejects_zero_root() {
        let result = EvidenceAnchorer::validate_anchor_inputs([0u8; 32], 1, 1700000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_zero_finding_count() {
        let result = EvidenceAnchorer::validate_anchor_inputs([1u8; 32], 0, 1700000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_excessive_finding_count() {
        let result =
            EvidenceAnchorer::validate_anchor_inputs([1u8; 32], MAX_ANCHOR_FINDING_COUNT + 1, 1700000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_negative_timestamp() {
        let result = EvidenceAnchorer::validate_anchor_inputs([1u8; 32], 1, -1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_excessive_timestamp() {
        let result =
            EvidenceAnchorer::validate_anchor_inputs([1u8; 32], 1, MAX_ANCHOR_TIMESTAMP + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_accepts_valid_inputs() {
        let result = EvidenceAnchorer::validate_anchor_inputs([1u8; 32], 10, 1700000000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_instruction_rejects_invalid_inputs() {
        let anchorer = test_anchorer();
        // No payer set — should fail
        let result = anchorer.build_anchor_instruction([0u8; 32], 0, 0);
        assert!(result.is_err());
    }
}
