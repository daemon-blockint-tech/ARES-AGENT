use anchor_lang::prelude::*;

declare_id!("Evidencereg111111111111111111111111111111111");

#[program]
pub mod evidence_registry {
    use super::*;

    /// Anchor a batch of evidence findings on-chain via Merkle root
    pub fn anchor_finding(
        ctx: Context<AnchorFinding>,
        evidence_root: [u8; 32],
        finding_count: u32,
        timestamp: i64,
    ) -> Result<()> {
        let registry = &mut ctx.accounts.evidence_registry;

        if registry.is_initialized {
            // Verify authority before updating
            require!(
                registry.authority == ctx.accounts.authority.key(),
                EvidenceRegistryError::Unauthorized
            );
            // Update existing registry
            registry.evidence_root = evidence_root;
            registry.finding_count = finding_count;
            registry.last_update = timestamp;
            msg!(
                "Evidence updated: root={}, count={}",
                hex::encode(evidence_root),
                finding_count
            );
        } else {
            // Initialize new registry
            registry.authority = ctx.accounts.authority.key();
            registry.evidence_root = evidence_root;
            registry.finding_count = finding_count;
            registry.last_update = timestamp;
            registry.is_initialized = true;
            registry.bump = ctx.bumps.evidence_registry;
            msg!(
                "Evidence registry initialized: root={}, count={}",
                hex::encode(evidence_root),
                finding_count
            );
        }

        Ok(())
    }

    /// Update the evidence root (authority only)
    pub fn update_finding(
        ctx: Context<UpdateFinding>,
        new_root: [u8; 32],
        finding_count: u32,
    ) -> Result<()> {
        let registry = &mut ctx.accounts.evidence_registry;

        require!(
            registry.authority == ctx.accounts.authority.key(),
            EvidenceRegistryError::Unauthorized
        );

        registry.evidence_root = new_root;
        registry.finding_count = finding_count;
        registry.last_update = Clock::get()?.unix_timestamp;

        msg!(
            "Evidence updated: root={}, count={}",
            hex::encode(new_root),
            finding_count
        );

        Ok(())
    }

    /// Verify an evidence root matches the on-chain record
    pub fn verify_evidence(
        ctx: Context<VerifyEvidence>,
        expected_root: [u8; 32],
    ) -> Result<bool> {
        let registry = &ctx.accounts.evidence_registry;
        let matches = registry.evidence_root == expected_root;
        msg!("Evidence verification: {}", if matches { "PASS" } else { "FAIL" });
        Ok(matches)
    }
}

#[derive(Accounts)]
#[instruction()]
pub struct AnchorFinding<'info> {
    #[account(
        mut,
        seeds = [b"evidence", authority.key().as_ref()],
        bump,
        has_one = authority,
        space = 8 + 32 + 32 + 4 + 8 + 1 + 1,
        payer = authority,
    )]
    pub evidence_registry: Account<'info, EvidenceRegistryData>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateFinding<'info> {
    #[account(
        mut,
        seeds = [b"evidence", authority.key().as_ref()],
        bump = evidence_registry.bump,
        has_one = authority,
    )]
    pub evidence_registry: Account<'info, EvidenceRegistryData>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct VerifyEvidence<'info> {
    #[account(
        seeds = [b"evidence", authority.key().as_ref()],
        bump = evidence_registry.bump,
        has_one = authority,
    )]
    pub evidence_registry: Account<'info, EvidenceRegistryData>,

    #[account(signer)]
    pub authority: Signer<'info>,
}

#[account]
pub struct EvidenceRegistryData {
    /// Authority who can update the registry
    pub authority: Pubkey,
    /// Merkle root of the current evidence batch
    pub evidence_root: [u8; 32],
    /// Number of findings in the current batch
    pub finding_count: u32,
    /// Timestamp of last update
    pub last_update: i64,
    /// Whether the registry has been initialized
    pub is_initialized: bool,
    /// Bump seed for PDA
    pub bump: u8,
}

#[error_code]
pub enum EvidenceRegistryError {
    #[msg("Only the authority can update the evidence registry")]
    Unauthorized,
    #[msg("Evidence registry is not initialized")]
    NotInitialized,
}
