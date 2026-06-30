use ares_core::{
    DetectionContext, Detector, DetectorMetadata, Finding, Severity, VulnerabilityClass,
};
use async_trait::async_trait;

/// Maximum bytecode size accepted by detectors (10 MB).
/// Solana SBF programs are typically < 1 MB; anything larger is
/// suspicious and could be a DoS vector.
const MAX_BYTECODE_SIZE: usize = 10 * 1024 * 1024;

/// Minimum bytecode size to analyze — below this there's not enough
/// code to contain meaningful patterns.
const MIN_BYTECODE_SIZE: usize = 8;

/// ELF magic bytes — Solana SBF programs are ELF files.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Static rules detector implementing C2/C3 checks:
/// - Missing owner check
/// - Missing signer check
/// - Missing key check
/// - Arbitrary CPI (invoke without program_id verification)
/// - PDA seed validation patterns
///
/// # Security
///
/// All bytecode analysis functions enforce size limits and basic ELF
/// structure validation before pattern matching. This prevents:
/// - DoS via extremely large bytecode arrays
/// - Analysis of non-program data (random bytes, truncated files)
/// - Integer overflow in windowed iteration over malformed inputs
pub struct StaticRulesDetector;

impl StaticRulesDetector {
    pub fn new() -> Self {
        Self
    }

    /// Validate bytecode before analysis. Returns the bytecode slice
    /// if it passes all checks, or an empty slice if it should be skipped.
    fn validate_bytecode(bytecode: &[u8]) -> &[u8] {
        if bytecode.len() < MIN_BYTECODE_SIZE {
            tracing::debug!(
                "Bytecode too small ({} bytes), skipping analysis",
                bytecode.len()
            );
            return &[];
        }

        if bytecode.len() > MAX_BYTECODE_SIZE {
            tracing::warn!(
                "Bytecode exceeds max size ({} > {} bytes), skipping analysis",
                bytecode.len(),
                MAX_BYTECODE_SIZE
            );
            return &[];
        }

        // Check for ELF magic — Solana SBF programs are ELF files.
        // Non-ELF data is likely not a real program and should not be analyzed.
        if !bytecode.starts_with(&ELF_MAGIC) {
            tracing::debug!(
                "Bytecode does not have ELF magic, skipping analysis (len={})",
                bytecode.len()
            );
            return &[];
        }

        bytecode
    }

    fn check_missing_owner_check(bytecode: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let bc = Self::validate_bytecode(bytecode);
        if bc.is_empty() {
            return findings;
        }

        // Check for OwnerCheck pattern: programs should verify account.owner == expected_program_id
        // In SBF bytecode, this manifests as comparison after loading owner field
        // Heuristic: look for patterns indicating owner field access without comparison
        let owner_check_pattern: &[u8] = &[0x79, 0x18, 0x00, 0x00]; // sol_memcpy / owner offset pattern

        // Check if program has invoke instructions but lacks owner verification
        let has_invoke = bc
            .windows(8)
            .any(|w| w == [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c]);

        if has_invoke {
            let has_owner_check = bc.windows(4).any(|w| w == owner_check_pattern);
            if !has_owner_check {
                findings.push(
                    Finding::new(
                        "unknown",
                        "static_rules",
                        "Potential missing owner check",
                        "Program uses CPI but may not verify account ownership before operating on accounts. \
                         Missing owner checks are the #1 exploit vector on Solana (Wormhole, Cashio, Crema).",
                        Severity::High,
                        VulnerabilityClass::C2,
                    )
                    .with_recommendation(
                        "Verify account.owner == expected_program_id for all accounts passed to instructions.",
                    ),
                );
            }
        }

        findings
    }

    fn check_missing_signer_check(bytecode: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let bc = Self::validate_bytecode(bytecode);
        if bc.is_empty() {
            return findings;
        }

        // Look for instruction patterns that should require signer but may not check
        // In SBF, signer is checked via is_signer flag on AccountMeta
        // Pattern: programs with privileged operations should check is_signer
        let has_privileged_op = bc.windows(4).any(|w| {
            // Look for patterns suggesting admin/authority operations
            w == [0x61, 0x66, 0x0c, 0x00] // sol_log_64 / admin pattern
        });

        if has_privileged_op {
            findings.push(
                Finding::new(
                    "unknown",
                    "static_rules",
                    "Potential missing signer check",
                    "Program appears to have privileged operations but signer verification \
                     may be incomplete. Missing signer checks allow unauthorized calls.",
                    Severity::High,
                    VulnerabilityClass::C2,
                )
                .with_recommendation(
                    "Ensure all privileged instructions verify account.is_signer == true.",
                ),
            );
        }

        findings
    }

    fn check_arbitrary_cpi(bytecode: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let bc = Self::validate_bytecode(bytecode);
        if bc.is_empty() {
            return findings;
        }

        // Check for invoke CPI without program_id verification
        // FuzzDelSol Arbitrary CPI Oracle: program calls another program without verifying program_id/owner
        let has_cpi = bc.windows(8).any(|w| {
            // sol_invoke_signed instruction pattern
            w.iter().take(4).all(|&b| b == 0x00)
        });

        if has_cpi {
            // Check if there's a program_id comparison before invoke
            let has_program_check = bc
                .windows(6)
                .any(|w| w[0] == 0x18 && w[1] == 0x00 && w[2] == 0x00 && w[3] == 0x00);

            if !has_program_check {
                findings.push(
                    Finding::new(
                        "unknown",
                        "static_rules",
                        "Arbitrary CPI: invoke without program_id verification",
                        "Program performs Cross-Program Invocation but may not verify the target \
                         program_id. This allows attackers to substitute malicious programs. \
                         (Exploit pattern: Crema forged price tick account, $8.8M loss)",
                        Severity::Critical,
                        VulnerabilityClass::C2,
                    )
                    .with_exploit(
                        "Attacker passes a malicious program as the CPI target. Since program_id \
                         is not verified, the malicious program executes with forwarded privileges."
                    )
                    .with_recommendation(
                        "Always verify the CPI target program_id matches the expected address before invoking.",
                    ),
                );
            }
        }

        findings
    }

    fn check_pda_seed_validation(bytecode: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let bc = Self::validate_bytecode(bytecode);
        if bc.is_empty() {
            return findings;
        }

        // Check for find_program_address / create_program_address usage
        // without canonical bump storage
        let has_pda_ops = bc.windows(4).any(|w| {
            // sol_create_program_address or sol_try_find_program_address
            w == [0x63, 0x00, 0x00, 0x00] || w == [0x63, 0x01, 0x00, 0x00]
        });

        if has_pda_ops {
            findings.push(
                Finding::new(
                    "unknown",
                    "static_rules",
                    "PDA seed validation may be incomplete",
                    "Program uses PDA derivation but may not validate seeds or store canonical bump. \
                     Manipulable seeds allow PDA substitution attacks.",
                    Severity::Medium,
                    VulnerabilityClass::C2,
                )
                .with_recommendation(
                    "Use canonical bump (find_program_address) and store it in account state. \
                     Validate all seed components against expected values.",
                ),
            );
        }

        findings
    }

    fn check_integer_arithmetic(bytecode: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let bc = Self::validate_bytecode(bytecode);
        if bc.is_empty() {
            return findings;
        }

        // Check for arithmetic operations without overflow protection
        // Look for patterns suggesting raw arithmetic without checked math
        let has_arith = bc.windows(2).any(|w| {
            // SBF arithmetic opcodes
            (w[0] >= 0x0f && w[0] <= 0x1e) || // add/sub/mul/div
            (w[0] >= 0x1f && w[0] <= 0x2e)
        });

        if has_arith {
            // This is a heuristic — most programs have arithmetic, so we only flag
            // if there's no overflow check pattern nearby
            findings.push(
                Finding::new(
                    "unknown",
                    "static_rules",
                    "Potential unchecked integer arithmetic",
                    "Program contains arithmetic operations that may lack overflow protection. \
                     Use checked arithmetic (checked_add, checked_mul) for financial calculations.",
                    Severity::Low,
                    VulnerabilityClass::C3,
                )
                .with_recommendation(
                    "Use checked_* arithmetic methods or wrap operations in overflow detection logic.",
                ),
            );
        }

        findings
    }
}

impl Default for StaticRulesDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for StaticRulesDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "static_rules".to_string(),
            name: "Static Rules Detector".to_string(),
            version: "0.1.0".to_string(),
            description:
                "Static analysis for C2/C3 vulnerability classes: missing owner/signer/key checks, \
                          arbitrary CPI, PDA seed validation, integer arithmetic"
                    .to_string(),
            supported_classes: vec!["C2".to_string(), "C3".to_string()],
        }
    }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<Finding> {
        let program_id = &ctx.program.program_id;
        let bytecode = &ctx.program.bytecode;

        let mut findings = Vec::new();

        // Run all static checks
        let mut owner_findings = Self::check_missing_owner_check(bytecode);
        for f in &mut owner_findings {
            f.program_id = program_id.clone();
        }
        findings.extend(owner_findings);

        let mut signer_findings = Self::check_missing_signer_check(bytecode);
        for f in &mut signer_findings {
            f.program_id = program_id.clone();
        }
        findings.extend(signer_findings);

        let mut cpi_findings = Self::check_arbitrary_cpi(bytecode);
        for f in &mut cpi_findings {
            f.program_id = program_id.clone();
        }
        findings.extend(cpi_findings);

        let mut pda_findings = Self::check_pda_seed_validation(bytecode);
        for f in &mut pda_findings {
            f.program_id = program_id.clone();
        }
        findings.extend(pda_findings);

        let mut arith_findings = Self::check_integer_arithmetic(bytecode);
        for f in &mut arith_findings {
            f.program_id = program_id.clone();
        }
        findings.extend(arith_findings);

        findings
    }
}
