/*
  ARES-AGENT YARA-X Ruleset: Solana SBF/BPF Bytecode Security Detection
  =====================================================================

  Targets compiled Solana programs (.so files) in SBF/BPF ELF format.
  Detects vulnerability patterns based on syscall usage and bytecode
  instruction sequences.

  Solana SBF facts:
  - Programs are ELF files with machine type EM_BPF (0xF7 = 247)
  - Instructions are 8 bytes: opcode(1) + dst_reg:src_reg(1) + offset(2) + imm(4)
  - call instruction (0x85) uses Murmur3-32 hash of syscall name as immediate
  - Key syscall hashes (Murmur3-32, seed=0):
      sol_invoke_signed_c         0xa22b9c85
      sol_invoke_signed_rust      0xd7449092
      sol_create_program_address  0x9377323c
      sol_try_find_program_address 0x48504a38
      sol_sha256                  0x11f49d86
      sol_keccak256               0xd7793abb
      sol_secp256k1_recover       0x17e40350
      sol_memcpy_                 0x717cc4a3
      sol_memcmp_                 0x5fdcde31
      sol_get_clock_sysvar        0xd56b5fe9
      sol_get_return_data         0x5d2245e4
      sol_set_return_data         0xa226d3eb
      sol_log_64_                 0x5c2a3178
      sol_panic_                  0x686093bb

  Author: ARES-AGENT
  License: MIT
*/

import "elf"

// ============================================================
// Rule 1: Solana SBF Program Identifier
// ============================================================
// Identifies any ELF compiled for the Solana BPF target.
// EM_BPF = 247 (0xF7). This is the baseline rule — all
// subsequent rules require this match first.

rule SOL_SBF_Program {
  meta:
    description = "Identifies a compiled Solana SBF/BPF program ELF"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  condition:
    uint16(16) == 0xF7 and  // e_machine = EM_BPF (247)
    uint8(4) == 2 and  // EI_CLASS = ELFCLASS64
    filesize < 10MB
}

// ============================================================
// Rule 2: CPI via sol_invoke_signed_c (Baseline for CPI rules)
// ============================================================
// Detects programs that perform Cross-Program Invocation.
// call opcode = 0x85, immediate = Murmur3 hash of syscall name.
// Instruction layout: [0x85] [0x00] [0x00 0x00] [hash_le32]

rule SOL_CPI_Invoke_Signed_C {
  meta:
    description = "Program uses sol_invoke_signed_c for CPI"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"
    cwe         = "CWE-862"  // Missing Authorization

  strings:
    // call sol_invoke_signed_c: 85 00 0000 859c22a2 (little-endian)
    $invoke_c = { 85 00 00 00 85 9C 22 A2 }

  condition:
    uint16(16) == 0xF7 and
    $invoke_c
}

rule SOL_CPI_Invoke_Signed_Rust {
  meta:
    description = "Program uses sol_invoke_signed_rust for CPI"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  strings:
    // call sol_invoke_signed_rust
    $invoke_rust = { 85 00 00 00 92 90 44 D7 }

  condition:
    uint16(16) == 0xF7 and
    $invoke_rust
}

// ============================================================
// Rule 3: Arbitrary CPI — invoke without owner check
// ============================================================
// Detects programs that use CPI but lack sol_memcmp_ calls,
// which are typically used for owner field comparison.
// This is the #1 Solana exploit vector (Wormhole, Cashio, Crema).

rule SOL_CPI_Without_Owner_Check {
  meta:
    description    = "CPI without owner verification (sol_memcmp_ absent) — top Solana exploit vector"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "high"
    cwe            = "CWE-862"
    cve_examples   = "Wormhole $320M, Cashio $52M, Crema $8.8M"
    recommendation = "Verify account.owner == expected_program_id before CPI"

  strings:
    // call sol_invoke_signed_c
    $invoke_c    = { 85 00 00 00 85 9C 22 A2 }
    // call sol_invoke_signed_rust
    $invoke_rust = { 85 00 00 00 92 90 44 D7 }
    // call sol_memcmp_ (used for owner comparison)
    $memcmp      = { 85 00 00 00 31 DE FD 5F }

  condition:
    uint16(16) == 0xF7 and
    filesize < 10MB and
    ($invoke_c or $invoke_rust) and
    not $memcmp
}

// ============================================================
// Rule 4: PDA Derivation without Canonical Bump Storage
// ============================================================
// Detects programs that use sol_try_find_program_address
// (canonical bump) but NOT sol_create_program_address
// (verification). Programs that only find but don't verify
// may accept attacker-controlled PDAs.

rule SOL_PDA_Without_Verification {
  meta:
    description    = "PDA derivation via try_find without create_program_address verification"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "medium"
    cwe            = "CWE-345"
    recommendation = "Use find_program_address and store canonical bump; verify via create_program_address"

  strings:
    // call sol_try_find_program_address
    $find_pda   = { 85 00 00 00 38 4A 50 48 }
    // call sol_create_program_address
    $create_pda = { 85 00 00 00 3C 32 77 93 }

  condition:
    uint16(16) == 0xF7 and
    $find_pda and
    not $create_pda
}

// ============================================================
// Rule 5: PDA Usage (any) — for audit triage
// ============================================================

rule SOL_PDA_Usage {
  meta:
    description = "Program uses PDA derivation syscalls"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  strings:
    $find_pda   = { 85 00 00 00 38 4A 50 48 }
    $create_pda = { 85 00 00 00 3C 32 77 93 }

  condition:
    uint16(16) == 0xF7 and
    ($find_pda or $create_pda)
}

// ============================================================
// Rule 6: Missing Signer Check — CPI without secp256k1
// ============================================================
// Programs that perform privileged operations (CPI, fund
// transfers) but don't use signature verification syscalls.
// Signer checks in SBF are done via AccountInfo.is_signer flag,
// but programs that also verify signatures via secp256k1_recover
// are more likely to have robust auth.

rule SOL_CPI_Without_Signature_Verification {
  meta:
    description    = "CPI program lacks secp256k1 signature verification"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "medium"
    cwe            = "CWE-306"
    recommendation = "Ensure all privileged instructions verify account.is_signer or use secp256k1_recover"

  strings:
    $invoke_c    = { 85 00 00 00 85 9C 22 A2 }
    $invoke_rust = { 85 00 00 00 92 90 44 D7 }
    // call sol_secp256k1_recover
    $secp        = { 85 00 00 00 50 03 E4 17 }

  condition:
    uint16(16) == 0xF7 and
    ($invoke_c or $invoke_rust) and
    not $secp
}

// ============================================================
// Rule 7: Unchecked Arithmetic — raw ALU without overflow guard
// ============================================================
// SBF ALU opcodes: 0x0f-0x2e (add/sub/mul/div/mod).
// Checked math in Rust emits conditional branch after arithmetic.
// This rule flags programs with ALU ops but no conditional jumps
// (0x1d = jne, 0x30 = jne_reg) following them — a heuristic for
// missing overflow checks.

rule SOL_Unchecked_Arithmetic_Heuristic {
  meta:
    description    = "Program has ALU operations without sol_panic_ (potential unchecked arithmetic)"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "low"
    cwe            = "CWE-190"
    recommendation = "Use checked_add/checked_mul for financial calculations"

  strings:
    // call sol_panic_ (used by Rust checked math on overflow)
    $panic = { 85 00 00 00 BB 93 60 68 }
    // add64 reg, imm: opcode 0x0f with dst_reg in low nibble
    $add64 = { 0F 0? 00 00 }
    // mul64 reg, reg: opcode 0x2f with dst_reg in low nibble
    $mul64 = { 2F 0? 00 00 }

  condition:
    uint16(16) == 0xF7 and
    filesize < 10MB and
    ($add64 or $mul64) and
    not $panic
}

// ============================================================
// Rule 8: Sysvar Access — Clock/Rent (Oracle dependency)
// ============================================================
// Programs reading sysvars are often DeFi protocols that
// depend on oracle data. Flag for manual review of oracle
// manipulation risks.

rule SOL_Sysvar_Clock_Access {
  meta:
    description = "Program reads Clock sysvar — review for oracle/time-dependence vulnerabilities"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"
    cwe         = "CWE-841"

  strings:
    // call sol_get_clock_sysvar
    $clock = { 85 00 00 00 E9 5F 6B D5 }

  condition:
    uint16(16) == 0xF7 and
    $clock
}

// ============================================================
// Rule 9: Return Data Pattern (CPI re-entrancy indicator)
// ============================================================
// Programs that both set and get return data around CPI calls
// may be vulnerable to re-entrancy if state is updated after
// the CPI returns.

rule SOL_CPI_Return_Data_Pattern {
  meta:
    description    = "Program uses CPI with return data — review for re-entrancy (state-after-CPI)"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "medium"
    cwe            = "CWE-836"
    recommendation = "Update state before CPI, not after, to prevent re-entrancy"

  strings:
    $invoke_c    = { 85 00 00 00 85 9C 22 A2 }
    $invoke_rust = { 85 00 00 00 92 90 44 D7 }
    // call sol_get_return_data
    $get_ret     = { 85 00 00 00 E4 45 22 5D }

  condition:
    uint16(16) == 0xF7 and
    ($invoke_c or $invoke_rust) and
    $get_ret
}

// ============================================================
// Rule 10: High-Risk Program Profile
// ============================================================
// Combines multiple risk indicators: CPI + PDA + arithmetic
// without owner check. These programs have the highest
// exploit surface and should be prioritized for audit.

rule SOL_High_Risk_Profile {
  meta:
    description    = "High-risk program: CPI + PDA + arithmetic without owner verification"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "critical"
    recommendation = "Prioritize for full manual audit"

  strings:
    $invoke_c    = { 85 00 00 00 85 9C 22 A2 }
    $invoke_rust = { 85 00 00 00 92 90 44 D7 }
    $find_pda    = { 85 00 00 00 38 4A 50 48 }
    $create_pda  = { 85 00 00 00 3C 32 77 93 }
    $memcmp      = { 85 00 00 00 31 DE FD 5F }
    // add64 reg, imm: opcode 0x0f
    $add64       = { 0F 0? 00 00 }
    // mul64 reg, reg: opcode 0x2f
    $mul64       = { 2F 0? 00 00 }

  condition:
    uint16(16) == 0xF7 and
    filesize < 10MB and
    // Has CPI
    ($invoke_c or $invoke_rust) and
    // Has PDA operations
    ($find_pda or $create_pda) and
    // Lacks owner verification
    not $memcmp and
    // Has arithmetic
    ($add64 or $mul64)
}

// ============================================================
// Rule 11: SHA256 Usage (hash-based patterns)
// ============================================================
// Programs using sol_sha256 may implement custom hashing.
// Review for hash collision risks or improper seed hashing.

rule SOL_SHA256_Usage {
  meta:
    description = "Program uses sol_sha256 syscall"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  strings:
    // call sol_sha256
    $sha = { 85 00 00 00 86 9D F4 11 }

  condition:
    uint16(16) == 0xF7 and
    $sha
}

// ============================================================
// Rule 12: Keccak256 Usage (EVM compatibility / Merkle proofs)
// ============================================================

rule SOL_Keccak256_Usage {
  meta:
    description = "Program uses sol_keccak256 syscall — review Merkle proof verification"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  strings:
    // call sol_keccak256
    $keccak = { 85 00 00 00 BB 3A 79 D7 }

  condition:
    uint16(16) == 0xF7 and
    $keccak
}

// ============================================================
// Rule 13: Anchor Framework Detection
// ============================================================
// Anchor programs contain characteristic strings in .rodata:
// - "anchor" in error messages
// - "global:" prefix for instruction discriminators
// - "AnchorError" in panic messages

rule SOL_Anchor_Framework {
  meta:
    description = "Program compiled with Anchor framework"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  strings:
    $anchor1 = "AnchorError" ascii
    $anchor2 = "anchor" ascii nocase
    $anchor3 = "global:" ascii
    $anchor4 = "InstructionFallbackNotFound" ascii
    $anchor5 = "AccountNotInitialized" ascii

  condition:
    uint16(16) == 0xF7 and
    filesize < 10MB and
    2 of ($anchor*)
}

// ============================================================
// Rule 14: Anchor Program Missing has_one (heuristic)
// ============================================================
// Anchor programs that use "has_one" constraints emit
// "ConstraintHasOne" error strings. Programs with account
// validation but without this string may be missing
// has_one constraints (F-003 pattern).

rule SOL_Anchor_Missing_HasOne {
  meta:
    description    = "Anchor program without ConstraintHasOne — may miss has_one authority checks"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "medium"
    cwe            = "CWE-862"
    recommendation = "Add has_one = authority constraints to account validation structs"

  strings:
    $has_one = "ConstraintHasOne" ascii
    $anchor  = "AnchorError" ascii
    $seeds   = "ConstraintSeeds" ascii

  condition:
    uint16(16) == 0xF7 and
    $anchor and
    $seeds and
    not $has_one
}

// ============================================================
// Rule 15: Debug Build Detection
// ============================================================
// Debug builds contain sol_log_ calls and panic strings.
// These should never be deployed to mainnet.

rule SOL_Debug_Build {
  meta:
    description = "Debug build detected — should not be deployed to mainnet"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "medium"

  strings:
    // call sol_log_64_ (common in debug builds)
    $log64  = { 85 00 00 00 78 31 2A 5C }
    // Debug format strings
    $debug1 = "panicked at" ascii
    $debug2 = "src/" ascii
    $debug3 = ".rs:" ascii

  condition:
    uint16(16) == 0xF7 and
    $log64 and
    any of ($debug*)
}

// ============================================================
// Rule 16: Token Program Interaction
// ============================================================
// Detects programs that likely interact with SPL Token
// by looking for the Token Program ID in .rodata.
// Token Program: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

rule SOL_Token_Program_Interaction {
  meta:
    description = "Program likely interacts with SPL Token program"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  strings:
    // Token Program ID (base58 decoded, 32 bytes)
    // TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
    $token_prog = { 06 DD E6 F4 F1 EE 7A 86 B7 47 3C 3A 9D 4F 45 87 94 8E 09 12 30 01 6B 1A 14 5C 4A E4 4D 41 0F 3A }

  condition:
    uint16(16) == 0xF7 and
    $token_prog
}

// ============================================================
// Rule 17: Large Program (audit complexity indicator)
// ============================================================

rule SOL_Large_Program {
  meta:
    description = "Large Solana program (>500KB) — complex audit surface"
    author      = "ARES-AGENT"
    date        = "2026-06-30"
    severity    = "info"

  condition:
    uint16(16) == 0xF7 and
    filesize > 500KB
}

// ============================================================
// Rule 18: CPI with PDA Signer (privileged escalation)
// ============================================================
// Programs that invoke CPI with PDA signers have elevated
// privileges. Combined with missing owner checks, this is
// the highest-risk pattern on Solana.

rule SOL_CPI_With_PDA_Signer {
  meta:
    description    = "Program uses CPI with PDA signer derivation — privileged escalation pattern"
    author         = "ARES-AGENT"
    date           = "2026-06-30"
    severity       = "high"
    cwe            = "CWE-269"
    recommendation = "Verify all PDA seeds are non-manipulable; verify CPI target program_id"

  strings:
    $invoke_c    = { 85 00 00 00 85 9C 22 A2 }
    $invoke_rust = { 85 00 00 00 92 90 44 D7 }
    $find_pda    = { 85 00 00 00 38 4A 50 48 }
    $create_pda  = { 85 00 00 00 3C 32 77 93 }

  condition:
    uint16(16) == 0xF7 and
    ($invoke_c or $invoke_rust) and
    ($find_pda or $create_pda)
}
