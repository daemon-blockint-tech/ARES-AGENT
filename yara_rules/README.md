# ARES-AGENT YARA-X Rules: Solana SBF Security Detection

18 YARA-X rules for detecting vulnerability patterns in compiled Solana SBF/BPF programs.

## Usage

```bash
# Validate rules
yr check yara_rules/solana_security.yar

# Scan a compiled Solana program (.so)
yr scan yara_rules/solana_security.yar path/to/program.so

# Scan with specific rule
yr scan -s SOL_CPI_Without_Owner_Check yara_rules/solana_security.yar path/to/program.so
```

## How It Works

Solana programs are ELF files compiled for the BPF target (`EM_BPF = 247`). The SBF instruction set uses 8-byte instructions where `call` (opcode `0x85`) takes a Murmur3-32 hash of the syscall name as its immediate value.

These rules match against:
- **ELF header magic**: `uint16(16) == 0xF7` (EM_BPF machine type)
- **Syscall call patterns**: 8-byte sequences encoding `call <syscall_hash>` in little-endian
- **Anchor framework strings**: Error message strings in `.rodata` section
- **Token Program ID**: 32-byte public key embedded in program data

## Rules Overview

| Rule | Severity | Description |
|------|----------|-------------|
| `SOL_SBF_Program` | info | Baseline: identifies any Solana SBF ELF |
| `SOL_CPI_Invoke_Signed_C` | info | Uses `sol_invoke_signed_c` for CPI |
| `SOL_CPI_Invoke_Signed_Rust` | info | Uses `sol_invoke_signed_rust` for CPI |
| `SOL_CPI_Without_Owner_Check` | **high** | CPI without `sol_memcmp_` (Wormhole/Cashio/Crema pattern) |
| `SOL_PDA_Without_Verification` | medium | PDA `try_find` without `create_program_address` |
| `SOL_PDA_Usage` | info | Any PDA syscall usage |
| `SOL_CPI_Without_Signature_Verification` | medium | CPI without `secp256k1_recover` |
| `SOL_Unchecked_Arithmetic_Heuristic` | low | ALU ops without `sol_panic_` (checked math guard) |
| `SOL_Sysvar_Clock_Access` | info | Reads Clock sysvar (oracle dependence) |
| `SOL_CPI_Return_Data_Pattern` | medium | CPI + return data (re-entrancy risk) |
| `SOL_High_Risk_Profile` | **critical** | CPI + PDA + arithmetic without owner check |
| `SOL_SHA256_Usage` | info | Uses `sol_sha256` syscall |
| `SOL_Keccak256_Usage` | info | Uses `sol_keccak256` (Merkle proof review) |
| `SOL_Anchor_Framework` | info | Compiled with Anchor framework |
| `SOL_Anchor_Missing_HasOne` | medium | Anchor program without `ConstraintHasOne` |
| `SOL_Debug_Build` | medium | Debug build (should not be on mainnet) |
| `SOL_Token_Program_Interaction` | info | Interacts with SPL Token program |
| `SOL_Large_Program` | info | >500KB (complex audit surface) |
| `SOL_CPI_With_PDA_Signer` | high | CPI with PDA signer (privileged escalation) |

## Key Syscall Hashes (Murmur3-32)

| Syscall | Hash | Used For |
|---------|------|----------|
| `sol_invoke_signed_c` | `0xa22b9c85` | CPI (C ABI) |
| `sol_invoke_signed_rust` | `0xd7449092` | CPI (Rust ABI) |
| `sol_create_program_address` | `0x9377323c` | PDA verification |
| `sol_try_find_program_address` | `0x48504a38` | PDA derivation |
| `sol_memcmp_` | `0x5fdcde31` | Memory comparison (owner checks) |
| `sol_secp256k1_recover` | `0x17e40350` | Signature recovery |
| `sol_panic_` | `0x686093bb` | Panic (checked math guard) |
| `sol_sha256` | `0x11f49d86` | SHA-256 hashing |
| `sol_keccak256` | `0xd7793abb` | Keccak-256 hashing |
| `sol_get_return_data` | `0x5d2245e4` | CPI return data |
| `sol_get_clock_sysvar` | `0xd56b5fe9` | Clock sysvar (oracle) |

## Integration with ARES-AGENT

These rules complement the Rust static analysis detectors in `ares-detectors`. While the Rust detectors work on downloaded bytecode at runtime, these YARA rules can be used for:

- Pre-deployment scanning of compiled `.so` files
- Batch scanning of programs from Solana mainnet
- CI/CD integration for Solana program builds
- Threat hunting across program databases

## License

MIT
