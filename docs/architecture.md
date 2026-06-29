# ARES-AGENT Architecture

## System Overview

ARES-AGENT is a multi-model, multi-agent Solana audit platform that combines binary-level fuzzing, symbolic execution, static analysis, clone detection, and on-chain evidence anchoring into a unified pipeline.

```
┌──────────────────────────────────────────────────────────────┐
│                      ARES-AGENT MVP                          │
│                                                              │
│  ┌────────────┐  ┌─────────────┐  ┌───────────────────────┐  │
│  │ Ingestion  │→ │ Multi-Det   │→ │ Evidence Registry     │  │
│  │ & Indexer  │  │ Pipeline    │  │ + On-chain Anchoring  │  │
│  └────────────┘  └─────────────┘  └───────────────────────┘  │
│       │              │                      │                │
│       ▼              ▼                      ▼                │
│  ┌────────────┐  ┌─────────────┐  ┌───────────────────────┐  │
│  │ Program    │  │ Agent Eval  │  │ REST API + Webhooks   │  │
│  │ Family     │  │ Lab         │  │ + SIEM Integration    │  │
│  │ Clustering │  │ (Metrics)   │  │                       │  │
│  └────────────┘  └─────────────┘  └───────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Module Architecture

### Rust Crates (Off-chain)

| Crate | Purpose |
|---|---|
| `ares-core` | Shared types: Finding, Detector, Evidence, RiskScore, ProgramInfo, MerkleTree |
| `ares-ingestion` | Pluggable RPC trait (Helius + Standard), WebSocket subscriber, sled DB indexer |
| `ares-detectors` | Detector pipeline, static rules (C2/C3), CPI graph tracer, fuzz/symbolic adapters, risk engine |
| `ares-evidence` | Evidence bundling (Merkle tree), on-chain anchoring client |
| `ares-api` | REST API (axum), webhook dispatcher, SIEM integration |
| `ares-cli` | CLI tool: scan, ingest, anchor, serve |

### Solana Program (On-chain)

| Program | Purpose |
|---|---|
| `evidence_registry` | Anchor program for Merkle root anchoring: `anchor_finding`, `update_finding`, `verify_evidence` |

### Python Components (ML/Eval)

| Package | Purpose |
|---|---|
| `ares_family` | Clone detection (FAISS), family clustering, risk propagation |
| `ares_eval` | Agent Eval Lab: benchmark corpus, precision/recall/F1 per class |
| `ares_llm` | LLM-guided semantic fuzzer stub (C1 business logic) |

## Data Flow

1. **Ingest**: `ares ingest <program_id>` → RPC fetch bytecode → sled DB
2. **Scan**: `ares scan <program_id>` → Load from DB → Run detector pipeline → Findings + Risk score
3. **Evidence**: Findings → EvidenceBundler → Merkle tree → Merkle root
4. **Anchor**: Merkle root → Evidence Registry program (on-chain)
5. **API**: `ares serve` → REST endpoints → `/findings`, `/programs/{id}/risk`, `/families`
6. **Eval**: Benchmark corpus → Run detector → EvalRunner → Precision/Recall/F1

## Vulnerability Classification

Based on Solana Security Ecosystem Review 2025 (1,669 vulnerabilities from 163 audits):

| Class | Description | % of High/Critical |
|---|---|---|
| C1 | Business logic & economic exploits | 38.5% |
| C2 | Validation & access control (owner, signer, key, PDA, CPI) | 25.0% |
| C3 | Low-level technical (integer overflow, panics, liveness) | 19.0% |

## Risk Scoring Formula

```
Risk(S) = w1·f_C1(S) + w2·f_C2(S) + w3·f_C3(S) + w4·g_clone(S) + w5·h_economic(S)
```

Default weights: w1=0.385, w2=0.250, w3=0.190, w4=0.100, w5=0.075

## Detector Coverage Matrix

| Detector | C1 | C2 | C3 | Status |
|---|---|---|---|---|
| StaticRulesDetector | - | ✓ | ✓ | Implemented |
| CpiTracerDetector | - | ✓ | ✓ | Implemented |
| FuzzAdapterDetector | - | ✓ | ✓ | Stub (FuzzDelSol) |
| SymbolicAdapterDetector | - | ✓ | - | Stub (SseRex) |
| LLM-guided Fuzzer | ✓ | - | - | Stub (ares_llm) |

## RPC Provider Architecture

```
trait RpcProvider
├── HeliusProvider (default, enterprise)
└── StandardRpcProvider (plain Solana RPC)
```

Configurable via CLI flags or environment variables.
