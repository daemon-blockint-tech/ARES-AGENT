# ARES-AGENT

**Multi-Model Multi-Agent System Solana Auditor**

ARES-AGENT is a data-driven Solana audit platform that combines binary-level fuzzing, symbolic execution, static analysis, clone detection, and on-chain evidence anchoring into a unified multi-agent pipeline.

## Architecture

```
Ingestion → Multi-Detector Pipeline → Evidence Bundling → On-chain Anchoring → REST API
                    ↑                                              ↓
            Program Family Clustering                     Agent Eval Lab
```

### Vulnerability Classes (data-driven from 1,669 findings)

| Class | Description | % of High/Critical |
|---|---|---|
| C1 | Business logic & economic exploits | 38.5% |
| C2 | Validation & access control (owner, signer, key, PDA, CPI) | 25.0% |
| C3 | Low-level technical (integer overflow, panics) | 19.0% |

### Risk Scoring Formula

```
Risk(S) = 0.385·f_C1 + 0.250·f_C2 + 0.190·f_C3 + 0.100·g_clone + 0.075·h_economic
```

## Quick Start

### Prerequisites

- Rust 1.75+ (stable)
- Solana CLI tools (optional, for on-chain program deployment)
- Anchor 0.30+ (optional, for on-chain program)
- Python 3.11+ with `uv` (for ML components)

### Build

```bash
cargo build --workspace
```

### CLI Usage

```bash
# Ingest a program from Solana mainnet
ares ingest <PROGRAM_ID> --helius-api-key <KEY>

# Scan a program for vulnerabilities
ares scan <PROGRAM_ID>

# List indexed programs
ares programs

# Start REST API server
ares serve --port 8080

# Anchor evidence on-chain
ares anchor <BATCH_ID>
```

### API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/findings?program_id=&severity=&class=` | List findings |
| GET | `/findings/:id` | Get specific finding |
| GET | `/programs/:id/risk` | Get risk score |
| GET | `/families` | List program families |
| POST | `/webhooks/register` | Register webhook |
| GET | `/eval/metrics` | Eval lab metrics |

### Python Components

```bash
# Clone detection and family clustering
cd python/ares_family
uv sync
ares-family cluster --input programs.json

# Agent evaluation lab
cd python/ares_eval
uv sync
ares-eval init --corpus corpus.json
ares-eval run --corpus corpus.json --findings results.json --detector-id static_rules
```

## Project Structure

```
ARES-AGENT/
├── crates/
│   ├── ares-core/          # Shared types: Finding, Detector, Evidence, RiskScore
│   ├── ares-ingestion/     # RPC client (Helius/Standard), indexer (sled DB)
│   ├── ares-detectors/     # Static rules, CPI tracer, fuzz/symbolic adapters, risk engine
│   ├── ares-evidence/      # Merkle tree bundling, on-chain anchoring client
│   ├── ares-api/           # REST API (axum), webhooks
│   └── ares-cli/           # CLI tool
├── programs/
│   └── evidence_registry/  # Anchor on-chain program for Merkle root anchoring
├── python/
│   ├── ares_family/        # Clone detection (FAISS), family risk propagation
│   ├── ares_eval/          # Agent Eval Lab (precision/recall/F1)
│   └── ares_llm/           # LLM-guided semantic fuzzer (stub)
├── datasets/
│   └── benchmark_corpus/   # Curated findings for evaluation
├── tests/
│   └── integration/        # End-to-end tests
└── docs/
    ├── architecture.md
    ├── ontology.md
    └── threat_model.md
```

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `ARES_RPC_URL` | `https://api.mainnet-beta.solana.com` | Solana RPC URL |
| `HELIUS_API_KEY` | - | Helius API key (enables Helius provider) |
| `ARES_DB_PATH` | `./ares-db` | sled database path |

## License

MIT
