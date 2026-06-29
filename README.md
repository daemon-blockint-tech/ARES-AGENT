# ARES-AGENT

**Multi-Model Multi-Agent System Solana Auditor**

ARES-AGENT is a data-driven Solana audit platform that combines binary-level fuzzing, symbolic execution, static analysis, clone detection, CVE enrichment, and on-chain evidence anchoring into a unified multi-agent pipeline.

## Architecture

```
Ingestion → Multi-Detector Pipeline → CVE Enrichment → Evidence Bundling → On-chain Anchoring → REST API
                    ↑                                                       ↓
            Program Family Clustering                               Agent Eval Lab
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
- Python 3.11+ with `uv` (for ML components and CVE enrichment)

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

# Search for known CVEs (offline CVEdb)
ares cve <KEYWORD>
# Examples:
ares cve anchor
ares cve solana
ares cve CVE-2026-45137

# Start REST API server (with API key auth)
ares serve --port 8080 --api-key mysecret123

# Start REST API server (without auth, localhost only)
ares serve --port 8080

# Anchor evidence on-chain
ares anchor <BATCH_ID>
```

### API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Health check |
| GET | `/findings?program_id=&severity=&class=` | Yes | List findings |
| GET | `/findings/:id` | Yes | Get specific finding |
| GET | `/programs/:id/risk` | Yes | Get risk score |
| GET | `/families` | Yes | List program families |
| POST | `/webhooks/register` | Yes | Register webhook (SSRF-protected) |
| GET | `/cve/search?keyword=` | Yes | Search known CVEs |
| GET | `/eval/metrics` | Yes | Eval lab metrics |

### API Authentication

All endpoints except `/health` require an API key when configured:

```bash
# Via CLI flag
ares serve --api-key mysecret123

# Via environment variable
ARES_API_KEY=mysecret123 ares serve

# Client usage
curl -H "Authorization: Bearer mysecret123" http://127.0.0.1:8080/findings
```

When no API key is configured, auth is disabled (server logs a warning). The server binds to `127.0.0.1` by default.

### Webhook SSRF Protection

Webhook URL registration is protected against SSRF attacks:

- Only `http` and `https` schemes allowed
- Literal internal IPs (loopback, private, link-local, CGNAT) blocked
- **DNS resolution performed** to prevent DNS rebinding attacks
- All resolved IPs checked against internal ranges (IPv4 and IPv6)

### CVE Enrichment

ARES includes a Python↔Rust CVE bridge for offline CVE enrichment:

```bash
# Python CLI (standalone)
cd python/ares_cve
uv sync
ares-cve search anchor
ares-cve dep-scan anchor-lang 0.28.0
ares-cve enrich findings.json --output enriched.json
ares-cve lookup CVE-2026-45137

# From Rust (automatic during scan)
# The CveBridge calls the Python ares_cve CLI as a subprocess
# Falls back gracefully if Python package is not installed
```

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

# CVE enrichment (offline CVEdb)
cd python/ares_cve
uv sync
ares-cve search solana
ares-cve dep-scan solana-sdk 2.2.1
```

## Project Structure

```
ARES-AGENT/
├── crates/
│   ├── ares-core/          # Shared types: Finding, Detector, Evidence, RiskScore, CVEEntry
│   ├── ares-ingestion/     # RPC client (Helius/Standard), indexer (sled DB)
│   ├── ares-detectors/     # Static rules, CPI tracer, fuzz/symbolic adapters, risk engine
│   ├── ares-evidence/      # Merkle tree bundling, on-chain anchoring, CVE bridge
│   ├── ares-api/           # REST API (axum), webhooks, SSRF protection, API key auth
│   └── ares-cli/           # CLI tool
├── programs/
│   └── evidence_registry/  # Anchor on-chain program for Merkle root anchoring
├── python/
│   ├── ares_family/        # Clone detection (FAISS), family risk propagation
│   ├── ares_eval/          # Agent Eval Lab (precision/recall/F1)
│   ├── ares_cve/           # Offline CVE enrichment (CVEdb, CLI, Python↔Rust bridge)
│   └── ares_llm/           # LLM-guided semantic fuzzer (stub)
├── datasets/
│   └── benchmark_corpus/   # 60 curated findings for evaluation
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
| `ARES_API_KEY` | - | API key for REST API authentication |
| `ARES_PYTHON` | `python3` | Python binary for CVE bridge subprocess |

## Security

- **API server** binds to `127.0.0.1` (localhost only) by default
- **API key authentication** via `Authorization: Bearer <key>` header
- **SSRF protection** on webhook URLs with DNS rebinding prevention
- **Anchor discriminator** computed via `sha256("global:anchor_finding")` (not hardcoded)
- **RPC client timeout** (30s) and **webhook client timeout** (10s) enforced
- **No API keys in URLs** — Helius API key sent via headers, not query params
- **Safe error handling** — no `unwrap()` on network/parse operations

### Dependency Audit

`cargo audit` is configured via `audit.toml`. All 5 vulnerabilities and 11 unmaintained-crate warnings are **transitive dependencies of the Solana SDK** (solana-sdk 2.2.1, solana-client 2.3.13) and cannot be upgraded without Solana releasing new versions:

| Advisory | Crate | Type | Blocked By |
|---|---|---|---|
| RUSTSEC-2024-0344 | curve25519-dalek 3.2.0 | Vulnerability | ed25519-dalek → solana-keypair |
| RUSTSEC-2022-0093 | ed25519-dalek 1.0.1 | Vulnerability | solana-keypair → solana-sdk |
| RUSTSEC-2026-0104 | rustls-webpki 0.101.7 | Vulnerability | rustls 0.21 → solana-pubsub-client |
| RUSTSEC-2026-0098 | rustls-webpki 0.101.7 | Vulnerability | same as above |
| RUSTSEC-2026-0099 | rustls-webpki 0.101.7 | Vulnerability | same as above |
| RUSTSEC-2026-0186 | memmap2 0.5.10 | Unsound | solana-genesis-config → solana-sdk |
| RUSTSEC-2026-0097 | rand 0.7.3 | Unsound | solana-keypair → solana-sdk |
| RUSTSEC-2021-0145 | atty 0.2.14 | Unsound | solana-cli / clap |
| 8 more | various | Unmaintained | solana-sdk transitive |

These are tracked in `audit.toml` and will be resolved when the Solana SDK upstream updates. The CI/CD pipeline runs `cargo audit` as an informational (non-blocking) step.

## CI/CD

GitHub Actions workflow runs on every push and PR:

- `cargo fmt --check` — formatting verification
- `cargo clippy --all-targets -- -D warnings` — zero lint warnings
- `cargo test --all` — full test suite
- `cargo build --workspace` — build verification
- `cargo audit` — dependency vulnerability scan (informational, non-blocking)

See `.github/workflows/ci.yml`.

## License

MIT
