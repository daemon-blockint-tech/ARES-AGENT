# ARES-AGENT Threat Model (STRIDE)

## System Under Analysis

ARES-AGENT: Multi-model Solana audit platform with ingestion, detection, evidence anchoring, and API.

## Trust Boundaries

1. **Solana Mainnet ↔ ARES Ingestion**: Untrusted on-chain data enters system via RPC
2. **ARES Internal Pipeline**: Detectors process bytecode and transaction data
3. **ARES Evidence ↔ On-chain Registry**: Anchoring writes to Solana program
4. **ARES API ↔ External Clients**: REST API exposed to enterprise customers

## STRIDE Analysis

### Spoofing

| Threat | Mitigation |
|---|---|
| Attacker submits fake RPC responses to ingestion | Use authenticated RPC (Helius API key), TLS |
| Unauthorized API access to `/findings` | API key auth (TODO), rate limiting |
| Fake evidence anchoring transaction | PDA-based authority check in Evidence Registry program |

### Tampering

| Threat | Mitigation |
|---|---|
| Tampered bytecode in sled DB | Hash verification on ingest, sled is local-only |
| Forged findings injected into pipeline | Detector signatures, finding UUIDs |
| Merkle root tampering before anchoring | SHA-256 Merkle tree, on-chain immutability |
| Evidence root modified on-chain | Authority check in `update_finding` instruction |

### Repudiation

| Threat | Mitigation |
|---|---|
| Detector denies producing a finding | Each finding has `detector_id` + timestamp |
| Anchoring authority denies submission | On-chain transaction signature, anchor_tx field |

### Information Disclosure

| Threat | Mitigation |
|---|---|
| API leaks findings for non-customer programs | Program-level access control (TODO) |
| Sled DB contains sensitive program data | Local filesystem, OS-level permissions |
| Webhook URLs leaked | Stored in memory only, not persisted (TODO: encrypted storage) |
| LLM fuzzer leaks program logic to external LLM API | Local LLM option, data minimization in prompts |

### Denial of Service

| Threat | Mitigation |
|---|---|
| Large program bytecode exhausts memory | Bytecode size limits, streaming processing |
| API flooded with requests | Rate limiting (TODO), axum connection limits |
| Detector pipeline hangs on pathological input | Timeout per detector (TODO) |
| FAISS index OOM on large program count | Batch indexing, disk-backed index |

### Elevation of Privilege

| Threat | Mitigation |
|---|---|
| Non-authority calls `update_finding` | `require!(registry.authority == authority.key())` |
| PDA collision allows unauthorized evidence write | Canonical bump, program-derived seeds |
| API client escalates to admin operations | Role-based access control (TODO) |

## Priority Mitigations (MVP → Production)

1. **API authentication** — Add API key middleware to axum routes
2. **Detector timeouts** — Wrap each detector in `tokio::time::timeout`
3. **Rate limiting** — `tower::limit` or `tower_governor` middleware
4. **Encrypted webhook storage** — Encrypt webhook URLs at rest in sled
5. **Program access control** — Per-customer program allowlist in API
