# Daemon Protocol Ontology

## Nouns (Entities)

| Noun | Description | Solana Mapping |
|---|---|---|
| **Program** | A Solana program (smart contract) | `Pubkey` of executable account |
| **Account** | A data account owned by a program | `Pubkey` of non-executable account |
| **Finding** | A detected vulnerability | UUID + evidence bundle |
| **Evidence** | Proof artifact for a finding | Trace + state diff + Merkle leaf |
| **EvidenceBundle** | Batch of evidence with Merkle root | On-chain anchoring unit |
| **RiskScore** | Computed risk for a program | Weighted formula output |
| **ProgramFamily** | Group of cloned/related programs | Clone detection cluster |
| **Detector** | An analysis engine | Trait implementation |
| **DetectionContext** | Input to a detector | Program + transaction traces |
| **TransactionTrace** | Executed transaction data | Signature + instructions |
| **CpiEdge** | A cross-program invocation edge | From → To + validation flags |
| **BenchmarkEntry** | Known vulnerability for eval | Corpus entry |

## Verbs (Actions)

| Verb | Description | Actor |
|---|---|---|
| **ingest** | Download and index a program | Indexer |
| **scan** | Run detector pipeline on a program | DetectorPipeline |
| **detect** | Find vulnerabilities in context | Detector |
| **classify** | Assign C1/C2/C3 class to finding | Detector |
| **score** | Compute risk score | RiskEngine |
| **bundle** | Package findings into evidence | EvidenceBundler |
| **anchor** | Submit Merkle root on-chain | EvidenceAnchorer |
| **verify** | Check on-chain evidence matches | Evidence Registry program |
| **cluster** | Group programs by similarity | FamilyClusterer |
| **propagate** | Spread risk across family | FamilyRiskPropagator |
| **evaluate** | Measure detector precision/recall | EvalRunner |
| **dispatch** | Send webhook notification | WebhookDispatcher |

## Relationships

```
Program ──has──→ Finding
Finding ──has──→ Evidence
Evidence ──belongs_to──→ EvidenceBundle
EvidenceBundle ──anchored_as──→ MerkleRoot (on-chain)
Program ──belongs_to──→ ProgramFamily
ProgramFamily ──has_risk──→ RiskScore
Detector ──produces──→ Finding
Finding ──classified_as──→ VulnerabilityClass (C1/C2/C3)
Finding ──has_severity──→ Severity (Critical/High/Medium/Low/Info)
```

## On-chain Objects

| Object | PDA Seeds | Fields |
|---|---|---|
| EvidenceRegistryData | `["evidence", authority]` | authority, evidence_root, finding_count, last_update, is_initialized, bump |

## Risk Score Weights (Data-Driven)

Derived from Solana Security Ecosystem Review 2025:

| Weight | Factor | Value | Source |
|---|---|---|---|
| w1 | C1 (business logic) | 0.385 | 38.5% of high/critical findings |
| w2 | C2 (validation/access) | 0.250 | 25.0% of high/critical findings |
| w3 | C3 (low-level technical) | 0.190 | 19.0% of high/critical findings |
| w4 | Clone family factor | 0.100 | SolaSim clone ratio >50% |
| w5 | Economic exposure | 0.075 | TVL-weighted impact |
