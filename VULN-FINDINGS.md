# ARES-AGENT Vulnerability Findings

**Scan date:** 2026-06-30  
**Target:** `/Users/macbook/DAEMON_BLOCKINT_TECHNOLOGIES/ARES-AGENT`  
**Files scanned:** 22 source files (Rust + Python + Anchor program)  
**Findings:** 12 (2 HIGH, 4 MEDIUM, 6 LOW)

---

## Summary

| Severity | Count | Confidence Range |
|----------|-------|-----------------|
| HIGH     | 1     | 0.85            |
| MEDIUM   | 4     | 0.70 - 0.90     |
| LOW      | 7     | 0.55 - 0.70     |

---

## F-001: anchor_finding allows anyone to overwrite an existing evidence registry (HIGH)

- **File:** `programs/evidence_registry/src/lib.rs:10`
- **Category:** auth-bypass
- **Confidence:** 0.85

The `anchor_finding` instruction checks `registry.is_initialized` and if so, updates `evidence_root`, `finding_count`, and `last_update` WITHOUT verifying that `ctx.accounts.authority` matches `registry.authority`. The authority check only exists in `update_finding` (line 54-57). However, PDA seeds include `authority.key()`, so a different signer derives a different PDA — mitigating direct exploitation. The missing explicit check is a defense-in-depth gap that becomes exploitable if PDA seeds are ever changed.

**Recommendation:** Add `require!(registry.authority == ctx.accounts.authority.key(), EvidenceRegistryError::Unauthorized)` in the update branch.

---

## F-002: verify_evidence uses UncheckedAccount for authority (MEDIUM)

- **File:** `programs/evidence_registry/src/lib.rs:123`
- **Category:** auth-bypass
- **Confidence:** 0.90

`VerifyEvidence` declares `authority` as `UncheckedAccount<'info>` with no constraints. Any account can be passed. While `verify_evidence` is read-only, the unchecked account pattern is dangerous for future modifications.

**Recommendation:** Add `#[account(signer)]` or use `Signer<'info>`.

---

## F-003: AnchorFinding missing explicit authority-to-registry constraint on update (MEDIUM)

- **File:** `programs/evidence_registry/src/lib.rs:85`
- **Category:** auth-bypass
- **Confidence:** 0.80

Similar to F-001. The `AnchorFinding` struct has no `has_one` or `constraint` linking `authority` to `registry.authority`. Safe by PDA construction today, but architecturally fragile.

**Recommendation:** Add explicit authority check in the update path.

---

## F-004: IngestionConfig embeds API key in URL strings (MEDIUM)

- **File:** `crates/ares-ingestion/src/config.rs:36`
- **Category:** hardcoded-secret
- **Confidence:** 0.75

`IngestionConfig::helius()` stores the API key directly in `rpc_url` and `ws_url` as query parameters. If serialized to disk or logged, the key is exposed in plaintext.

**Recommendation:** Store only the API key; construct URLs at runtime. Add `#[serde(skip_serializing)]` on `api_key`.

---

## F-005: download_program silently returns empty bytecode on base64 decode failure (LOW)

- **File:** `crates/ares-ingestion/src/provider.rs:243`
- **Category:** deserialization
- **Confidence:** 0.70

Uses `.unwrap_or_default()` on base64 decode, silently storing empty bytecode on RPC data corruption.

**Recommendation:** Return an error on decode failure.

---

## F-006: SSRF blocklist incomplete — misses IPv6, 172.17-31.x.x, DNS rebinding (LOW)

- **File:** `crates/ares-api/src/routes.rs:139`
- **Category:** ssrf
- **Confidence:** 0.65

Webhook URL validation misses IPv6 loopback (`::1`), IPv6 link-local, most of 172.16.0.0/12 (only 172.16.* blocked), and is vulnerable to DNS rebinding.

**Recommendation:** Resolve hostname, check all IPs against full RFC1918 + loopback + link-local ranges (IPv4+IPv6), use custom DNS resolver.

---

## F-007: Webhook dispatch does not re-validate URL (MEDIUM)

- **File:** `crates/ares-api/src/webhook.rs:35`
- **Category:** ssrf
- **Confidence:** 0.75

`dispatch_webhooks` sends POST requests without re-validating URLs. If a webhook is added through a code path that bypasses registration validation, finding data is exfiltrated. No timeout, redirect limit, or TLS config.

**Recommendation:** Add defense-in-depth URL validation in dispatch. Configure `reqwest::Client` with redirect policy, timeout, and HTTPS-only.

---

## F-008: Anchor instruction discriminator is hardcoded stub (LOW)

- **File:** `crates/ares-evidence/src/anchorer.rs:55`
- **Category:** hardcoded-secret
- **Confidence:** 0.60

Uses `[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]` instead of actual Anchor discriminator. On-chain transactions will fail.

**Recommendation:** Compute actual discriminator from `sha256("global:anchor_finding")`.

---

## F-009: API server binds to 0.0.0.0 with no authentication (LOW)

- **File:** `crates/ares-cli/src/commands.rs:175`
- **Category:** auth-bypass
- **Confidence:** 0.55

Server binds to all interfaces. All endpoints are unauthenticated — findings, risk scores, and webhook registration are accessible to anyone on the network.

**Recommendation:** Bind to `127.0.0.1` by default. Add `--host` flag for explicit opt-in. Add API key auth.

---

## F-010: No authentication on any API endpoint (MEDIUM)

- **File:** `crates/ares-api/src/state.rs:35`
- **Category:** auth-bypass
- **Confidence:** 0.70

No auth middleware on any route. Attackers can enumerate findings, register malicious webhooks, and query risk scores for target selection.

**Recommendation:** Add API key authentication, rate limiting, and role-based access control.

---

## F-011: Merkle leaf decoding silently uses empty bytes on hex failure (LOW)

- **File:** `crates/ares-core/src/evidence.rs:51`
- **Category:** deserialization
- **Confidence:** 0.60

`EvidenceBundle::new` uses `.unwrap_or_default()` on hex decode of merkle leaves. Invalid hex produces empty leaves, corrupting the Merkle root.

**Recommendation:** Return error on hex decode failure.

---

## F-012: StandardRpcProvider uses unwrap() on Option after is_none check (LOW)

- **File:** `crates/ares-ingestion/src/provider.rs:305`
- **Category:** deserialization
- **Confidence:** 0.65

Double `unwrap()` pattern on `value` after `is_none()` check. Fragile — refactoring could introduce a panic (DoS).

**Recommendation:** Replace with `if let Some(val) = value` pattern.
