#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target: EvidenceBundle::new with arbitrary hex-encoded merkle leaves
// Trailmark: EvidenceBundle.new is in high_blast_radius.
// EvidenceBundle::new calls hex::decode on merkle_leaf strings then
// MerkleTree::new. Malformed hex could cause panics or unexpected errors.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use fuzz data as raw leaf bytes, encode to hex, build Evidence
    let leaves: Vec<Vec<u8>> = data.chunks(32).map(|c| {
        let mut leaf = vec![0u8; 32];
        let len = c.len().min(32);
        leaf[..len].copy_from_slice(&c[..len]);
        leaf
    }).collect();

    let mut evidences = Vec::new();
    for (i, leaf) in leaves.iter().enumerate() {
        evidences.push(ares_core::Evidence {
            finding_id: format!("FIND-{:04x}", i),
            trace: Vec::new(),
            state_diff: serde_json::Value::Null,
            exploit_scenario: String::new(),
            merkle_leaf: hex::encode(leaf),
        });
    }

    // This should never panic — only return Ok or Err
    let result = ares_core::EvidenceBundle::new("fuzz-batch", evidences);
    if let Ok(bundle) = result {
        // Root must be 64 hex chars (32 bytes)
        assert_eq!(bundle.merkle_root.len(), 64, "merkle_root must be 64 hex chars");
    }
});
