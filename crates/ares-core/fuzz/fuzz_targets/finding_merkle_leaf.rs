#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target: Finding::merkle_leaf
// Trailmark: Finding.merkle_leaf is in high_blast_radius (43 nodes).
// Exercises SHA-256 hashing of finding fields with arbitrary string data.
// Catches panics from malformed UTF-8 or extreme string lengths.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let id = format!("FIND-{:04x}", u16::from_le_bytes([data[0], data[1]]));
    let detector_id = "fuzz";
    let title = String::from_utf8_lossy(&data[2..data.len().min(34)]);
    let description = String::from_utf8_lossy(&data[34.min(data.len())..]);

    let finding = ares_core::Finding::new(
        &id,
        detector_id,
        &title,
        &description,
        ares_core::Severity::Medium,
        ares_core::VulnerabilityClass::C2,
    );

    // merkle_leaf returns Vec<u8> — verify it's always 32 bytes (SHA-256)
    let leaf = finding.merkle_leaf();
    assert_eq!(leaf.len(), 32, "merkle_leaf must be 32 bytes");

    // Verify idempotency — same finding should produce same leaf
    let leaf2 = finding.merkle_leaf();
    assert_eq!(leaf, leaf2, "merkle_leaf must be deterministic");
});
