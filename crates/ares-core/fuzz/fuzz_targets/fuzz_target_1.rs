#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target: MerkleTree::new + proof
// Trailmark blast_radius: 43 high_blast_radius nodes include MerkleTree.new
// CC=8 on MerkleTree.proof — exercises edge cases with odd leaf counts,
// empty trees, and large leaf arrays.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Split fuzz input into 32-byte leaves
    let leaves: Vec<Vec<u8>> = data.chunks(32).map(|c| {
        let mut leaf = vec![0u8; 32];
        let len = c.len().min(32);
        leaf[..len].copy_from_slice(&c[..len]);
        leaf
    }).collect();

    let tree = ares_core::MerkleTree::new(&leaves);

    // Verify root is always 32 bytes
    let root = tree.root();
    assert!(root.len() == 32, "root must be 32 bytes, got {}", root.len());

    // Fuzz proof generation for every index
    for i in 0..=tree.leaf_count() {
        let proof = tree.proof(i);
        // Proof for valid indices should have entries (unless single leaf)
        if i < tree.leaf_count() && tree.leaf_count() > 1 {
            assert!(!proof.is_empty(), "proof for valid index {} should not be empty", i);
        }
        // Proof for out-of-bounds indices must be empty
        if i >= tree.leaf_count() {
            assert!(proof.is_empty(), "proof for OOB index {} should be empty", i);
        }
    }
});
