#![no_main]

use libfuzzer_sys::fuzz_target;
use ares_core::Detector;

// Fuzz target: StaticRulesDetector bytecode pattern matching
// Trailmark: check_arbitrary_cpi (13 downstream, 0 upstream),
// check_missing_owner_check (high_blast_radius), check_integer_arithmetic.
// These functions process untrusted Solana bytecode with windowed pattern
// matching. Fuzzing catches panics from edge cases in window iteration.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Build a DetectionContext with fuzzed bytecode
    let program = ares_core::ProgramInfo::new(
        &bs58::encode(&data[..data.len().min(32)]).into_string(),
        data.to_vec(),
    );

    let ctx = ares_core::DetectionContext {
        program,
        transaction_traces: Vec::new(),
    };

    // Run all detectors — should never panic on arbitrary bytecode
    let detector = ares_detectors::StaticRulesDetector::new();

    // Use blocking runtime since detect is async
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let findings = rt.block_on(detector.detect(&ctx));

    // Verify findings have valid structure
    for f in &findings {
        assert!(!f.id.is_empty(), "finding id must not be empty");
        assert!(!f.title.is_empty(), "finding title must not be empty");
        assert!(!f.program_id.is_empty(), "finding program_id must not be empty");
    }
});
