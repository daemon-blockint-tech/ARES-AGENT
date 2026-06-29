#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target: RiskEngine::compute with arbitrary findings
// Trailmark: RiskEngine.classify_and_score has CC=10 — highest complexity
// in Rust codebase. Exercises severity weighting, class classification,
// and normalization with large numbers of findings.
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let num_findings = (data[0] as usize % 50) + 1; // 1-50 findings
    let mut findings = Vec::new();

    for i in 0..num_findings {
        let offset = 1 + i * 3;
        if offset + 2 >= data.len() {
            break;
        }

        let severity = match data[offset] % 5 {
            0 => ares_core::Severity::Critical,
            1 => ares_core::Severity::High,
            2 => ares_core::Severity::Medium,
            3 => ares_core::Severity::Low,
            _ => ares_core::Severity::Info,
        };

        let class = match data[offset + 1] % 3 {
            0 => ares_core::VulnerabilityClass::C1,
            1 => ares_core::VulnerabilityClass::C2,
            _ => ares_core::VulnerabilityClass::C3,
        };

        findings.push(ares_core::Finding::new(
            &format!("prog_{:02x}", data[offset + 2]),
            "fuzz",
            &format!("finding_{}", i),
            "fuzz description",
            severity,
            class,
        ));
    }

    let engine = ares_detectors::RiskEngine::default();
    let clone_factor = if data.len() > 1 { Some(data[1] as f64 / 255.0) } else { None };
    let economic = if data.len() > 2 { Some(data[2] as f64 / 255.0) } else { None };

    let score = engine.compute("fuzz-program", &findings, clone_factor, economic);

    // Verify score bounds
    assert!(score.total >= 0.0, "total must be non-negative, got {}", score.total);
    assert!(score.c1_score >= 0.0 && score.c1_score <= 1.0, "c1 out of range: {}", score.c1_score);
    assert!(score.c2_score >= 0.0 && score.c2_score <= 1.0, "c2 out of range: {}", score.c2_score);
    assert!(score.c3_score >= 0.0 && score.c3_score <= 1.0, "c3 out of range: {}", score.c3_score);
    assert!(score.clone_family_factor >= 0.0 && score.clone_family_factor <= 1.0);
    assert!(score.economic_exposure >= 0.0 && score.economic_exposure <= 1.0);
});
