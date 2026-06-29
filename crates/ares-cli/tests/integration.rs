use ares_core::{
    DetectionContext, Evidence, EvidenceBundle, Finding, MerkleTree, ProgramInfo, RiskScore,
    Severity, VulnerabilityClass,
};
use ares_detectors::{DetectorPipeline, RiskEngine, StaticRulesDetector};
use ares_evidence::EvidenceBundler;
use std::sync::Arc;

#[tokio::test]
async fn test_full_pipeline_static_rules() {
    // Create a fake program with some bytecode
    let bytecode = vec![
        0x79, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x61, 0x66, 0x0c, 0x00,
    ];
    let program = ProgramInfo::new("Test11111111111111111111111111111111111", bytecode);

    let ctx = DetectionContext {
        program,
        transaction_traces: Vec::new(),
    };

    let mut pipeline = DetectorPipeline::new();
    pipeline.add(Arc::new(StaticRulesDetector::new()));

    let findings = pipeline.run(&ctx).await;

    // Should find at least some findings from static rules
    assert!(
        !findings.is_empty(),
        "Expected findings from static rules detector"
    );

    // All findings should have the correct program_id
    for f in &findings {
        assert_eq!(f.program_id, "Test11111111111111111111111111111111111");
    }
}

#[tokio::test]
async fn test_risk_scoring() {
    let findings = vec![
        Finding::new(
            "prog1",
            "test",
            "Missing owner check",
            "desc",
            Severity::Critical,
            VulnerabilityClass::C2,
        ),
        Finding::new(
            "prog1",
            "test",
            "Arbitrary CPI",
            "desc",
            Severity::Critical,
            VulnerabilityClass::C2,
        ),
        Finding::new(
            "prog1",
            "test",
            "Integer overflow",
            "desc",
            Severity::Low,
            VulnerabilityClass::C3,
        ),
    ];

    let engine = RiskEngine::default();
    let score = engine.compute("prog1", &findings, Some(0.5), Some(0.8));

    assert!(score.c2_score > 0.0);
    assert!(score.c3_score > 0.0);
    assert!(score.total > 0.0);
    assert_eq!(score.clone_family_factor, 0.5);
    assert_eq!(score.economic_exposure, 0.8);
}

#[test]
fn test_merkle_tree() {
    let leaves = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32], vec![4u8; 32]];

    let tree = MerkleTree::new(&leaves);
    assert_eq!(tree.leaf_count(), 4);
    assert_eq!(tree.root().len(), 32);

    // Verify proof for leaf 0
    let proof = tree.proof(0);
    assert!(!proof.is_empty());
}

#[test]
fn test_evidence_bundle() {
    let finding = Finding::new(
        "prog1",
        "test",
        "Test finding",
        "desc",
        Severity::High,
        VulnerabilityClass::C2,
    );
    let evidence = Evidence::new(&finding);

    let bundle = EvidenceBundle::new("batch_001", vec![evidence]).unwrap();

    assert_eq!(bundle.batch_id, "batch_001");
    assert_eq!(bundle.findings.len(), 1);
    assert!(!bundle.merkle_root.is_empty());
    assert!(!bundle.anchored);
}

#[tokio::test]
async fn test_evidence_bundler() {
    let mut bundler = EvidenceBundler::new();

    let f1 = Finding::new(
        "prog1",
        "d1",
        "Finding 1",
        "desc",
        Severity::Critical,
        VulnerabilityClass::C2,
    );
    let f2 = Finding::new(
        "prog1",
        "d2",
        "Finding 2",
        "desc",
        Severity::High,
        VulnerabilityClass::C3,
    );

    bundler.add(&f1);
    bundler.add(&f2);

    assert_eq!(bundler.pending_count(), 2);

    let bundle = bundler.finalize("batch_test").unwrap();
    assert_eq!(bundle.findings.len(), 2);
    assert!(!bundle.merkle_root.is_empty());

    assert_eq!(bundler.pending_count(), 0);
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical.numeric() > Severity::High.numeric());
    assert!(Severity::High.numeric() > Severity::Medium.numeric());
    assert!(Severity::Medium.numeric() > Severity::Low.numeric());
    assert!(Severity::Low.numeric() > Severity::Info.numeric());
}

#[test]
fn test_vulnerability_class_codes() {
    assert_eq!(VulnerabilityClass::C1.code(), "C1");
    assert_eq!(VulnerabilityClass::C2.code(), "C2");
    assert_eq!(VulnerabilityClass::C3.code(), "C3");

    assert_eq!(
        VulnerabilityClass::from_code("c1"),
        Some(VulnerabilityClass::C1)
    );
    assert_eq!(
        VulnerabilityClass::from_code("C2"),
        Some(VulnerabilityClass::C2)
    );
    assert_eq!(VulnerabilityClass::from_code("X1"), None);
}

#[test]
fn test_risk_score_severity_labels() {
    let critical = RiskScore::new("test", 1.0, 1.0, 1.0, 1.0, 1.0);
    assert_eq!(critical.severity_label(), "critical");

    let info = RiskScore::new("test", 0.01, 0.01, 0.01, 0.01, 0.01);
    assert_eq!(info.severity_label(), "info");
}
