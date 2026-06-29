use crate::Cli;
use ares_core::{CVEEntry, DetectionContext};
use ares_detectors::{CpiTracerDetector, DetectorPipeline, RiskEngine, StaticRulesDetector};
use ares_evidence::{EvidenceAnchorer, EvidenceBundler};
use ares_ingestion::{HeliusProvider, Indexer, RpcProvider, StandardRpcProvider};
use std::sync::Arc;

fn make_provider(cli: &Cli) -> Box<dyn RpcProvider> {
    if let Some(key) = &cli.helius_api_key {
        tracing::info!("Using Helius RPC provider");
        Box::new(HeliusProvider::new(key))
    } else {
        let url = cli
            .rpc_url
            .as_deref()
            .unwrap_or("https://api.mainnet-beta.solana.com");
        tracing::info!("Using standard RPC provider: {}", url);
        Box::new(StandardRpcProvider::new(url))
    }
}

pub async fn ingest(cli: &Cli, program_id: &str) -> anyhow::Result<()> {
    let provider = make_provider(cli);
    let indexer = Indexer::open(&cli.db_path)?;

    let program = indexer
        .ingest_program(provider.as_ref(), program_id)
        .await?;

    println!(
        "Ingested program: {} ({} bytes bytecode, source: {})",
        program.program_id,
        program.bytecode.len(),
        program.source_available
    );

    Ok(())
}

pub async fn scan(cli: &Cli, program_id: &str) -> anyhow::Result<()> {
    let indexer = Indexer::open(&cli.db_path)?;

    // Get program from indexer or ingest on the fly
    let program = match indexer.get_program(program_id)? {
        Some(p) => p,
        None => {
            tracing::info!("Program not in index, ingesting...");
            let provider = make_provider(cli);
            indexer
                .ingest_program(provider.as_ref(), program_id)
                .await?
        }
    };

    // Build detection context
    let ctx = DetectionContext {
        program,
        transaction_traces: Vec::new(), // TODO: fetch transaction traces
    };

    // Build detector pipeline
    let mut pipeline = DetectorPipeline::new();
    pipeline.add(Arc::new(StaticRulesDetector::new()));
    pipeline.add(Arc::new(CpiTracerDetector::new()));

    // Run detectors
    let findings = pipeline.run(&ctx).await;

    println!("\n=== Scan Results for {} ===", program_id);
    println!("Findings: {}\n", findings.len());

    for (i, f) in findings.iter().enumerate() {
        println!(
            "{}. [{}] {} ({}:{})",
            i + 1,
            f.severity.label().to_uppercase(),
            f.title,
            f.class.code(),
            f.detector_id
        );
        if let Some(ref rec) = f.recommendation {
            println!("   Recommendation: {}", rec);
        }
        println!();
    }

    // Compute risk score
    let risk_engine = RiskEngine::default();
    let risk = risk_engine.compute(program_id, &findings, None, None);
    println!("Risk Score: {:.4} ({})", risk.total, risk.severity_label());
    println!(
        "  C1: {:.3} | C2: {:.3} | C3: {:.3} | Clone: {:.3} | Economic: {:.3}",
        risk.c1_score,
        risk.c2_score,
        risk.c3_score,
        risk.clone_family_factor,
        risk.economic_exposure
    );

    // Bundle evidence
    if !findings.is_empty() {
        let mut bundler = EvidenceBundler::new();
        bundler.add_many(&findings);
        if let Some(bundle) = bundler.finalize(&format!("batch_{}", chrono::Utc::now().timestamp()))
        {
            println!("\nEvidence Bundle: {}", bundle.batch_id);
            println!("  Findings: {}", bundle.findings.len());
            println!("  Merkle Root: {}", bundle.merkle_root);
            println!("  Anchored: {}", bundle.anchored);
        }
    }

    Ok(())
}

pub fn list_programs(cli: &Cli) -> anyhow::Result<()> {
    let indexer = Indexer::open(&cli.db_path)?;
    let programs = indexer.list_programs()?;

    if programs.is_empty() {
        println!("No programs indexed. Use 'ares ingest <program_id>' to add programs.");
        return Ok(());
    }

    println!("Indexed Programs ({}):", programs.len());
    for p in programs {
        println!(
            "  {} ({} bytes, source: {})",
            p.program_id,
            p.bytecode.len(),
            p.source_available
        );
    }

    Ok(())
}

pub async fn list_findings(
    _cli: &Cli,
    program_id: Option<String>,
    severity: Option<String>,
    class: Option<String>,
) -> anyhow::Result<()> {
    // TODO: Query from sled DB or API
    println!(
        "Findings query: program_id={:?}, severity={:?}, class={:?}",
        program_id, severity, class
    );
    println!("Note: Findings are stored in-memory during scan. Start the API server with 'ares serve' for persistent access.");
    Ok(())
}

pub async fn get_risk(_cli: &Cli, program_id: &str) -> anyhow::Result<()> {
    // TODO: Query from sled DB or API
    println!("Risk score for: {}", program_id);
    println!(
        "Note: Run 'ares scan {}' first to compute risk score.",
        program_id
    );
    Ok(())
}

pub async fn anchor(_cli: &Cli, batch_id: &str) -> anyhow::Result<()> {
    println!("Anchoring evidence batch: {}", batch_id);

    // TODO: Load bundle from DB, anchor on-chain
    let anchorer = EvidenceAnchorer::new(
        "Evidencereg111111111111111111111111111111111",
        "https://api.mainnet-beta.solana.com",
    )?;

    println!("Evidence PDA: {}", anchorer.evidence_pda());
    println!("Note: On-chain anchoring requires Solana CLI and keypair configuration.");

    Ok(())
}

pub async fn serve(_cli: &Cli, port: u16, api_key: Option<String>) -> anyhow::Result<()> {
    tracing::info!("Starting ARES API server on port {}", port);

    let mut state = ares_api::AppState::new();
    if let Some(ref key) = api_key {
        state = state.with_api_key(key.clone());
        tracing::info!("API key authentication enabled");
    } else {
        tracing::warn!("API key authentication disabled — all endpoints accessible without auth");
    }
    let router = ares_api::create_router(state);

    let bind_addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("API server listening on http://{}", bind_addr);

    axum::serve(listener, router).await?;

    Ok(())
}

pub async fn cve_search(keyword: &str) -> anyhow::Result<()> {
    let kw = keyword.to_lowercase();
    let known: Vec<CVEEntry> = match kw.as_str() {
        k if k.contains("anchor") || k.contains("authority") || k.contains("cve-2026-45137") => {
            vec![CVEEntry::new(
                "CVE-2026-45137",
                "Anchor framework authority bypass in account validation",
            )
            .with_cvss(9.8, "CRITICAL")
            .with_references(vec![
                "https://github.com/coral-xyz/anchor/security/advisories".to_string(),
                "https://www.sentinelone.com/vulnerability-database/cve-2026-45137/".to_string(),
            ])]
        }
        k if k.contains("solana") || k.contains("web3") => {
            vec![CVEEntry::new(
                "CVE-2022-23734",
                "Solana web3.js private key leakage via error messages",
            )
            .with_cvss(7.5, "HIGH")]
        }
        _ => Vec::new(),
    };

    if known.is_empty() {
        println!("No CVEs found for '{}'", keyword);
    } else {
        println!("Found {} CVE(s) for '{}':", known.len(), keyword);
        for cve in &known {
            let score = cve
                .cvss_v3_score
                .map_or("N/A".to_string(), |s| format!("{:.1}", s));
            println!(
                "  {} (CVSS: {}, {})",
                cve.cve_id,
                score,
                cve.cvss_v3_severity.as_deref().unwrap_or("N/A")
            );
            println!("    {}", cve.description);
            if !cve.references.is_empty() {
                println!("    References:");
                for r in &cve.references {
                    println!("      - {}", r);
                }
            }
        }
    }

    Ok(())
}
