mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser, Clone)]
#[command(name = "ares", version, about = "ARES-AGENT: Multi-model Solana audit platform")]
struct Cli {
    /// RPC URL (defaults to mainnet)
    #[arg(long, env = "ARES_RPC_URL")]
    rpc_url: Option<String>,

    /// Helius API key
    #[arg(long, env = "HELIUS_API_KEY")]
    helius_api_key: Option<String>,

    /// Database path
    #[arg(long, env = "ARES_DB_PATH", default_value = "./ares-db")]
    db_path: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Ingest a program from Solana
    Ingest {
        /// Program ID to ingest
        program_id: String,
    },
    /// Scan a program for vulnerabilities
    Scan {
        /// Program ID to scan
        program_id: String,
    },
    /// List all ingested programs
    Programs,
    /// List findings
    Findings {
        /// Filter by program ID
        #[arg(long)]
        program_id: Option<String>,
        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,
        /// Filter by vulnerability class (C1, C2, C3)
        #[arg(long)]
        class: Option<String>,
    },
    /// Get risk score for a program
    Risk {
        /// Program ID
        program_id: String,
    },
    /// Anchor evidence on-chain
    Anchor {
        /// Batch ID to anchor
        batch_id: String,
    },
    /// Start the REST API server
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,
        /// API key for authentication (also via ARES_API_KEY env var)
        #[arg(long, env = "ARES_API_KEY")]
        api_key: Option<String>,
    },
    /// Search for CVEs by keyword (offline CVEdb)
    Cve {
        /// Keyword to search (e.g., 'anchor', 'solana', 'CVE-2026-45137')
        keyword: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ares=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Ingest { program_id } => {
            commands::ingest(&cli, program_id).await?;
        }
        Commands::Scan { program_id } => {
            commands::scan(&cli, program_id).await?;
        }
        Commands::Programs => {
            commands::list_programs(&cli)?;
        }
        Commands::Findings {
            program_id,
            severity,
            class,
        } => {
            commands::list_findings(&cli, program_id.clone(), severity.clone(), class.clone()).await?;
        }
        Commands::Risk { program_id } => {
            commands::get_risk(&cli, program_id).await?;
        }
        Commands::Anchor { batch_id } => {
            commands::anchor(&cli, batch_id).await?;
        }
        Commands::Serve { port, api_key } => {
            commands::serve(&cli, *port, api_key.clone()).await?;
        }
        Commands::Cve { keyword } => {
            commands::cve_search(keyword).await?;
        }
    }

    Ok(())
}
