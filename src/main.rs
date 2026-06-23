#![allow(warnings)]

use clap::{Parser, Subcommand};

mod commands;
mod core;
mod models;

use commands::probe::ProbeCommand;
use crate::commands::login::LoginCommand;

#[derive(Parser)]
#[command(name = "krysta-probe")]
#[command(about = "Security scanner for AI agent infrastructure")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Discover and scan MCP servers for vulnerabilities
    Probe(ProbeCommand),
    Login(LoginCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Probe(cmd) => cmd.execute().await?,
        Commands::Login(cmd) => cmd.execute().await?,
    }

    Ok(())
}