use clap::Args;
use colored::*;
use std::path::PathBuf;

use crate::core::mcp::McpDiscovery;
use crate::core::scanner::Scanner;
use crate::models::finding::{Finding, Severity};

#[derive(Args)]
pub struct ProbeCommand {
    /// Path to scan (defaults to current directory)
    #[arg(short, long, default_value = ".")]
    path: PathBuf,

    /// Deep scan (check tool schemas for vulnerabilities)
    #[arg(short, long)]
    deep: bool,

    /// Output format
    #[arg(short, long, default_value = "table", value_parser = ["table", "json", "sarif"])]
    format: String,
}

impl ProbeCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        println!("{}", "🔍 Krysta Probe — Scanning for MCP servers...".bold().cyan());
        println!();

        // Step 1: Discover MCP configs
        let discovery = McpDiscovery::new(&self.path);
        let servers = discovery.find_servers().await?;

        if servers.is_empty() {
            println!("{}", "No MCP servers found.".yellow());
            println!("Searched for: claude_desktop_config.json, .cursor/mcp.json, mcp_settings.json");
            return Ok(());
        }

        println!("Found {} MCP server(s)", servers.len().to_string().bold());
        println!();

        // Step 2: Scan each server
        let mut all_findings: Vec<Finding> = Vec::new();
        let scanner = Scanner::new();

        for server in &servers {
            println!("  📡 {} ({:?})", server.name, server.transport);
            
            let findings = scanner.scan(server, self.deep).await?;
            for finding in &findings {
                let icon = match finding.severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠",
                    Severity::Medium => "🟡",
                    Severity::Low => "🟢",
                };
                println!("    {} {}", icon, finding.title);
            }
            all_findings.extend(findings);
        }

        println!();

        // Step 3: Generate report
        self.generate_report(&servers, &all_findings).await?;

        Ok(())
    }

    async fn generate_report(
        &self,
        servers: &[crate::core::mcp::McpServer],
        findings: &[Finding],
    ) -> anyhow::Result<()> {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

        let risk_score = if critical > 0 {
            "🔴 CRITICAL"
        } else if high > 0 {
            "🟠 HIGH"
        } else if medium > 0 {
            "🟡 MEDIUM"
        } else {
            "🟢 LOW"
        };

        println!("{}", "═".repeat(65).dimmed());
        println!("{}", " SCAN SUMMARY ".bold().white().on_black());
        println!("{}", "═".repeat(65).dimmed());
        println!();
        println!("  Servers Found:    {}", servers.len().to_string().bold());
        println!("  Total Findings:   {}", findings.len().to_string().bold());
        println!();
        println!("  🔴 Critical:     {}", critical.to_string().red().bold());
        println!("  🟠 High:         {}", high.to_string().yellow().bold());
        println!("  🟡 Medium:       {}", medium.to_string().cyan());
        println!("  🟢 Low:          {}", low.to_string().green());
        println!();
        println!("  Risk Score:       {}", risk_score.bold());
        println!();

        if !findings.is_empty() {
            println!("{}", "Detailed findings saved to: krysta-report.json".dimmed());
            
            let report = serde_json::json!({
                "scan_date": chrono::Utc::now().to_rfc3339(),
                "servers_found": servers.len(),
                "total_findings": findings.len(),
                "severity_breakdown": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                },
                "findings": findings,
            });
            std::fs::write("krysta-report.json", serde_json::to_string_pretty(&report)?)?;
        }

        println!();
        println!("{}", "Next steps:".bold());
        println!("  • View full report: cat krysta-report.json");
        println!("  • Upgrade for remediation guides: https://krystawing.com/probe");
        println!();

        Ok(())
    }
}