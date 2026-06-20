use anyhow::Result;
use serde::Deserialize;
use regex::Regex;

use crate::core::mcp::McpServer;
use crate::core::vuln_db::{VulnDb, Vulnerability, Severity, Category};
use crate::models::finding::Finding as ModelFinding;

pub struct Scanner {
    vuln_db: VulnDb,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            vuln_db: VulnDb::new(),
        }
    }

    pub async fn scan(&self, server: &McpServer, deep: bool) -> Result<Vec<ModelFinding>> {
        let mut findings = Vec::new();

        // Check 1: Missing authentication
        findings.push(ModelFinding {
            id: "KRYSTA-001".to_string(),
            title: format!("{} — Missing authentication", server.name),
            severity: crate::models::finding::Severity::High,
            category: crate::models::finding::Category::Authentication,
            description: "MCP server has no authentication configured. Any process can connect.".to_string(),
            evidence: "No auth token or credentials found in config".to_string(),
            remediation: "Add API key or OAuth2 authentication to the MCP server.".to_string(),
        });

        // Check 2: Exposed to internet
        if let Some(ref url) = server.url {
            let url_lower = url.to_lowercase();
            if !url_lower.contains("localhost") 
                && !url_lower.contains("127.0.0.1")
                && !url_lower.contains("192.168.")
                && !url_lower.contains("10.")
            {
                findings.push(ModelFinding {
                    id: "KRYSTA-002".to_string(),
                    title: format!("{} — Exposed to internet", server.name),
                    severity: crate::models::finding::Severity::Critical,
                    category: crate::models::finding::Category::NetworkExposure,
                    description: "MCP server is accessible from the public internet.".to_string(),
                    evidence: format!("URL: {}", url),
                    remediation: "Bind to localhost (127.0.0.1) or add IP allowlist.".to_string(),
                });
            }
        }

        // Check 3: Dangerous command patterns
        if let Some(ref cmd) = server.command {
            let dangerous = ["rm", "curl", "wget", "bash", "sh", "python", "node"];
            if dangerous.iter().any(|&d| cmd.contains(d)) {
                findings.push(ModelFinding {
                    id: "KRYSTA-003".to_string(),
                    title: format!("{} — Potentially dangerous command", server.name),
                    severity: crate::models::finding::Severity::High,
                    category: crate::models::finding::Category::CommandInjection,
                    description: "MCP server command contains potentially dangerous patterns.".to_string(),
                    evidence: format!("Command: {}", cmd),
                    remediation: "Review command arguments. Avoid shell execution with user input.".to_string(),
                });
            }
        }

        // DEEP SCAN: Fetch tool schemas and check against vulnerability database
        if deep {
            if let Some(ref url) = server.url {
                match self.fetch_tools(url).await {
                    Ok(tools) => {
                        for tool in tools {
                            let schema_str = serde_json::to_string(&tool.input_schema).unwrap_or_default();
                            
                            // Check against vulnerability database
                            let vuln_matches = self.vuln_db.check_tool(&tool.name, &schema_str);
                            for vuln in vuln_matches {
                                findings.push(ModelFinding {
                                    id: vuln.id,
                                    title: format!("{} — {}", server.name, vuln.title),
                                    severity: map_severity(&vuln.severity),
                                    category: map_category(&vuln.category),
                                    description: vuln.description,
                                    evidence: format!("Tool: {} | Pattern matched in schema", tool.name),
                                    remediation: vuln.remediation,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(ModelFinding {
                            id: "KRYSTA-005".to_string(),
                            title: format!("{} — Could not fetch tool schemas", server.name),
                            severity: crate::models::finding::Severity::Medium,
                            category: crate::models::finding::Category::InformationDisclosure,
                            description: "Failed to connect to MCP server for deep scan.".to_string(),
                            evidence: format!("Error: {}", e),
                            remediation: "Verify server is running and accessible.".to_string(),
                        });
                    }
                }
            }
        }

        // Check 4: Path traversal in file system tools
        if server.name.contains("file") || server.name.contains("fs") {
            findings.push(ModelFinding {
                id: "KRYSTA-004".to_string(),
                title: format!("{} — Potential path traversal risk", server.name),
                severity: crate::models::finding::Severity::Medium,
                category: crate::models::finding::Category::PathTraversal,
                description: "File system MCP servers often have path traversal vulnerabilities.".to_string(),
                evidence: "Server name suggests file system access".to_string(),
                remediation: "Validate all paths against an allowlist. Block ../ sequences.".to_string(),
            });
        }

        Ok(findings)
    }

    async fn fetch_tools(&self, url: &str) -> Result<Vec<Tool>> {
        let client = reqwest::Client::new();
        
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });

        let response = client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?;

        let rpc_response: RpcResponse = response.json().await?;
        
        Ok(rpc_response.result.tools)
    }
}

fn map_severity(sev: &Severity) -> crate::models::finding::Severity {
    match sev {
        Severity::Critical => crate::models::finding::Severity::Critical,
        Severity::High => crate::models::finding::Severity::High,
        Severity::Medium => crate::models::finding::Severity::Medium,
        Severity::Low => crate::models::finding::Severity::Low,
    }
}

fn map_category(cat: &Category) -> crate::models::finding::Category {
    match cat {
        Category::CommandInjection => crate::models::finding::Category::CommandInjection,
        Category::PathTraversal => crate::models::finding::Category::PathTraversal,
        Category::Authentication => crate::models::finding::Category::Authentication,
        Category::NetworkExposure => crate::models::finding::Category::NetworkExposure,
        Category::InformationDisclosure => crate::models::finding::Category::InformationDisclosure,
        Category::CredentialExposure => crate::models::finding::Category::CredentialExposure,
        Category::SSRF => crate::models::finding::Category::SSRF,
        Category::ToolPoisoning => crate::models::finding::Category::ToolPoisoning,
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    id: Option<u64>,
    result: ToolList,
}

#[derive(Debug, Deserialize)]
struct ToolList {
    tools: Vec<Tool>,
}

#[derive(Debug, Deserialize)]
struct Tool {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Option<serde_json::Value>,
}

