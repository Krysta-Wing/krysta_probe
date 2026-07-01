use anyhow::Result;
use serde::Deserialize;
use crate::core::mcp_client::{McpClient, Tool};
use crate::core::mcp::McpServer;
use crate::core::vuln_db::VulnDb;
use crate::models::finding::{Finding, FindingSource};
use crate::core::source_analyzer::SourceAnalyzer;
use crate::core::package_analyzer::PackageAnalyzer;

pub struct Scanner {
    vuln_db: VulnDb,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            vuln_db: VulnDb::new(),
        }
    }

    
    pub async fn scan(&self, server: &McpServer, deep: bool) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        
        findings.extend(self.static_checks(server));

       
        match self.analyze_package_and_source(server).await {
            Ok(pkg_findings) => findings.extend(pkg_findings),
            Err(e) => {
                eprintln!(
                    "  ⚠ Package analysis failed for '{}': {}",
                    server.name, e
                );
                
            }
        }

        
        if deep {
            match self.deep_scan(server).await {
                Ok(deep_findings) => findings.extend(deep_findings),
                Err(e) => {
                    eprintln!(
                        "  ⚠ Deep scan failed for '{}': {}",
                        server.name, e
                    );
                   
                    findings.push(Finding {
                        id: "KRYSTA-WARN-001".to_string(),
                        title: format!("{} — Deep scan incomplete", server.name),
                        severity: crate::models::finding::Severity::Low,
                        category: crate::models::finding::Category::InformationDisclosure,
                        description: format!(
                            "Deep scan could not complete: {}. Static findings are still valid.",
                            e
                        ),
                        evidence: "Server process may have failed to start or timed out.".to_string(),
                        remediation: "Check server command and try again. Ensure the MCP server is installable.".to_string(),
                        source: FindingSource::Dynamic,
                    });
                }
            }
        }

        
        let merged = self.merge_findings(findings);

        Ok(merged)
    }

   
    fn merge_findings(&self, mut findings: Vec<Finding>) -> Vec<Finding> {
        let has_confirmed_path_traversal = findings.iter().any(|f| 
            (f.source == FindingSource::Dynamic || f.source == FindingSource::SourceCode) 
            && f.category == crate::models::finding::Category::PathTraversal
        );
        let has_confirmed_command_injection = findings.iter().any(|f| 
            (f.source == FindingSource::Dynamic || f.source == FindingSource::SourceCode) 
            && f.category == crate::models::finding::Category::CommandInjection
        );

        findings.retain(|f| {
            if f.source == FindingSource::Static {
                if f.id == "KRYSTA-004" && has_confirmed_path_traversal {
                    
                    return false;
                }
                if f.id == "KRYSTA-003" && has_confirmed_command_injection {
                    
                    return false;
                }
            }
            true
        });

        
        findings.dedup_by(|a, b| a.id == b.id && a.title == b.title);

        findings
    }

    

    fn static_checks(&self, server: &McpServer) -> Vec<Finding> {
        let mut findings = Vec::new();

        
        findings.push(Finding {
            id: "KRYSTA-001".to_string(),
            title: format!("{} — Missing authentication", server.name),
            severity: crate::models::finding::Severity::High,
            category: crate::models::finding::Category::Authentication,
            description: "MCP server has no authentication configured. Any process can connect.".to_string(),
            evidence: "No auth token or credentials found in config".to_string(),
            remediation: "Add API key or OAuth2 authentication to the MCP server.".to_string(),
            source: FindingSource::Static,
        });

        
        if let Some(ref url) = server.url {
            let url_lower = url.to_lowercase();
            if !url_lower.contains("localhost")
                && !url_lower.contains("127.0.0.1")
                && !url_lower.contains("192.168.")
                && !url_lower.contains("10.")
            {
                findings.push(Finding {
                    id: "KRYSTA-002".to_string(),
                    title: format!("{} — Exposed to internet", server.name),
                    severity: crate::models::finding::Severity::Critical,
                    category: crate::models::finding::Category::NetworkExposure,
                    description: "MCP server is accessible from the public internet.".to_string(),
                    evidence: format!("URL: {}", url),
                    remediation: "Bind to localhost (127.0.0.1) or add IP allowlist.".to_string(),
                    source: FindingSource::Static,
                });
            }
        }

        
        if let Some(ref cmd) = server.command {
            let dangerous = ["rm", "curl", "wget", "bash", "sh", "python", "node"];
            if dangerous.iter().any(|&d| cmd.contains(d)) {
                findings.push(Finding {
                    id: "KRYSTA-003".to_string(),
                    title: format!("{} — Potentially dangerous command", server.name),
                    severity: crate::models::finding::Severity::High,
                    category: crate::models::finding::Category::CommandInjection,
                    description: "MCP server command contains potentially dangerous patterns.".to_string(),
                    evidence: format!("Command: {}", cmd),
                    remediation: "Review command arguments. Avoid shell execution with user input.".to_string(),
                    source: FindingSource::Static,
                });
            }
        }

        
        if server.name.contains("file") || server.name.contains("fs") {
            findings.push(Finding {
                id: "KRYSTA-004".to_string(),
                title: format!("{} — Potential path traversal risk", server.name),
                severity: crate::models::finding::Severity::Medium,
                category: crate::models::finding::Category::PathTraversal,
                description: "File system MCP servers often have path traversal vulnerabilities.".to_string(),
                evidence: "Server name suggests file system access".to_string(),
                remediation: "Validate all paths against an allowlist. Block ../ sequences.".to_string(),
                source: FindingSource::Static,
            });
        }

        findings
    }

    
    async fn analyze_package_and_source(&self, server: &McpServer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        
        if let Some(local_dir) = SourceAnalyzer::detect_local_source_dir(server) {
            println!("   Detected local source directory: {}", local_dir.display());

            
            if local_dir.join("package.json").exists() {
                match PackageAnalyzer::inspect_package_contents(&local_dir) {
                    Ok(pkg_findings) => {
                        if !pkg_findings.is_empty() {
                            println!("      Local package findings: {}", pkg_findings.len());
                        }
                        findings.extend(pkg_findings);
                    }
                    Err(e) => {
                        eprintln!("   Local package inspection failed: {}", e);
                    }
                }
            }

            
            match SourceAnalyzer::analyze_source(&local_dir) {
                Ok(src_findings) => {
                    if !src_findings.is_empty() {
                        println!("      Local source code findings: {}", src_findings.len());
                    }
                    findings.extend(src_findings);
                }
                Err(e) => {
                    eprintln!("  ⚠ Local source analysis failed: {}", e);
                }
            }

            return Ok(findings);
        }

        
        let package = match PackageAnalyzer::extract_package(server) {
            Some(pkg) => pkg,
            None => return Ok(findings), 
        };

        println!("   Detected package: {}", package);

        
        match PackageAnalyzer::npm_view(&package).await {
            Ok(info) => {
                println!("     Version   : {}", info.version);
                if let Some(repo) = &info.repository {
                    println!("     Repository: {}", repo);
                }
                if let Some(home) = &info.homepage {
                    println!("     Homepage  : {}", home);
                }
            }
            Err(e) => {
                eprintln!("  ⚠ npm view failed: {}", e);
            }
        }

        
        let tarball = SourceAnalyzer::download_package(&package).await?;
        println!("     Downloaded : {}", tarball.display());

        let (extracted, temp_dir) = SourceAnalyzer::extract_package(&tarball)?;

        
        match PackageAnalyzer::inspect_package_contents(&extracted) {
            Ok(pkg_findings) => {
                if !pkg_findings.is_empty() {
                    println!("      Package findings: {}", pkg_findings.len());
                }
                findings.extend(pkg_findings);
            }
            Err(e) => {
                eprintln!("   Package inspection failed: {}", e);
            }
        }

        
        match SourceAnalyzer::analyze_source(&extracted) {
            Ok(src_findings) => {
                if !src_findings.is_empty() {
                    println!("     🔍 Source code findings: {}", src_findings.len());
                }
                findings.extend(src_findings);
            }
            Err(e) => {
                eprintln!("  ⚠ Source analysis failed: {}", e);
            }
        }

        
        SourceAnalyzer::cleanup(&temp_dir);
        SourceAnalyzer::cleanup_tarball(&tarball);

        Ok(findings)
    }

    
    async fn deep_scan(&self, server: &McpServer) -> Result<Vec<Finding>> {
        let (tools, dynamic_findings) = match server.transport {
            crate::core::mcp::TransportType::Stdio => {
                self.deep_scan_stdio(server).await?
            }
            crate::core::mcp::TransportType::Sse
            | crate::core::mcp::TransportType::Http => {
                let tools = if let Some(ref url) = server.url {
                    self.fetch_http_tools(url).await?
                } else {
                    Vec::new()
                };
                (tools, Vec::new())
            }
            _ => (Vec::new(), Vec::new()),
        };

        let mut findings = dynamic_findings;
        use std::collections::HashSet;
        let mut reported = HashSet::new();

        for tool in &tools {
            let schema_str =
                serde_json::to_string(&tool.input_schema).unwrap_or_default();

            let full_context = format!(
                "{} {} {}",
                tool.name,
                tool.description,
                schema_str
            );

            let vuln_matches = self.vuln_db.check_tool(&tool.name, &full_context);

            for vuln in vuln_matches {
                if (vuln.id == "CVE-2026-MCP-009" || vuln.id == "CVE-2026-MCP-010")
                    && server.transport == crate::core::mcp::TransportType::Stdio
                {
                    continue;
                }
                let key = vuln.id.clone();
                if !reported.insert(key) {
                    continue;
                }
                findings.push(Finding {
                    id: vuln.id,
                    title: format!("{} — {}", server.name, vuln.title),
                    severity: map_severity(&vuln.severity),
                    category: map_category(&vuln.category),
                    description: vuln.description,
                    evidence: format!(
                        "Tool: {} | Schema: {} | Desc: {}",
                        tool.name,
                        schema_str,
                        tool.description
                    ),
                    remediation: vuln.remediation,
                    source: FindingSource::Dynamic,
                });
            }
        }

        Ok(findings)
    }

    
    async fn deep_scan_stdio(
        &self,
        server: &McpServer,
    ) -> Result<(Vec<Tool>, Vec<Finding>)> {
        let command = server
            .command
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing command for stdio server"))?;

        let mut client =
            McpClient::connect_stdio(command, &server.args).await?;

        
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            client.initialize().await?;
            client.initialized().await?;
            anyhow::Ok(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("MCP handshake timed out"))??;

        
        let tools = client.list_tools().await?;

        println!("     🔧 Discovered {} tool(s):", tools.len());
        for tool in &tools {
            println!("        • {}", tool.name);
        }

        
        let mut dynamic_findings = Vec::new();

        match self.test_path_traversal(&mut client, server, &tools).await {
            Ok(f) => dynamic_findings.extend(f),
            Err(e) => eprintln!("  ⚠ Path traversal test failed: {}", e),
        }

        match self.test_command_injection(&mut client, server, &tools).await {
            Ok(f) => dynamic_findings.extend(f),
            Err(e) => eprintln!("  ⚠ Command injection test failed: {}", e),
        }

        match self.test_ssrf(&mut client, server, &tools).await {
            Ok(f) => dynamic_findings.extend(f),
            Err(e) => eprintln!("  ⚠ SSRF test failed: {}", e),
        }

        
        if let Err(e) = client.shutdown().await {
            eprintln!("  ⚠ Server shutdown warning: {}", e);
        }

        Ok((tools, dynamic_findings))
    }

    
    async fn fetch_http_tools(&self, url: &str) -> Result<Vec<Tool>> {
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
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;

        let rpc_response: RpcResponse = response.json().await?;

        Ok(rpc_response.result.tools)
    }

    
    async fn test_path_traversal(
        &self,
        client: &mut McpClient,
        server: &McpServer,
        tools: &[Tool],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut vulnerability_confirmed = false;

        let payloads = vec![
            ("../../Windows/win.ini", "[fonts]"),
            ("../../../../etc/passwd", "root:"),
            ("../../../etc/shadow", "root:"),
        ];

        
        let file_tools: Vec<&Tool> = tools.iter().filter(|t| {
            let lower = t.name.to_lowercase();
            let desc_lower = t.description.to_lowercase();
            lower.contains("read") || lower.contains("file") || lower.contains("get_content")
                || desc_lower.contains("read") || desc_lower.contains("file")
        }).collect();

        for tool in &file_tools {
            if vulnerability_confirmed {
                break;
            }
            
            let path_param = Self::find_param_name(tool, &["path", "file", "filename", "filepath"]);

            for (payload, indicator) in &payloads {
                let mut args_map = serde_json::Map::new();
                args_map.insert(path_param.clone(), serde_json::Value::String(payload.to_string()));
                let args = serde_json::Value::Object(args_map);

                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.call_tool(&tool.name, args),
                )
                .await;

                match result {
                    Ok(Ok(response)) => {
                        let text = response.content.to_string();
                        if text.contains(indicator) {
                            findings.push(Finding {
                                id: "KRYSTA-REAL-001".to_string(),
                                title: format!(
                                    "{} — Confirmed Path Traversal",
                                    server.name
                                ),
                                severity: crate::models::finding::Severity::Critical,
                                category: crate::models::finding::Category::PathTraversal,
                                description:
                                    "Successfully escaped sandbox using filesystem tool."
                                        .to_string(),
                                evidence: format!(
                                    "Tool '{}' accepted payload '{}' and returned sensitive file content",
                                    tool.name, payload
                                ),
                                remediation:
                                    "Restrict filesystem access to allowed directories. \
                                     Resolve canonical paths and validate against allowlist."
                                        .to_string(),
                                source: FindingSource::Dynamic,
                            });
                            vulnerability_confirmed = true;
                            
                            break;
                        }
                    }
                    Ok(Err(_)) => {} 
                    Err(_) => {}     
                }
            }
        }

        Ok(findings)
    }

    
    async fn test_command_injection(
        &self,
        client: &mut McpClient,
        server: &McpServer,
        tools: &[Tool],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let payloads = vec![
            ("echo KRYSTA_CANARY_TOKEN_7x9z", "KRYSTA_CANARY_TOKEN_7x9z"),
            ("whoami", ""),     
            ("id", "uid="),
        ];

        let exec_tools: Vec<&Tool> = tools.iter().filter(|t| {
            let lower = t.name.to_lowercase();
            let desc_lower = t.description.to_lowercase();
            lower.contains("exec") || lower.contains("command") || lower.contains("shell")
                || lower.contains("run") || lower.contains("terminal")
                || desc_lower.contains("execute") || desc_lower.contains("command")
        }).collect();

        for tool in &exec_tools {
            let cmd_param = Self::find_param_name(tool, &["command", "cmd", "script", "input", "code"]);

            for (payload, indicator) in &payloads {
                let mut args_map = serde_json::Map::new();
                args_map.insert(cmd_param.clone(), serde_json::Value::String(payload.to_string()));
                let args = serde_json::Value::Object(args_map);

                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.call_tool(&tool.name, args),
                )
                .await;

                match result {
                    Ok(Ok(response)) => {
                        let output = response.content.to_string();

                        let confirmed = if !indicator.is_empty() {
                            output.contains(indicator)
                        } else {
                            
                            !output.is_empty()
                                && !output.contains("error")
                                && output.len() > 2
                        };

                        if confirmed {
                            findings.push(Finding {
                                id: "KRYSTA-REAL-002".to_string(),
                                title: format!(
                                    "{} — Confirmed Command Injection",
                                    server.name
                                ),
                                severity: crate::models::finding::Severity::Critical,
                                category: crate::models::finding::Category::CommandInjection,
                                description:
                                    "Server executed arbitrary command without sanitization."
                                        .to_string(),
                                evidence: format!(
                                    "Tool '{}' executed '{}' and produced output",
                                    tool.name, payload
                                ),
                                remediation:
                                    "Validate commands against a strict allowlist. \
                                     Never pass user input directly to shell execution."
                                        .to_string(),
                                source: FindingSource::Dynamic,
                            });
                            break;
                        }
                    }
                    Ok(Err(_)) => {}
                    Err(_) => {}
                }
            }
        }

        Ok(findings)
    }

    async fn test_ssrf(
        &self,
        client: &mut McpClient,
        server: &McpServer,
        tools: &[Tool],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let payloads = vec![
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:22",
            "http://127.0.0.1:8080",
            "http://[::1]:80",
        ];

        let url_tools: Vec<&Tool> = tools.iter().filter(|t| {
            let lower = t.name.to_lowercase();
            let desc_lower = t.description.to_lowercase();
            lower.contains("fetch") || lower.contains("http") || lower.contains("request")
                || lower.contains("download") || lower.contains("url")
                || desc_lower.contains("fetch") || desc_lower.contains("url")
                || desc_lower.contains("http")
        }).collect();

        for tool in &url_tools {
            let url_param = Self::find_param_name(tool, &["url", "uri", "href", "endpoint", "target"]);

            for payload in &payloads {
                let mut args_map = serde_json::Map::new();
                args_map.insert(url_param.clone(), serde_json::Value::String(payload.to_string()));
                let args = serde_json::Value::Object(args_map);

                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.call_tool(&tool.name, args),
                )
                .await;

                match result {
                    Ok(Ok(response)) => {
                        
                        let is_error = response.is_error.unwrap_or(false);
                        if !is_error {
                            findings.push(Finding {
                                id: "KRYSTA-REAL-003".to_string(),
                                title: format!(
                                    "{} — Confirmed SSRF",
                                    server.name
                                ),
                                severity: crate::models::finding::Severity::Critical,
                                category: crate::models::finding::Category::SSRF,
                                description:
                                    "Server accepted request to an internal/metadata URL."
                                        .to_string(),
                                evidence: format!(
                                    "Tool '{}' accepted internal URL '{}' without rejection",
                                    tool.name, payload
                                ),
                                remediation:
                                    "Restrict URLs using an allowlist. Block private IP ranges \
                                     (10.x, 172.16-31.x, 192.168.x, 169.254.x, ::1)."
                                        .to_string(),
                                source: FindingSource::Dynamic,
                            });
                            break;
                        }
                    }
                    Ok(Err(_)) => {}
                    Err(_) => {}
                }
            }
        }

        Ok(findings)
    }

    
    fn find_param_name(tool: &Tool, candidates: &[&str]) -> String {
        if let Some(schema) = &tool.input_schema {
            if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
                
                for candidate in candidates {
                    if props.contains_key(*candidate) {
                        return candidate.to_string();
                    }
                }
                
                for candidate in candidates {
                    for key in props.keys() {
                        if key.to_lowercase().contains(candidate) {
                            return key.clone();
                        }
                    }
                }
                
                if let Some(first_key) = props.keys().next() {
                    return first_key.clone();
                }
            }
        }
        
        candidates.first().unwrap_or(&"input").to_string()
    }
}



fn map_severity(sev: &crate::core::vuln_db::Severity) -> crate::models::finding::Severity {
    match sev {
        crate::core::vuln_db::Severity::Critical => crate::models::finding::Severity::Critical,
        crate::core::vuln_db::Severity::High => crate::models::finding::Severity::High,
        crate::core::vuln_db::Severity::Medium => crate::models::finding::Severity::Medium,
        crate::core::vuln_db::Severity::Low => crate::models::finding::Severity::Low,
    }
}

fn map_category(cat: &crate::core::vuln_db::Category) -> crate::models::finding::Category {
    match cat {
        crate::core::vuln_db::Category::CommandInjection => crate::models::finding::Category::CommandInjection,
        crate::core::vuln_db::Category::PathTraversal => crate::models::finding::Category::PathTraversal,
        crate::core::vuln_db::Category::Authentication => crate::models::finding::Category::Authentication,
        crate::core::vuln_db::Category::NetworkExposure => crate::models::finding::Category::NetworkExposure,
        crate::core::vuln_db::Category::InformationDisclosure => crate::models::finding::Category::InformationDisclosure,
        crate::core::vuln_db::Category::CredentialExposure => crate::models::finding::Category::CredentialExposure,
        crate::core::vuln_db::Category::SSRF => crate::models::finding::Category::SSRF,
        crate::core::vuln_db::Category::ToolPoisoning => crate::models::finding::Category::ToolPoisoning,
    }
}


#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: Option<u64>,
    result: ToolList,
}

#[derive(Debug, Deserialize)]
struct ToolList {
    tools: Vec<Tool>,
}
