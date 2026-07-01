use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,          
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub description: String,
    pub affected_tools: Vec<String>,  
    pub evidence_pattern: String,     
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Category {
    CommandInjection,
    PathTraversal,
    Authentication,
    NetworkExposure,
    InformationDisclosure,
    CredentialExposure,
    SSRF,
    ToolPoisoning,
}

pub struct VulnDb {
    vulnerabilities: Vec<Vulnerability>,
}

impl VulnDb {
    pub fn new() -> Self {
        let mut db = Self {
            vulnerabilities: Vec::new(),
        };
        db.load_default_vulnerabilities();
        db
    }

    fn load_default_vulnerabilities(&mut self) {
        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-001".to_string(),
            severity: Severity::Critical,
            category: Category::CommandInjection,
            title: "Command injection via tool description".to_string(),
            description: "MCP server allows arbitrary command execution through tool inputSchema".to_string(),
            affected_tools: vec!["execute_command".to_string(), "run_shell".to_string(), "exec".to_string()],
            evidence_pattern: r#"(?i)(command|exec|shell)"#.to_string(),
            remediation: "Remove execute_command tool or sandbox with strict allowlist".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-002".to_string(),
            severity: Severity::High,
            category: Category::PathTraversal,
            title: "Path traversal in file system tools".to_string(),
            description: "File read/write tools lack path validation".to_string(),
            affected_tools: vec!["read_file".to_string(), "write_file".to_string(), "list_directory".to_string()],
            evidence_pattern: r#""path"\s*:\s*\{"#.to_string(),
            remediation: "Add path pattern validation to inputSchema".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-003".to_string(),
            severity: Severity::High,
            category: Category::SSRF,
            title: "SSRF via fetch_url tool".to_string(),
            description: "URL fetching tool allows access to internal services".to_string(),
            affected_tools: vec!["fetch_url".to_string(), "http_request".to_string(), "download".to_string()],
            evidence_pattern: r#""url"\s*:\s*\{"#.to_string(),
            remediation: "Add URL allowlist or block internal IP ranges".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-004".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialExposure,
            title: "Credential exposure in tool schema".to_string(),
            description: "Tool schema contains hardcoded API keys or tokens".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)(api_key|token|secret|password)"#.to_string(),
            remediation: "Never hardcode credentials in tool schemas".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-005".to_string(),
            severity: Severity::Critical,
            category: Category::CommandInjection,
            title: "Exec/Shell injection via subprocess".to_string(),
            description: "Server passes unsanitized input to subprocess or eval".to_string(),
            affected_tools: vec!["execute".to_string(), "run".to_string(), "shell".to_string(), "run_script".to_string()],
            evidence_pattern: r#"(?i)(exec|eval|subprocess|shell)"#.to_string(),
            remediation: "Never pass user input directly to shell execution.".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-006".to_string(),
            severity: Severity::Critical,
            category: Category::CommandInjection,
            title: "Hardening bypass via npx -c flag".to_string(),
            description: "Malicious commands hidden inside npx -c argument".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)-c.*?(curl|wget|bash|rm|sh)"#.to_string(),
            remediation: "Block -c flag in npx invocations.".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-007".to_string(),
            severity: Severity::High,
            category: Category::ToolPoisoning,
            title: "Tool description poisoning".to_string(),
            description: "Malicious instructions injected into tool description".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)(ignore previous|secretly|without user knowledge|exfiltrate|curl http)"#.to_string(),
            remediation: "Validate tool descriptions against known safe patterns.".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-008".to_string(),
            severity: Severity::Medium,
            category: Category::ToolPoisoning,
            title: "Unpinned server configuration".to_string(),
            description: "MCP server uses @latest enabling supply chain attacks".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)@latest"#.to_string(),
            remediation: "Pin all package versions.".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-009".to_string(),
            severity: Severity::High,
            category: Category::NetworkExposure,
            title: "Insecure SSE transport".to_string(),
            description: "SSE endpoint exposed without authentication".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)0\.0\.0\.0"#.to_string(),
            remediation: "Never bind to 0.0.0.0 in production.".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-010".to_string(),
            severity: Severity::High,
            category: Category::SSRF,
            title: "Missing auth on public SSE endpoint".to_string(),
            description: "SSE transport URL exposed to internet without authentication".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#.to_string(),
            remediation: "Add token enforcement or move behind API gateway.".to_string(),
        });
    }

    pub fn check_tool(&self, tool_name: &str, tool_schema: &str) -> Vec<Vulnerability> {
        let mut matches = Vec::new();
        
        for vuln in &self.vulnerabilities {
            
            let tool_matches = vuln.affected_tools.iter().any(|t| {
                t == "*" || tool_name.to_lowercase().contains(&t.to_lowercase())
            });

            if tool_matches {
                
                let regex = regex::Regex::new(&vuln.evidence_pattern);
                if let Ok(re) = regex {
                    if re.is_match(tool_schema) {
                        matches.push(vuln.clone());
                    }
                }
            }
        }
        
        matches
    }

    pub fn all_vulnerabilities(&self) -> &[Vulnerability] {
        &self.vulnerabilities
    }
}

impl Default for VulnDb {
    fn default() -> Self {
        Self::new()
    }
}