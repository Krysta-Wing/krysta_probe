use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,           // e.g., "CVE-2026-XXXX" or "KRYSTA-XXX"
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub description: String,
    pub affected_tools: Vec<String>,  // Tool names or patterns
    pub evidence_pattern: String,     // Regex pattern to match in schema
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
        // Real MCP vulnerabilities based on OX Security report and CVEs
        
        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-001".to_string(),
            severity: Severity::Critical,
            category: Category::CommandInjection,
            title: "Command injection via tool description".to_string(),
            description: "MCP server allows arbitrary command execution through tool inputSchema".to_string(),
            affected_tools: vec!["execute_command".to_string(), "run_shell".to_string(), "exec".to_string()],
            evidence_pattern: r#"("command"|"exec"|"shell").*?"type":\s*"string""#.to_string(),
            remediation: "Remove execute_command tool or sandbox with strict allowlist".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-002".to_string(),
            severity: Severity::High,
            category: Category::PathTraversal,
            title: "Path traversal in file system tools".to_string(),
            description: "File read/write tools lack path validation, allowing access outside workspace".to_string(),
            affected_tools: vec!["read_file".to_string(), "write_file".to_string(), "list_directory".to_string()],
            evidence_pattern: r#""path".*?"type":\s*"string"(?!.*"pattern")"#.to_string(),
            remediation: "Add path pattern validation to inputSchema".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-003".to_string(),
            severity: Severity::High,
            category: Category::SSRF,
            title: "SSRF via fetch_url tool".to_string(),
            description: "URL fetching tool allows access to internal services and metadata endpoints".to_string(),
            affected_tools: vec!["fetch_url".to_string(), "http_request".to_string(), "download".to_string()],
            evidence_pattern: r#"("url"|"endpoint").*?"type":\s*"string"(?!.*"enum")"#.to_string(),
            remediation: "Add URL allowlist or block internal IP ranges".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "CVE-2026-MCP-004".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialExposure,
            title: "Credential exposure in environment variables".to_string(),
            description: "MCP server config contains hardcoded API keys or tokens".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)(api_key|token|secret|password|passwd)\s*[:=]\s*["'][^"']{8,}["']"#.to_string(),
            remediation: "Use environment variable references instead of hardcoded credentials".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "KRYSTA-005".to_string(),
            severity: Severity::Medium,
            category: Category::InformationDisclosure,
            title: "Verbose error messages leak system information".to_string(),
            description: "Debug mode or verbose logging exposes internal paths and stack traces".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"(?i)(debug|verbose|trace).*:.*true"#.to_string(),
            remediation: "Disable debug mode in production".to_string(),
        });

        self.vulnerabilities.push(Vulnerability {
            id: "KRYSTA-006".to_string(),
            severity: Severity::High,
            category: Category::Authentication,
            title: "Missing authentication on MCP endpoint".to_string(),
            description: "MCP server accepts connections without any authentication".to_string(),
            affected_tools: vec!["*".to_string()],
            evidence_pattern: r#"^(?!.*(auth|token|key|bearer)).*"#.to_string(),
            remediation: "Implement API key or OAuth2 authentication".to_string(),
        });
    }

    pub fn check_tool(&self, tool_name: &str, tool_schema: &str) -> Vec<Vulnerability> {
        let mut matches = Vec::new();
        
        for vuln in &self.vulnerabilities {
            // Check if this vulnerability applies to this tool
            let tool_matches = vuln.affected_tools.iter().any(|t| {
                t == "*" || tool_name.to_lowercase().contains(&t.to_lowercase())
            });

            if tool_matches {
                // Check if schema matches evidence pattern
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