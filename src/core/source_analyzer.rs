use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use walkdir::WalkDir;
use regex::Regex;
use std::fs;
use flate2::read::GzDecoder;
use std::fs::File;
use tar::Archive;

use crate::models::finding::{Finding, Severity, Category, FindingSource};


struct ScanPattern {
    title: &'static str,
    severity: Severity,
    category: Category,
    regex: Regex,
    
    tool_context_sensitive: bool,
    description: &'static str,
    remediation: &'static str,
}


#[derive(Debug, Clone, Copy, PartialEq)]
enum Confidence {
    
    High,
    
    Medium,
}

pub struct SourceAnalyzer;

impl SourceAnalyzer {
    
    pub async fn download_package(package: &str) -> Result<PathBuf> {
        let npm = if cfg!(windows) {
            "npm.cmd"
        } else {
            "npm"
        };

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            Command::new(npm)
                .args(["pack", package])
                .output(),
        )
        .await
        .map_err(|_| anyhow!("Timeout after 60s running 'npm pack {}'", package))??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "npm pack failed for '{}': {}",
                package,
                stderr.trim()
            ));
        }

        let tarball = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string();

        if tarball.is_empty() {
            return Err(anyhow!("npm pack returned empty output for '{}'", package));
        }

        Ok(std::env::current_dir()?.join(tarball))
    }

    
    pub fn extract_package(tarball: &Path) -> Result<(PathBuf, PathBuf)> {
        if !tarball.exists() {
            return Err(anyhow!("Tarball not found: {}", tarball.display()));
        }

        let dir = tempfile::tempdir()?;
        let file = File::open(tarball)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        archive.unpack(dir.path())?;

        
        let package_dir = dir.path().join("package");
        let root = if package_dir.exists() {
            package_dir
        } else {
            dir.path().to_path_buf()
        };

        
        let persisted = dir.into_path();
        let final_root = if root.starts_with(&persisted) {
            root
        } else {
            persisted.clone()
        };

        Ok((final_root, persisted))
    }

    
    pub fn detect_local_source_dir(server: &crate::core::mcp::McpServer) -> Option<PathBuf> {
        
        if let Some(ref cmd) = server.command {
            let cmd_path = Path::new(cmd);
            if cmd_path.exists() {
                if cmd_path.is_dir() {
                    return Some(cmd_path.to_path_buf());
                } else if let Some(parent) = cmd_path.parent() {
                    if parent.is_dir() {
                        return Some(parent.to_path_buf());
                    }
                }
            }
        }

        
        for arg in &server.args {
            let path = Path::new(arg);
            if path.exists() {
                if path.is_dir() {
                    let looks_like_source = path.join("package.json").exists()
                        || path.join("src").exists()
                        || path.join("index.js").exists()
                        || path.join("index.ts").exists()
                        || path.join("Cargo.toml").exists();

                    if looks_like_source {
                        return Some(path.to_path_buf());
                    }
                } else if let Some(parent) = path.parent() {
                    if parent.is_dir() {
                        let looks_like_source = parent.join("package.json").exists()
                            || parent.join("src").exists()
                            || parent.join("index.js").exists()
                            || parent.join("index.ts").exists()
                            || parent.join("Cargo.toml").exists();

                        if looks_like_source {
                            return Some(parent.to_path_buf());
                        }
                    }
                }
            }
        }

        None
    }

    
    pub fn cleanup(path: &Path) {
        if path.exists() {
            let _ = fs::remove_dir_all(path);
        }
    }

    
    pub fn cleanup_tarball(path: &Path) {
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }

    
    pub fn analyze_source(root: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let patterns = Self::build_patterns()?;
        let mut finding_counter: u32 = 0;

        for entry in WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            
            let path_str = path.display().to_string();
            if path_str.contains("node_modules")
                || path_str.contains(".git")
                /*|| path_str.contains("dist/")*/
                /*|| path_str.contains("build/")*/
            {
                continue;
            }

            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            if !matches!(ext, "js" | "ts" | "mjs" | "cjs" | "py" | "jsx" | "tsx") {
                continue;
            }

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue, 
            };

            
            let has_tool_context = Self::has_tool_handler_context(&content, ext);
            fn is_filesystem_call(line: &str) -> bool {
                line.contains("fs.readFile(")
                    || line.contains("fs.writeFile(")
                    || line.contains("fs.readFileSync(")
                    || line.contains("fs.writeFileSync(")
            }

            fn looks_user_controlled(line: &str) -> bool {
                let vars = [
                   "req.",
                   "request.",
                   "args.",
                   "argv",
                   "input.",
                   "params.",
                   "query.",
                   "body.",
                   "url",
                   "uri",
                   "target",
                   "userInput",
                   "user_input",
                   "filename",
                   "filepath",
                   "path",
                   "file",
                ];

                vars.iter().any(|v| line.contains(v))
            }

            fn is_network_call(line: &str) -> bool {
                line.contains("fetch(")
                    || line.contains("axios(")
                    || line.contains("axios.get(")
                    || line.contains("axios.post(")
                    || line.contains("http.request(")
                    || line.contains("https.request(")

            }

            
            let relative_path = path.strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string();

            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if is_filesystem_call(trimmed)
                    && has_tool_context
                    && looks_user_controlled(trimmed) 
                {
                    

                        finding_counter += 1;

                        findings.push(Finding {

                            id: format!("KRYSTA-SRC-{:03}", finding_counter),

                            title: format!(
                                "Path Traversal — Unsanitized file access in {}:{}",
                                relative_path,
                                line_num + 1
                            ),

                            severity: Severity::High,

                            category: Category::PathTraversal,

                            description:
                                "Filesystem operation appears to use user-controlled input."
                                .to_string(),

                            evidence: format!(
                                "File: {}:{}\nCode: {}",
                                relative_path,
                                line_num + 1,
                                trimmed
                            ),

                            remediation:
                                "Validate and canonicalize paths before filesystem access."
                                .to_string(),

                            source: FindingSource::SourceCode,
                        });
                        if is_network_call(trimmed)
                           && has_tool_context
                           && looks_user_controlled(trimmed)
                        {
                            finding_counter +=1;
                            findings.push(Finding {
                                id: format!("KRYSTA-SRC-{:03}", finding_counter),
                                title: format!("SSRF - User-controlled outbound request in {}:{}",
                                    relative_path,
                                    line_num + 1
                                ),
                                severity: Severity::High,
                                category: Category::SSRF,
                                description: "Network request uses user-controlled input."
                                       .to_string(),
                                evidence: format!(
                                    "File: {}:{}\nCode: {}",
                                    relative_path,
                                    line_num + 1,
                                    trimmed
                                ),
                                remediation: "Validate destination URLs and block internal/private IP ranges." .to_string(),
                                source: FindingSource::SourceCode
                            });
                        }
                    
                }

                
                if trimmed.starts_with("//")
                    || trimmed.starts_with('#')
                    || trimmed.starts_with('*')
                    || trimmed.starts_with("/*")
                {
                    continue;
                }

                for pattern in &patterns {
                    if pattern.category == Category::PathTraversal {
                        continue;
                    }
                    if pattern.category == Category::SSRF {
                        continue;
                    }
                    if pattern.regex.is_match(line) {
                        finding_counter += 1;
                        let confidence = if has_tool_context && pattern.tool_context_sensitive {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        };

                        let severity = if confidence == Confidence::High {
                            pattern.severity.clone()
                        } else {
                           
                            match &pattern.severity {
                                Severity::Critical => Severity::High,
                                other => other.clone(),
                            }
                        };

                        findings.push(Finding {
                            id: format!("KRYSTA-SRC-{:03}", finding_counter),
                            title: format!(
                                "{} in {}:{}",
                                pattern.title,
                                relative_path,
                                line_num + 1
                            ),
                            severity,
                            category: pattern.category.clone(),
                            description: format!(
                                "{} (Confidence: {:?})",
                                pattern.description,
                                confidence
                            ),
                            evidence: format!(
                                "File: {}:{}\nCode: {}",
                                relative_path,
                                line_num + 1,
                                trimmed.chars().take(200).collect::<String>()
                            ),
                            remediation: pattern.remediation.to_string(),
                            source: FindingSource::SourceCode,
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    
    fn has_tool_handler_context(content: &str, ext: &str) -> bool {
        match ext {
            "py" => {
                content.contains("@server.tool")
                    || content.contains("@app.tool")
                    || content.contains("mcp.server")
                    || content.contains("Tool(")
                    || content.contains("def handle_")
            }
            _ => {
                
                content.contains("server.tool(")
                    || content.contains("server.setRequestHandler")
                    || content.contains("ListToolsRequestSchema")
                    || content.contains("CallToolRequestSchema")
                    || content.contains(".handle(")
                    || content.contains("app.post(")
                    || content.contains("McpServer")
                    || content.contains("@modelcontextprotocol")
            }
        }
    }

    
    fn build_patterns() -> Result<Vec<ScanPattern>> {
        let patterns = vec![
            
            ScanPattern {
                title: "Command Injection — exec/spawn",
                severity: Severity::Critical,
                category: Category::CommandInjection,
                regex: Regex::new(
                    r#"(?i)(execSync\(|spawnSync\(|spawn\(|child_process\.exec\(|require\(['"]child_process['"]\))"#
                )?,
                tool_context_sensitive: true,
                description: "Direct process execution found. If user-controlled input reaches this call, arbitrary commands can be executed.",
                remediation: "Use an allowlist of permitted commands. Never pass unsanitized user input to exec/spawn.",
            },

            ScanPattern {
                title: "Command Injection — eval/Function",
                severity: Severity::Critical,
                category: Category::CommandInjection,
                regex: Regex::new(
                    r"(?i)\b(eval\(|new\s+Function\(|setTimeout\([^,]*,|setInterval\([^,]*,)"
                )?,
                tool_context_sensitive: true,
                description: "Dynamic code evaluation found. Can lead to arbitrary code execution if user input is evaluated.",
                remediation: "Never use eval() or new Function() with user-controlled input. Use JSON.parse() for data.",
            },
            ScanPattern {
                title: "Command Injection — Python subprocess",
                severity: Severity::Critical,
                category: Category::CommandInjection,
                regex: Regex::new(
                    r"(?i)(subprocess\.(run|call|Popen|check_output|check_call)|os\.system\(|os\.popen\(|os\.exec)"
                )?,
                tool_context_sensitive: true,
                description: "Python subprocess execution found. Unsanitized input can lead to command injection.",
                remediation: "Use subprocess with shell=False and pass arguments as a list. Validate all inputs.",
            },
            ScanPattern {
                title: "Command Injection — Python eval",
                severity: Severity::Critical,
                category: Category::CommandInjection,
                regex: Regex::new(
                    r"(?i)\b(eval\(|compile\()"
                )?,
                tool_context_sensitive: true,
                description: "Python exec() executes arbitrary Python code.",
                remediation: "Avoid exec(). Use safe parsing or explicit dispatch.",
            },

            
            
            ScanPattern {
                title: "Path Traversal — Python open",
                severity: Severity::High,
                category: Category::PathTraversal,
                regex: Regex::new(
                    r"(?i)\b(open\(|pathlib\.Path|shutil\.(copy|move|rmtree))"
                )?,
                tool_context_sensitive: true,
                description: "Python file operation found. May allow path traversal if input is not validated.",
                remediation: "Resolve paths with os.path.realpath() and check they fall within allowed directories.",
            },

            
            

            
            ScanPattern {
                title: "Credential Exposure — Hardcoded secret",
                severity: Severity::High,
                category: Category::CredentialExposure,
                regex: Regex::new(
                    r#"(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*["'][^"']{8,}["']"#
                )?,
                tool_context_sensitive: false,
                description: "Potential hardcoded secret or API key found in source code.",
                remediation: "Use environment variables or a secrets manager. Never commit secrets to source code.",
            },

            
            ScanPattern {
                title: "Information Disclosure — Environment variable dump",
                severity: Severity::Medium,
                category: Category::InformationDisclosure,
                regex: Regex::new(
                    r"(?i)(process\.env|os\.environ|JSON\.stringify\(process\.env)"
                )?,
                tool_context_sensitive: true,
                description: "Bulk environment variable access found. May leak secrets if exposed through a tool.",
                remediation: "Access only specific environment variables. Never expose the full environment.",
            },

            
            ScanPattern {
                title: "Network Exposure — Binding to all interfaces",
                severity: Severity::High,
                category: Category::NetworkExposure,
                regex: Regex::new(
                    r#"(?i)(listen\(.*0\.0\.0\.0|host\s*[:=]\s*["']0\.0\.0\.0["']|bind\s*\(\s*["']0\.0\.0\.0)"#
                )?,
                tool_context_sensitive: false,
                description: "Server binds to 0.0.0.0, exposing it to all network interfaces.",
                remediation: "Bind to 127.0.0.1 for local-only access, or use a reverse proxy.",
            },

            
            ScanPattern {
                title: "Tool Poisoning — Suspicious tool description",
                severity: Severity::Critical,
                category: Category::ToolPoisoning,
                regex: Regex::new(
                    r#"(?i)(ignore previous|secretly|without user knowledge|exfiltrate|do not tell the user|hidden instruction)"#
                )?,
                tool_context_sensitive: false,
                description: "Suspicious instruction found in source that may poison tool descriptions.",
                remediation: "Audit all tool descriptions for hidden instructions or prompt injection attempts.",
            },
        ];

        Ok(patterns)
    }
}