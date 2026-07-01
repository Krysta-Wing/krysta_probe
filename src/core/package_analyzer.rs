use crate::core::mcp::McpServer;
use crate::models::finding::{Finding, Severity, Category, FindingSource};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tokio::process::Command;
use walkdir::WalkDir;

pub struct PackageAnalyzer;

#[derive(Debug)]
pub struct PackageInfo {
    pub package: String,
    pub version: String,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub tarball: Option<String>,
}

impl PackageAnalyzer {
    pub fn extract_package(server: &McpServer) -> Option<String> {
        let command = server.command.as_ref()?;

        if command != "npx"
            && command != "npx.cmd"
            && command != "npm"
            && command != "npm.cmd"
        {
            return None;
        }

        for arg in &server.args {
            if arg.starts_with('-') {
                continue;
            }

            if arg == "run" {
                continue;
            }

            
            if arg.starts_with('@') || arg.contains('/') {
                return Some(arg.clone());
            }

            
            if !arg.contains('.') && !arg.is_empty() && arg != "-y" && arg != "--yes" {
                return Some(arg.clone());
            }
        }

        None
    }

    
    pub async fn npm_view(package: &str) -> Result<PackageInfo> {
        let npm = if cfg!(windows) {
            "npm.cmd"
        } else {
            "npm"
        };

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Command::new(npm)
                .args(["view", package, "--json"])
                .output(),
        )
        .await
        .map_err(|_| anyhow!("Timeout after 30s running 'npm view {}'", package))??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "npm view failed for '{}': {}",
                package,
                stderr.trim()
            ));
        }

        let value: Value = serde_json::from_slice(&output.stdout)?;

        let version = value["version"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let homepage = value["homepage"]
            .as_str()
            .map(|s| s.to_string());

        let repository = if value["repository"].is_object() {
            value["repository"]["url"]
                .as_str()
                .map(|s| s.to_string())
        } else {
            value["repository"]
                .as_str()
                .map(|s| s.to_string())
        };

        let tarball = value["dist"]["tarball"]
            .as_str()
            .map(|s| s.to_string());

        Ok(PackageInfo {
            package: package.to_string(),
            version,
            repository,
            homepage,
            tarball,
        })
    }

    pub fn inspect_package_contents(root: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut finding_counter: u32 = 0;

        
        findings.extend(Self::check_package_json(root, &mut finding_counter)?);
        findings.extend(Self::check_suspicious_files(root, &mut finding_counter)?);
        findings.extend(Self::check_obfuscated_code(root, &mut finding_counter)?);

        Ok(findings)
    }

    fn check_package_json(root: &Path, counter: &mut u32) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        
        let pkg_json_path = if root.join("package.json").exists() {
            root.join("package.json")
        } else if root.join("package").join("package.json").exists() {
            root.join("package").join("package.json")
        } else {
            return Ok(findings);
        };

        let content = fs::read_to_string(&pkg_json_path)?;
        let value: Value = serde_json::from_str(&content)?;

        
        let dangerous_scripts = [
            "preinstall",
            "postinstall",
            "preuninstall",
            "postuninstall",
            "prepare",
            "prepublish",
        ];

        let dangerous_commands_re = Regex::new(
            r"(?i)(curl|wget|bash|sh\s|powershell|cmd\s|rm\s|del\s|net\s|nc\s|ncat)"
        )?;

        if let Some(scripts) = value.get("scripts").and_then(|s| s.as_object()) {
            for script_name in &dangerous_scripts {
                if let Some(script_cmd) = scripts.get(*script_name).and_then(|s| s.as_str()) {
                    *counter += 1;

                    let severity = if dangerous_commands_re.is_match(script_cmd) {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    findings.push(Finding {
                        id: format!("KRYSTA-PKG-{:03}", counter),
                        title: format!(
                            "Lifecycle script '{}' detected",
                            script_name
                        ),
                        severity,
                        category: Category::CommandInjection,
                        description: format!(
                            "package.json contains a '{}' script that runs during installation. \
                             This is a common supply-chain attack vector.",
                            script_name
                        ),
                        evidence: format!(
                            "Script '{}': {}",
                            script_name,
                            script_cmd.chars().take(200).collect::<String>()
                        ),
                        remediation: "Audit the lifecycle script contents. Consider using \
                            --ignore-scripts during installation."
                            .to_string(),
                        source: FindingSource::Package,
                    });
                }
            }
        }

        
        let dep_sections = ["dependencies", "devDependencies", "optionalDependencies"];
        for section in &dep_sections {
            if let Some(deps) = value.get(*section).and_then(|d| d.as_object()) {
                for (dep_name, dep_version) in deps {
                    let ver = dep_version.as_str().unwrap_or("");
                    if ver.starts_with("git") || ver.starts_with("http") || ver.contains("github") {
                        *counter += 1;
                        findings.push(Finding {
                            id: format!("KRYSTA-PKG-{:03}", counter),
                            title: format!(
                                "Non-registry dependency: {}",
                                dep_name
                            ),
                            severity: Severity::Medium,
                            category: Category::ToolPoisoning,
                            description: format!(
                                "Dependency '{}' is fetched from a git/URL source instead of the \
                                 npm registry. This bypasses registry integrity checks.",
                                dep_name
                            ),
                            evidence: format!("{}: {}", dep_name, ver),
                            remediation: "Pin dependencies to registry versions with exact version numbers."
                                .to_string(),
                            source: FindingSource::Package,
                        });
                    }
                }
            }
        }

        
        let quality_fields = ["license", "repository", "engines"];
        let mut missing: Vec<&str> = Vec::new();
        for field in &quality_fields {
            if value.get(*field).is_none() {
                missing.push(field);
            }
        }
        if !missing.is_empty() {
            *counter += 1;
            findings.push(Finding {
                id: format!("KRYSTA-PKG-{:03}", counter),
                title: "Missing package metadata".to_string(),
                severity: Severity::Low,
                category: Category::InformationDisclosure,
                description: format!(
                    "package.json is missing fields: {}. This reduces traceability and trust.",
                    missing.join(", ")
                ),
                evidence: format!("Missing: {}", missing.join(", ")),
                remediation: "Add license, repository, and engines fields to package.json."
                    .to_string(),
                source: FindingSource::Package,
            });
        }

        Ok(findings)
    }

    
    fn check_suspicious_files(root: &Path, counter: &mut u32) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let suspicious_extensions = [
            "exe", "dll", "so", "dylib", "bat", "cmd", "ps1",
            "sh", "node", "wasm",
        ];

        for entry in WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            if suspicious_extensions.contains(&ext.as_str()) {
                *counter += 1;
                let relative = path.strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string();

                let severity = match ext.as_str() {
                    "exe" | "dll" | "bat" | "cmd" | "ps1" | "sh" => Severity::High,
                    "node" | "so" | "dylib" => Severity::Medium,
                    _ => Severity::Low,
                };

                findings.push(Finding {
                    id: format!("KRYSTA-PKG-{:03}", counter),
                    title: format!("Suspicious file: {}", relative),
                    severity,
                    category: Category::CommandInjection,
                    description: format!(
                        "Package contains a .{} file which may be a bundled binary or script. \
                         Native binaries in npm packages can execute arbitrary code.",
                        ext
                    ),
                    evidence: format!("File: {}", relative),
                    remediation: "Audit the file contents. Prefer pure JavaScript packages \
                        without native binaries."
                        .to_string(),
                    source: FindingSource::Package,
                });
            }
        }

        Ok(findings)
    }

    
    fn check_obfuscated_code(root: &Path, counter: &mut u32) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let obfuscation_re = Regex::new(
            r"(?i)(\\x[0-9a-f]{2}){10,}|(_0x[a-f0-9]{4,})|(\['\\x)"
        )?;

        for entry in WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            if !matches!(ext, "js" | "mjs" | "cjs") {
                continue;
            }

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            
            if obfuscation_re.is_match(&content) {
                *counter += 1;
                let relative = path.strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string();

                findings.push(Finding {
                    id: format!("KRYSTA-PKG-{:03}", counter),
                    title: format!("Obfuscated code: {}", relative),
                    severity: Severity::High,
                    category: Category::ToolPoisoning,
                    description: "File contains obfuscated JavaScript. Obfuscation is commonly \
                        used to hide malicious behavior in supply-chain attacks."
                        .to_string(),
                    evidence: format!("File: {}", relative),
                    remediation: "Deobfuscate and audit the file contents. Consider using a \
                        non-obfuscated alternative."
                        .to_string(),
                    source: FindingSource::Package,
                });
            }

            
            let line_count = content.lines().count();
            let total_len = content.len();
            if line_count <= 3 && total_len > 50_000 {
                *counter += 1;
                let relative = path.strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string();

                findings.push(Finding {
                    id: format!("KRYSTA-PKG-{:03}", counter),
                    title: format!("Heavily minified code: {}", relative),
                    severity: Severity::Medium,
                    category: Category::ToolPoisoning,
                    description: format!(
                        "File is {} bytes but only {} line(s). Extreme minification \
                         makes code review difficult and may hide malicious logic.",
                        total_len, line_count
                    ),
                    evidence: format!(
                        "File: {} ({} bytes, {} lines)",
                        relative, total_len, line_count
                    ),
                    remediation: "Prefer unminified source or vendor a readable copy for audit."
                        .to_string(),
                    source: FindingSource::Package,
                });
            }
        }

        Ok(findings)
    }
}