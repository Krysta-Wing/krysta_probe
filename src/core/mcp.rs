use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct McpServer {
    pub name: String,
    pub transport: TransportType,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub config_source: PathBuf,
}

#[derive(Debug, Clone)]
pub enum TransportType {
    Stdio,
    Sse,
    Http,
    Unknown,
}

#[derive(Debug, Deserialize)]
struct ClaudeConfig {
    #[serde(rename = "mcpServers")]
    mcp_servers: Option<std::collections::HashMap<String, ServerConfig>>,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(rename = "type")]
    server_type: Option<String>,
    url: Option<String>,
}

pub struct McpDiscovery {
    root_path: PathBuf,
}

impl McpDiscovery {
    pub fn new(path: &Path) -> Self {
        Self {
            root_path: path.to_path_buf(),
        }
    }

    pub async fn find_servers(&self) -> Result<Vec<McpServer>> {
        let mut servers = Vec::new();

        let config_files = vec![
            "claude_desktop_config.json",
            ".cursor/mcp.json",
            "mcp_settings.json",
            ".vscode/mcp.json",
        ];

        for entry in WalkDir::new(&self.root_path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_name = entry.file_name().to_string_lossy();
            
            if config_files.iter().any(|&cf| file_name.contains(cf)) {
                let path = entry.path();
                if let Ok(content) = tokio::fs::read_to_string(path).await {
                    if let Ok(config) = serde_json::from_str::<ClaudeConfig>(&content) {
                        if let Some(mcp_servers) = config.mcp_servers {
                            for (name, server_config) in mcp_servers {
                                let transport = if server_config.url.is_some() {
                                    TransportType::Sse
                                } else if server_config.command.is_some() {
                                    TransportType::Stdio
                                } else {
                                    TransportType::Unknown
                                };

                                servers.push(McpServer {
                                   name,
                                   transport,
                                   command: server_config.command,
                                   args: server_config.args,
                                   url: server_config.url,
                                   config_source: path.to_path_buf(),
                                });
                                
                            }
                        }
                    }
                }
            }
        }

        Ok(servers)
    }
}