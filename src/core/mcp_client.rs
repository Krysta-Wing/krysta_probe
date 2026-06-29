use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{timeout, Duration};
use std::process::Stdio;

/// Configuration for MCP client timeouts and behavior
#[derive(Debug, Clone)]
pub struct McpClientConfig {
    
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for McpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            request_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(3),
        }
    }
}

pub struct McpClient {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    config: McpClientConfig,
}

impl McpClient {
    pub async fn connect_stdio(
        command: &str,
        args: &[String],
    ) -> Result<Self> {
        Self::connect_stdio_with_config(command, args, McpClientConfig::default()).await
    }

    pub async fn connect_stdio_with_config(
        command: &str,
        args: &[String],
        config: McpClientConfig,
    ) -> Result<Self> {
        let executable = if cfg!(windows) {
            match command {
                "npx" => "npx.cmd",
                "npm" => "npm.cmd",
                "node" => "node.exe",
                "python" => "python.exe",
                "uvx" => "uvx.cmd",
                other => other,
            }
        } else {
            command
        };

        let spawn_result = timeout(config.connect_timeout, async {
            Command::new(executable)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
        })
        .await
        .map_err(|_| anyhow!(
            "Timeout after {:?} waiting for server process '{}' to spawn",
            config.connect_timeout,
            command
        ))?;

        let mut child = spawn_result?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("Failed to open stdin"))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to open stdout"))?;

        // Drain stderr in a background task to prevent deadlocks from full buffer
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    // Print stderr line for debugging/tracing
                    eprintln!("[Server Stderr] {}", line);
                }
            });
        }

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            next_id: 1,
            config,
        })
    }

    pub async fn send_request<P, R>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<R>
    where
       P: Serialize,
       R: for<'de> Deserialize<'de>,
    {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: self.next_id,
            method: method.to_string(),
            params,
        };

        self.next_id += 1;

        let json = serde_json::to_string(&request)?;
        let message = format!("{json}\n");

        let stdin = self.stdin.as_mut().ok_or_else(|| anyhow!("Stdin is closed"))?;
        stdin.write_all(message.as_bytes()).await?;
        stdin.flush().await?;

        let request_timeout = self.config.request_timeout;

        loop {
           let mut line = String::new();

           timeout(
              request_timeout,
              self.stdout.read_line(&mut line),
            )
            .await
            .map_err(|_| anyhow!(
                "Timeout after {:?} waiting for response to '{}'",
                request_timeout,
                request.method
            ))??;

            if line.trim().is_empty() {
               continue;
            }

            let value: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Skip notifications (messages without an id field)
            if value.get("id").is_none() {
                continue;
            }

            let response: JsonRpcResponse<R> = serde_json::from_value(value)?;

            if response.id != Some(request.id) {
                 continue;
            }

            if let Some(error) = response.error {
                return Err(anyhow!(
                    "MCP Error {}: {}",
                    error.code,
                    error.message
                ));
            }

            return response
               .result
               .ok_or_else(|| anyhow!("Missing JSON-RPC result"));
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        let params = InitializeParams {
            protocol_version: "2024-11-05",
            capabilities: serde_json::json!({}),
            client_info: ClientInfo {
                name: "krysta-probe".to_string(),
                version: "0.1.0".to_string(),
            },
        };
        let _: InitializeResult = self
             .send_request("initialize", params)
             .await?;
        Ok(())
    }

    pub async fn initialized(&mut self) -> Result<()> {
        let notification = serde_json::json!({
            "jsonrpc":"2.0",
            "method":"notifications/initialized"
        });
        let message = format!("{}\n", notification);
        let stdin = self.stdin.as_mut().ok_or_else(|| anyhow!("Stdin is closed"))?;
        stdin.write_all(message.as_bytes()).await?;
        stdin.flush().await?;
        Ok(())
    }

    pub async fn list_tools(&mut self) -> Result<Vec<Tool>> {
        let result: ToolListResult = self
             .send_request(
                 "tools/list",
                 EmptyParams {},
             )
             .await?;
        Ok(result.tools)
    }

    pub async fn call_tool(
       &mut self,
       tool: &str,
       arguments: serde_json::Value,
     ) -> Result<ToolCallResult> {
         self.send_request(
             "tools/call",
             ToolCallParams {
                name: tool.to_string(),
                arguments,
             },
         )
         .await
     }

    /// Gracefully shut down the MCP server process.
    
    
    pub async fn shutdown(&mut self) -> Result<()> {
        let close_notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "reason": "scanner shutting down" }
        });
        let msg = format!("{}\n", close_notification);
        if let Some(ref mut stdin) = self.stdin {
            let _ = stdin.write_all(msg.as_bytes()).await;
            let _ = stdin.flush().await;
        }

        
        self.stdin.take();

        
        let shutdown_timeout = self.config.shutdown_timeout;
        match timeout(shutdown_timeout, self.child.wait()).await {
            Ok(Ok(_status)) => {
                
            }
            Ok(Err(_e)) => {
                
                let _ = self.child.kill().await;
            }
            Err(_) => {
                
                let _ = self.child.kill().await;
            }
        }

        Ok(())
    }

    
    pub async fn force_kill(&mut self) {
        let _ = self.child.kill().await;
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[derive(Debug, Serialize)]
pub struct JsonRpcRequest<T> {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: T,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub result: Option<T>,
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: &'static str,
    pub capabilities: serde_json::Value,
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}
#[derive(Debug, Serialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct InitializeResult {
    #[serde(default)]
    pub capabilities: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct EmptyParams {}

#[derive(Debug, Deserialize)]
pub struct ToolListResult {
    pub tools: Vec<Tool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tool {
    pub name: String,

    #[serde(default)]
    pub description: String,

    #[serde(rename = "inputSchema")]
    pub input_schema: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ToolCallParams {
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ToolCallResult {
    #[serde(default)]
    pub content: serde_json::Value,

    #[serde(default, rename = "isError")]
    pub is_error: Option<bool>,
}