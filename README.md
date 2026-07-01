# Krysta Probe

Krysta Probe is a security scanner for AI agent infrastructure. It discovers, audits, and sandboxes Model Context Protocol (MCP) servers to protect AI agents and host environments from malicious commands, data exfiltration, command injections, and path traversals.

---

## Key Features

- **Automated Configuration Discovery**: Searches for standard MCP config files like `claude_desktop_config.json`, `.cursor/mcp.json`, `mcp_settings.json`, and `.vscode/mcp.json`.
- **Static Security Auditing**: Flags missing authentication, internet exposure, dangerous commands, and unsafe file system names from server configurations.
- **Dependency & Package Audits**: Scans `package.json` configurations to detect risky lifecycle script hooks (e.g. `preinstall`, `postinstall`), unpinned version ranges, and suspicious packages.
- **Source Code Analysis**: Inspects local or downloaded MCP server source files (JavaScript, TypeScript, Python) for shell executions (`exec`, `eval`), local file reads, user-controlled outbound requests (SSRF), and hardcoded credentials.
- **Deep Dynamic Scanning**: Spawns stdio or SSE-based MCP servers locally to list active tools, inspect parameters, and dynamically test endpoints using harmless vulnerability probes.
- **Mesh Policy Generation**: Automatically generates a `krysta-mesh-policy.yaml` configuration tailored to restrict or log access to flagged tools.
- **Dashboard Synchronization**: Uploads security scan findings directly to the Krysta Dashboard for visualization and monitoring.

---

## Architecture Overview

Krysta Probe coordinates multiple audit phases:

```
[Target Path]
      │
      ├──> McpDiscovery (Finds claude_desktop_config.json, mcp_settings.json, etc.)
      │
      └──> Scanner
             │
             ├──> Static Checks (Inspects command patterns, network bindings)
             │
             ├──> Package & Source Analysis
             │      │
             │      ├──> PackageAnalyzer (Inspects package.json scripts and dependencies)
             │      └──> SourceAnalyzer (Regex audit of JS/TS/PY files for path traversal & SSRF)
             │
             └──> Deep Scan (Dynamic auditing)
                    │
                    ├──> Spawns MCP client connection to the server
                    ├──> Resolves schemas via tools/list
                    └──> Executes active payload tests (SSRF, CmdInjection, PathTraversal)
```

---

## Vulnerabilities Catalog

The scanner cross-references files and dynamic tool schemas against a database of vulnerabilities:

| Vuln ID | Title | Severity | Category |
|---|---|---|---|
| **CVE-2026-MCP-001** | Command injection via tool description | Critical | CommandInjection |
| **CVE-2026-MCP-002** | Path traversal in file system tools | High | PathTraversal |
| **CVE-2026-MCP-003** | SSRF via fetch_url tool | High | SSRF |
| **CVE-2026-MCP-004** | Credential exposure in tool schema | Critical | CredentialExposure |
| **CVE-2026-MCP-005** | Exec/Shell injection via subprocess | Critical | CommandInjection |
| **CVE-2026-MCP-006** | Hardening bypass via npx -c flag | Critical | CommandInjection |
| **CVE-2026-MCP-007** | Tool description poisoning | High | ToolPoisoning |
| **CVE-2026-MCP-008** | Unpinned server configuration | Medium | ToolPoisoning |
| **CVE-2026-MCP-009** | Insecure SSE transport | High | NetworkExposure |
| **CVE-2026-MCP-010** | Missing auth on public SSE endpoint | High | SSRF |

---

## Installation & Building

Prerequisites:
- [Rust & Cargo](https://rustup.rs/) (edition 2021)
- [Node.js & npm](https://nodejs.org/) (required for npm package inspections)

```bash
cargo build --release
```

The compiled binary will be available at `./target/release/krysta-probe`.

---

## Command Line Interface (CLI)

### 1. `login`
Authenticate the CLI with the Krysta Dashboard to upload reports.

```bash
krysta-probe login --dashboard https://app.krystawing.com
```

### 2. `probe`
Run a security scan on the discovered MCP servers.

```bash
krysta-probe probe --path . --deep --format table --upload
```

#### Options:
- `-p, --path <PATH>`: The root directory to search for configuration and source files. (Default: `.`)
- `-d, --deep`: Run dynamic checks by connecting to stdio and SSE servers.
- `-f, --format <FORMAT>`: Report output format: `table`, `json`, or `sarif`. (Default: `table`)
- `--upload`: Sync report findings with the cloud dashboard.
- `--dashboard <URL>`: Override target dashboard URL. (Default: `https://app.krystawing.com`)

---

## Output Artifacts

Reports and security configurations are written to the `~/.krysta/` home subdirectory:

1. **Scan Report (`~/.krysta/krysta-report.json`)**  
   Contains complete structured JSON details of discovered servers, scanned packages, static code audit findings, and dynamic probe results.
   
2. **Krysta Mesh Policy (`~/.krysta/krysta-mesh-policy.yaml`)**  
   An access control policy mapped from the findings. Tools categorized with high or critical severity are blocked, and medium or low risks are marked for logging.
   
   Apply the generated configuration:
   ```bash
   krysta-mesh start -f ~/.krysta/krysta-mesh-policy.yaml
   ```

---

## Testing with the Mock Server

To test HTTP/SSE scanning and vulnerability detection without running live production servers, use the mock python server:

1. Start the mock server:
   ```bash
   python mock-server.py
   ```

2. Point the probe tool to a configuration specifying the mock server (e.g. `mcp_settings.json`):
   ```bash
   krysta probe --path . --deep
   ```
