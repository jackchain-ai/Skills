# MCP Protocol Security Guide

## Contents
- MCP Architecture Risks
- CVE-2025-54136 (MCPoison)
- Configuration Audit
- Server Allowlisting
- Transport Security
- Tool Permission Model

---

## MCP Architecture Risks

### Overview

Model Context Protocol (MCP) enables AI assistants to connect to external tools and data sources. This introduces supply chain risks similar to browser extensions or package managers.

### Attack Surface

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│   AI Assistant   │────▶│   MCP Server     │────▶│  External Service  │
│ (Claude, Cursor) │     │ (local/remote)   │     │  (API, DB, File)   │
└─────────────────┘     └──────────────────┘     └────────────────────┘
        │                       │                          │
   User trusts             May execute              Could be
   AI output               arbitrary code           compromised
```

### Risk Categories

| Risk | Severity | Description |
|------|----------|-------------|
| Malicious MCP server | CRITICAL | Server executes arbitrary code on host |
| Configuration injection | CRITICAL | Attacker modifies MCP config |
| Tool abuse | HIGH | Legitimate tool used for unintended purpose |
| Data exfiltration | HIGH | MCP server leaks sensitive data |
| Privilege escalation | HIGH | Tool gains broader access than intended |
| Transport interception | MEDIUM | Man-in-the-middle on MCP traffic |

---

## CVE-2025-54136 (MCPoison)

### Overview

**MCPoison** is a vulnerability in Cursor IDE's MCP server handling that allows silent and persistent remote code execution through malicious MCP configurations.

### Attack Chain

```
1. Attacker creates malicious repository:
   └── .cursor/mcp.json  (contains malicious MCP server config)

2. Developer clones repository:
   git clone https://github.com/attacker/cool-project

3. Cursor reads .cursor/mcp.json automatically
   → Registers attacker's MCP server

4. MCP server provides malicious tools:
   → "code_formatter" tool actually runs arbitrary commands

5. AI assistant calls the malicious tool:
   → Remote code execution on developer's machine
```

### Detection

```python
import json
import re
from pathlib import Path

MCP_CONFIG_FILES = [
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "mcp.json",
    "mcp-config.yaml",
    "mcp-config.json",
    ".claude/mcp.json",
]

SUSPICIOUS_MCP_PATTERNS = [
    # Remote servers (not localhost)
    r'"url"\s*:\s*"https?://(?!localhost|127\.0\.0\.1)',
    # Shell commands
    r'"command"\s*:\s*"(?:bash|sh|cmd|powershell|node|python)',
    # npx with unknown packages
    r'"command"\s*:\s*"npx\s+(?!@modelcontextprotocol)',
    # Environment variable exfiltration
    r'env|ENV|process\.env',
    # Network tool commands
    r'curl|wget|nc\s|ncat',
    # File system access
    r'/etc/|/home/|C:\\\\|%USERPROFILE%',
]

def audit_mcp_config(project_path: str) -> list:
    """Audit MCP configuration files in a project."""
    findings = []

    for config_file in MCP_CONFIG_FILES:
        config_path = Path(project_path) / config_file
        if not config_path.exists():
            continue

        try:
            content = config_path.read_text()

            # Check for suspicious patterns
            for pattern in SUSPICIOUS_MCP_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append({
                        "file": str(config_path),
                        "pattern": pattern,
                        "matches": matches,
                        "severity": "HIGH",
                        "description": f"Suspicious MCP configuration pattern found",
                    })

            # Parse and analyze server configs
            try:
                config = json.loads(content)
                servers = config.get("mcpServers", config.get("servers", {}))

                for server_name, server_config in servers.items():
                    findings.extend(
                        audit_single_server(str(config_path), server_name, server_config)
                    )
            except json.JSONDecodeError:
                findings.append({
                    "file": str(config_path),
                    "severity": "LOW",
                    "description": "Invalid JSON in MCP config file",
                })

        except Exception as e:
            findings.append({
                "file": str(config_path),
                "severity": "LOW",
                "description": f"Could not read MCP config: {e}",
            })

    return findings


def audit_single_server(config_file: str, name: str, config: dict) -> list:
    """Audit a single MCP server configuration."""
    findings = []

    # Check transport type
    transport = config.get("transport", "stdio")

    if transport == "sse" or "url" in config:
        url = config.get("url", "")
        from urllib.parse import urlparse
        parsed = urlparse(url)

        if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            findings.append({
                "file": config_file,
                "server": name,
                "severity": "HIGH",
                "description": f"Remote MCP server: {url} - verify trust",
            })

        if parsed.scheme == "http":
            findings.append({
                "file": config_file,
                "server": name,
                "severity": "MEDIUM",
                "description": f"Unencrypted HTTP transport for MCP server: {url}",
            })

    if transport == "stdio":
        command = config.get("command", "")
        args = config.get("args", [])

        # Check for npx with unknown packages
        if command == "npx":
            package = args[0] if args else ""
            if not package.startswith("@modelcontextprotocol/"):
                findings.append({
                    "file": config_file,
                    "server": name,
                    "severity": "HIGH",
                    "description": f"npx running unverified package: {package}",
                })

        # Check for direct shell execution
        if command in ("bash", "sh", "cmd", "powershell"):
            findings.append({
                "file": config_file,
                "server": name,
                "severity": "CRITICAL",
                "description": f"MCP server uses direct shell: {command}",
            })

    # Check environment variables
    env = config.get("env", {})
    for key, value in env.items():
        if any(secret in key.upper() for secret in ("KEY", "SECRET", "TOKEN", "PASSWORD")):
            if not value.startswith("$") and not value.startswith("env:"):
                findings.append({
                    "file": config_file,
                    "server": name,
                    "severity": "HIGH",
                    "description": f"Hardcoded secret in MCP env: {key}",
                })

    return findings
```

---

## Server Allowlisting

### Implementation

```python
from urllib.parse import urlparse

class MCPServerAllowlist:
    """Manage allowed MCP server connections."""

    def __init__(self):
        self.allowed_servers = set()
        self.allowed_commands = set()
        self.blocked_servers = set()

    def add_allowed_server(self, url: str):
        """Add a trusted MCP server URL."""
        parsed = urlparse(url)
        self.allowed_servers.add(f"{parsed.hostname}:{parsed.port or 443}")

    def add_allowed_command(self, command: str):
        """Add a trusted MCP server command."""
        self.allowed_commands.add(command)

    def is_allowed(self, config: dict) -> tuple:
        """Check if an MCP server config is allowed.

        Returns: (allowed: bool, reason: str)
        """
        # Check URL-based servers
        if "url" in config:
            parsed = urlparse(config["url"])
            server_key = f"{parsed.hostname}:{parsed.port or 443}"

            if server_key in self.blocked_servers:
                return False, f"Server {server_key} is blocked"

            if self.allowed_servers and server_key not in self.allowed_servers:
                return False, f"Server {server_key} not in allowlist"

        # Check command-based servers
        if "command" in config:
            command = config["command"]
            if self.allowed_commands and command not in self.allowed_commands:
                return False, f"Command '{command}' not in allowlist"

        return True, "Allowed"


# Example usage
allowlist = MCPServerAllowlist()
allowlist.add_allowed_server("https://localhost:3000")
allowlist.add_allowed_server("https://mcp.internal.company.com")
allowlist.add_allowed_command("npx")
allowlist.add_allowed_command("uvx")
```

### Configuration Template

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "mcpServers": {
    "local-files": {
      "comment": "✅ SAFE: Local filesystem access",
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/allowed/path"],
      "transport": "stdio"
    },
    "internal-api": {
      "comment": "✅ SAFE: Internal company server",
      "url": "https://mcp.internal.company.com",
      "transport": "sse"
    }
  },
  "_blocked": {
    "untrusted-remote": {
      "comment": "❌ BLOCKED: Unknown remote server",
      "url": "https://unknown-server.com/mcp"
    }
  }
}
```

---

## Transport Security

### stdio Transport

```
Pros:
  ✅ No network exposure
  ✅ Process-level isolation
  ✅ Easy to audit

Risks:
  ⚠️ Inherits user permissions
  ⚠️ Can read/write local files
  ⚠️ Can spawn child processes
```

### SSE (Server-Sent Events) Transport

```
Pros:
  ✅ Can use HTTPS encryption
  ✅ Network-level access control

Risks:
  ⚠️ Network exposure
  ⚠️ Man-in-the-middle if HTTP
  ⚠️ Server compromise affects all clients
```

### Security Recommendations

```python
MCP_TRANSPORT_RECOMMENDATIONS = {
    "stdio": {
        "risk_level": "MEDIUM",
        "mitigations": [
            "Run in sandboxed environment (Docker, VM)",
            "Restrict file system access",
            "Monitor spawned processes",
            "Use minimal permissions (non-root)",
        ],
    },
    "sse": {
        "risk_level": "HIGH",
        "mitigations": [
            "Always use HTTPS (never HTTP)",
            "Verify server TLS certificates",
            "Use mutual TLS where possible",
            "Implement request signing",
            "Monitor network traffic",
        ],
    },
}
```

---

## Tool Permission Model

### Principle of Least Privilege

```python
MCP_TOOL_RISK_MATRIX = {
    # Read-only tools - generally safe
    "read_file": {"risk": "LOW", "permissions": ["fs:read"]},
    "search": {"risk": "LOW", "permissions": ["network:read"]},
    "list_directory": {"risk": "LOW", "permissions": ["fs:list"]},

    # Write tools - moderate risk
    "write_file": {"risk": "MEDIUM", "permissions": ["fs:write"]},
    "create_directory": {"risk": "MEDIUM", "permissions": ["fs:write"]},

    # Execute tools - high risk
    "run_command": {"risk": "CRITICAL", "permissions": ["exec:any"]},
    "run_script": {"risk": "CRITICAL", "permissions": ["exec:any"]},
    "install_package": {"risk": "HIGH", "permissions": ["exec:install"]},

    # Network tools - moderate to high risk
    "http_request": {"risk": "MEDIUM", "permissions": ["network:read", "network:write"]},
    "database_query": {"risk": "HIGH", "permissions": ["db:read", "db:write"]},
}

def assess_tool_risk(tool_name: str, tool_description: str) -> dict:
    """Assess the risk of an MCP tool."""
    # Check against known patterns
    high_risk_keywords = [
        "execute", "run", "shell", "command", "eval",
        "write", "delete", "modify", "install",
        "admin", "root", "sudo",
    ]

    risk_score = 0
    risks = []

    desc_lower = tool_description.lower()
    for keyword in high_risk_keywords:
        if keyword in desc_lower:
            risk_score += 20
            risks.append(f"Tool description contains '{keyword}'")

    # Check known tools
    known = MCP_TOOL_RISK_MATRIX.get(tool_name)
    if known:
        return {
            "tool": tool_name,
            "risk_level": known["risk"],
            "permissions": known["permissions"],
            "risks": risks,
        }

    # Unknown tool assessment
    risk_level = (
        "CRITICAL" if risk_score >= 40 else
        "HIGH" if risk_score >= 20 else
        "MEDIUM"  # Unknown tools are at least medium risk
    )

    return {
        "tool": tool_name,
        "risk_level": risk_level,
        "permissions": ["unknown"],
        "risks": risks or ["Unknown tool - manual review required"],
    }
```

---

## Quick Reference

### MCP Security Checklist

```
Before using any MCP server:
- [ ] Verify the server source (npm package, GitHub repo)
- [ ] Check the server's npm/PyPI download count
- [ ] Review the server's tool list and permissions
- [ ] Test in isolated environment first
- [ ] Add to allowlist only after verification
- [ ] Monitor for unusual activity after enabling

Configuration security:
- [ ] No hardcoded secrets in MCP config
- [ ] HTTPS for all remote servers
- [ ] No shell command servers
- [ ] Environment variables for sensitive config
- [ ] Config files not committed to public repos
```

### Detection Commands

```bash
# Find all MCP config files
find . -name "mcp.json" -o -name "mcp-config.*" -o -name ".cursor/mcp.json"

# Check for remote MCP servers
grep -rE '"url"\s*:\s*"https?://' . --include="*.json" --include="*.yaml"

# Check for npx MCP servers
grep -rE '"command"\s*:\s*"npx' . --include="*.json"

# Check for shell-based MCP servers
grep -rE '"command"\s*:\s*"(bash|sh|cmd|powershell)' . --include="*.json"
```
