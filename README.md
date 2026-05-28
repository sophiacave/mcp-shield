# mcp-shield

**Security scanner for MCP servers.** Detects SSRF, path traversal, injection, secrets, auth issues. Grades A-F.

36.7% of MCP servers are SSRF-vulnerable. 52% are dead. Only 17% are production-ready. This tool finds the vulnerabilities before attackers do.

## Quick Start

```bash
git clone https://github.com/sophiacave/mcp-shield
cd mcp-shield

# Scan a file
python3 src/cli.py scan path/to/mcp_server.py

# Scan a project
python3 src/cli.py scan path/to/mcp-project/
```

## What It Checks

| Rule | Severity | What It Detects |
|------|----------|----------------|
| SSRF-01 | Critical | User input in HTTP request URLs |
| SSRF-02 | Medium | Dynamic URLs without validation |
| PATH-01 | High | User input in file paths |
| PATH-02 | Medium | No path traversal protection |
| INJ-01 | Critical | eval/exec on user input |
| INJ-02 | Critical | SQL string interpolation |
| INJ-03 | High | subprocess with shell=True |
| AUTH-01 | Medium | No auth on tool handlers |
| AUTH-02 | Critical | Hardcoded secrets/API keys |
| SEC-01 | High | SSL verification disabled |
| SEC-02 | Medium | Wildcard CORS |

## MCP Server Integration

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "mcp-shield": {
      "command": "python3",
      "args": ["/path/to/mcp-shield/src/mcp_server.py"]
    }
  }
}
```

Claude Code tools: `shield_scan_file`, `shield_scan_directory`, `shield_scan_code`

## Example Output

```
MCP Shield: my-server/ — 3 finding(s)

  [CRIT] SSRF-01: Potential SSRF: Dynamic URL from user input
    requests call with dynamic URL that may include user input
    Location: server.py:45
    Fix: Validate URL against allowlist. Block internal IPs.
    CWE: CWE-918

  [HIGH] INJ-03: Command injection: subprocess with shell=True
    subprocess called with shell=True. User input in args = RCE.
    Location: tools.py:112
    Fix: Use subprocess with shell=False and pass args as list.
    CWE: CWE-78

  [MED] AUTH-01: No authentication detected on tool handlers
    MCP tool handlers found but no auth logic detected
    Fix: Add authentication middleware.
    CWE: CWE-306

Grade: F | 1 critical, 1 high, 1 medium
```

## Why This Exists

The MCP ecosystem is growing at 4,750% per year. Security tooling hasn't kept up. We built MCP Shield because every MCP server deployed without a security scan is a liability.

## License

MIT — [Like One](https://likeone.ai)
