# MCP Shield

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 26 passing](https://img.shields.io/badge/Tests-26%20passing-green.svg)](tests/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io)

**Open-source security scanner for MCP servers.** 20 rules across 6 categories. Scan any server in seconds. Get a grade from A to F.

> 36.7% of MCP servers are SSRF-vulnerable ([BlueRock, 2026](https://likeone.ai/blog/mcp-server-security-vulnerabilities-2026/)). 82% have path traversal flaws. Only 17% are production-ready. MCP Shield finds the vulnerabilities before attackers do.

## Quick Start

```bash
git clone https://github.com/sophiacave/mcp-shield
cd mcp-shield

# Scan a file
python3 src/cli.py scan path/to/mcp_server.py

# Scan a project
python3 src/cli.py scan path/to/mcp-project/
```

## What It Checks (20 Rules)

| Rule | Severity | What It Detects |
|------|----------|----------------|
| SSRF-01 | Critical | User input in HTTP request URLs |
| SSRF-02 | Medium | Dynamic URLs without validation |
| SSRF-03 | Medium | DNS rebinding (URL validated but no IP pinning) |
| PATH-01 | High | User input in file paths |
| PATH-02 | Medium | No path traversal protection |
| PATH-03 | Medium | Symlink following without check |
| INJ-01 | Critical | eval/exec on user input |
| INJ-02 | Critical | SQL string interpolation |
| INJ-03 | High | subprocess with shell=True |
| INJ-04 | High | Template injection via .format() |
| INJ-05 | Critical | Unsafe deserialization (pickle/yaml) |
| AUTH-01 | Medium | No auth on tool handlers |
| AUTH-02 | Critical | Hardcoded secrets/API keys (OpenAI, Stripe, GitHub, AWS) |
| AUTH-03 | Low | No rate limiting on tool endpoints |
| SEC-01 | High | SSL verification disabled |
| SEC-02 | Medium | Wildcard CORS |
| SEC-03 | Medium | Stack traces/error details exposed to client |
| SEC-04 | Low | No input length validation (DoS risk) |
| LOG-01 | Low | No logging/audit trail on tool invocations |

## Testing

```bash
python3 tests/test_integration.py
# 26 tests, 0 failures
```

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

## Features

- **Zero dependencies** — Pure Python, no pip installs required
- **20 security rules** across SSRF, path traversal, injection, auth, config, and logging
- **CWE references** — Every finding maps to a Common Weakness Enumeration ID
- **Actionable fixes** — Each finding includes specific remediation steps
- **A-F grading** — Instant security posture assessment
- **Dual mode** — Run as CLI or as an MCP server inside Claude Code
- **Fast** — Scans a typical MCP server in under 1 second

## Why This Exists

The MCP ecosystem has 9,400+ servers and 97M monthly SDK downloads. Security tooling hasn't kept up. We built MCP Shield because every MCP server deployed without a security scan is a liability.

Built by [Like One](https://likeone.ai), a 501(c)(3) nonprofit. Security tooling should be free.

## License

MIT — [Like One](https://likeone.ai)
