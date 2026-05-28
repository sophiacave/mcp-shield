#!/bin/bash
# mcp-shield — Security scanner for MCP servers
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")/../src" && pwd)"
case "${1:-help}" in
  scan)
    shift
    python3 "$SCRIPT_DIR/cli.py" scan "$@"
    ;;
  serve)
    python3 "$SCRIPT_DIR/mcp_server.py"
    ;;
  help|--help|-h)
    cat <<'HELP'
mcp-shield — Security scanner for MCP servers

Commands:
  scan <path>       Scan a file or directory for vulnerabilities
  scan --url <url>  Scan a GitHub repo
  serve             Start MCP server for Claude Code integration

Checks: SSRF, path traversal, code injection, SQL injection,
        command injection, missing auth, hardcoded secrets, SSL issues

Built with love by Like One (likeone.ai)
HELP
    ;;
  *)
    echo "Unknown command: $1. Run 'mcp-shield help' for usage."
    exit 1
    ;;
esac
