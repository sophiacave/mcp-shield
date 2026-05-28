#!/usr/bin/env python3
"""mcp-shield MCP server — Security scanning tools for Claude Code."""
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scanner import scan_file, scan_directory, format_report


def handle_request(request):
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-shield", "version": "0.1.0"}
        }

    if method == "tools/list":
        return {"tools": [
            {
                "name": "shield_scan_file",
                "description": "Scan a source file for MCP security vulnerabilities (SSRF, path traversal, injection, secrets, auth).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the file to scan"}
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "shield_scan_directory",
                "description": "Scan an entire directory/project for MCP security vulnerabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "directory": {"type": "string", "description": "Path to directory to scan"}
                    },
                    "required": ["directory"]
                }
            },
            {
                "name": "shield_scan_code",
                "description": "Scan a code snippet for MCP security vulnerabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Code to scan"},
                        "language": {"type": "string", "description": "Language: python, typescript, javascript", "default": "python"}
                    },
                    "required": ["code"]
                }
            },
        ]}

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        if tool_name == "shield_scan_file":
            findings = scan_file(args["file_path"])
            result = format_report(findings, args["file_path"])
        elif tool_name == "shield_scan_directory":
            findings = scan_directory(args["directory"])
            result = format_report(findings, args["directory"])
        elif tool_name == "shield_scan_code":
            # Write code to temp file for scanning
            import tempfile
            ext = {"python": ".py", "typescript": ".ts", "javascript": ".js"}.get(args.get("language", "python"), ".py")
            with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
                f.write(args["code"])
                tmp_path = f.name
            findings = scan_file(tmp_path)
            Path(tmp_path).unlink()
            result = format_report(findings, "snippet")
        else:
            result = f"Unknown tool: {tool_name}"

        return {"content": [{"type": "text", "text": result}]}

    return {"error": f"Unknown method: {method}"}


def main():
    input_stream = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
    for line in input_stream:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            result = handle_request(request)
            response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32603, "message": str(e)}
            }) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
