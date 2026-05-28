#!/usr/bin/env python3
"""mcp-shield CLI — Scan files and directories for MCP security issues."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scanner import scan_file, scan_directory, format_report


def main():
    if len(sys.argv) < 3:
        print("Usage: mcp-shield scan <path>")
        sys.exit(1)

    target = sys.argv[2]
    path = Path(target)

    if path.is_file():
        findings = scan_file(str(path))
    elif path.is_dir():
        findings = scan_directory(str(path))
    else:
        print(f"Not found: {target}")
        sys.exit(1)

    print(format_report(findings, target))


if __name__ == "__main__":
    main()
