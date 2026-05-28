#!/usr/bin/env python3
"""
mcp-shield scanner — Detect security vulnerabilities in MCP server code.

Checks for:
  SSRF-01: Unvalidated URL/hostname in HTTP requests
  SSRF-02: User input passed directly to requests/fetch/urllib
  SSRF-03: DNS rebinding via hostname resolution without pinning
  PATH-01: Path traversal via unsanitized file paths
  PATH-02: User input in os.path.join / Path() without validation
  PATH-03: Symlink following without check
  INJ-01:  Code injection via eval/exec on user input
  INJ-02:  SQL injection via string interpolation in queries
  INJ-03:  Command injection via subprocess with shell=True
  INJ-04:  Template injection via format strings with user input
  INJ-05:  YAML/pickle deserialization of untrusted data
  AUTH-01: Missing authentication check on tool handlers
  AUTH-02: Hardcoded secrets/API keys
  AUTH-03: No rate limiting on tool endpoints
  SEC-01:  Disabled SSL verification (verify=False)
  SEC-02:  Overly permissive CORS
  SEC-03:  Sensitive data in error messages / stack traces
  SEC-04:  Missing input length validation (DoS risk)
  LOG-01:  No logging/audit trail on tool invocations
"""

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    rule_id: str
    severity: str  # critical, high, medium, low, info
    title: str
    message: str
    file: str = ""
    line: int = 0
    suggestion: str = ""
    cwe: str = ""


def scan_file(filepath: str) -> list[Finding]:
    """Scan a single file for MCP security issues."""
    path = Path(filepath)
    if not path.exists():
        return [Finding("ERR", "info", "File not found", f"{filepath} does not exist")]

    code = path.read_text(errors="ignore")
    lines = code.split("\n")
    findings = []

    findings.extend(_check_ssrf(code, lines, str(path)))
    findings.extend(_check_path_traversal(code, lines, str(path)))
    findings.extend(_check_injection(code, lines, str(path)))
    findings.extend(_check_auth(code, lines, str(path)))
    findings.extend(_check_secrets(code, lines, str(path)))
    findings.extend(_check_ssl(code, lines, str(path)))
    findings.extend(_check_deserialization(code, lines, str(path)))
    findings.extend(_check_logging(code, lines, str(path)))
    findings.extend(_check_input_validation(code, lines, str(path)))

    return findings


def scan_directory(dirpath: str) -> list[Finding]:
    """Scan all Python/TypeScript/JavaScript files in a directory."""
    path = Path(dirpath)
    if not path.exists():
        return [Finding("ERR", "info", "Directory not found", f"{dirpath} does not exist")]

    extensions = {".py", ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"}
    findings = []

    for fp in sorted(path.rglob("*")):
        if fp.suffix in extensions and "node_modules" not in str(fp) and "__pycache__" not in str(fp):
            findings.extend(scan_file(str(fp)))

    return findings


def _check_ssrf(code: str, lines: list[str], filepath: str) -> list[Finding]:
    findings = []

    # SSRF-01: requests/fetch/urllib with dynamic URLs
    ssrf_patterns = [
        (r'requests\.(get|post|put|delete|patch|head)\s*\(\s*[^"\'`]', "requests"),
        (r'urllib\.request\.urlopen\s*\(\s*[^"\'`]', "urllib"),
        (r'httpx\.(get|post|put|delete)\s*\(\s*[^"\'`]', "httpx"),
        (r'fetch\s*\(\s*[^"\'`]', "fetch"),
        (r'axios\.(get|post|put|delete)\s*\(\s*[^"\'`]', "axios"),
        (r'http\.request\s*\(\s*[^"\'`]', "http.request"),
    ]

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for pattern, lib in ssrf_patterns:
            if re.search(pattern, line):
                # Check if URL comes from params/arguments/input
                context = "\n".join(lines[max(0, i-5):min(len(lines), i+3)])
                if any(kw in context.lower() for kw in ["arguments", "params", "input", "args", "request", "body"]):
                    findings.append(Finding(
                        rule_id="SSRF-01",
                        severity="critical",
                        title="Potential SSRF: Dynamic URL from user input",
                        message=f"{lib} call with dynamic URL that may include user input",
                        file=filepath, line=i,
                        suggestion="Validate URL against an allowlist of permitted hosts/schemes. Block internal IPs (127.0.0.1, 169.254.x.x, 10.x.x.x).",
                        cwe="CWE-918"
                    ))
                else:
                    findings.append(Finding(
                        rule_id="SSRF-02",
                        severity="medium",
                        title="Dynamic URL in HTTP request",
                        message=f"{lib} call with variable URL. Verify source is trusted.",
                        file=filepath, line=i,
                        suggestion="Ensure URL source is not user-controllable. Add URL validation if it is.",
                        cwe="CWE-918"
                    ))
                break

    return findings


def _check_path_traversal(code: str, lines: list[str], filepath: str) -> list[Finding]:
    findings = []

    path_patterns = [
        (r'os\.path\.join\s*\([^)]*(?:arguments|params|input|args)', "os.path.join"),
        (r'Path\s*\([^)]*(?:arguments|params|input|args)', "pathlib.Path"),
        (r'open\s*\(\s*[^"\'`]', "open()"),
        (r'fs\.readFile(?:Sync)?\s*\(\s*[^"\'`]', "fs.readFile"),
        (r'fs\.writeFile(?:Sync)?\s*\(\s*[^"\'`]', "fs.writeFile"),
    ]

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for pattern, func in path_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                context = "\n".join(lines[max(0, i-5):min(len(lines), i+3)])
                if any(kw in context.lower() for kw in ["arguments", "params", "input", "args", "request"]):
                    findings.append(Finding(
                        rule_id="PATH-01",
                        severity="high",
                        title="Path traversal: User input in file path",
                        message=f"{func} with user-controllable path component",
                        file=filepath, line=i,
                        suggestion="Use os.path.realpath() and verify the resolved path starts with expected base directory. Reject paths containing '..'.",
                        cwe="CWE-22"
                    ))
                    break

    # PATH-02: No .. check near file operations
    if ("open(" in code or "readFile" in code) and '".."' not in code and "'..' " not in code:
        if "os.path.realpath" not in code and "path.resolve" not in code and "realpath" not in code:
            findings.append(Finding(
                rule_id="PATH-02",
                severity="medium",
                title="No path traversal protection detected",
                message="File operations found but no realpath/resolve validation or '..' rejection",
                file=filepath,
                suggestion="Add os.path.realpath() validation on all file paths from external input.",
                cwe="CWE-22"
            ))

    return findings


def _check_injection(code: str, lines: list[str], filepath: str) -> list[Finding]:
    findings = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # INJ-01: eval/exec
        if re.search(r'\beval\s*\(', line) or re.search(r'\bexec\s*\(', line):
            if not re.search(r'#.*\beval\b|#.*\bexec\b', line):  # skip comments
                findings.append(Finding(
                    rule_id="INJ-01",
                    severity="critical",
                    title="Code injection: eval/exec usage",
                    message="eval() or exec() found. If input is user-controllable, this is RCE.",
                    file=filepath, line=i,
                    suggestion="Remove eval/exec entirely. Use json.loads() for data parsing, ast.literal_eval() for Python literals only.",
                    cwe="CWE-94"
                ))

        # INJ-02: SQL string interpolation
        if re.search(r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)', line, re.IGNORECASE):
            findings.append(Finding(
                rule_id="INJ-02",
                severity="critical",
                title="SQL injection: String interpolation in query",
                message="SQL query built with f-string interpolation",
                file=filepath, line=i,
                suggestion="Use parameterized queries with ? placeholders. Never interpolate user input into SQL.",
                cwe="CWE-89"
            ))

        # INJ-03: subprocess with shell=True
        if re.search(r'subprocess\.\w+\(.*shell\s*=\s*True', line):
            findings.append(Finding(
                rule_id="INJ-03",
                severity="high",
                title="Command injection: subprocess with shell=True",
                message="subprocess called with shell=True. User input in args = RCE.",
                file=filepath, line=i,
                suggestion="Use subprocess with shell=False (default) and pass args as a list.",
                cwe="CWE-78"
            ))

    return findings


def _check_auth(code: str, lines: list[str], filepath: str) -> list[Finding]:
    findings = []

    # AUTH-01: Tool handlers without auth checks
    has_tools = "tools/call" in code or "tool_call" in code or "CallToolResult" in code
    has_auth = any(kw in code for kw in ["authenticate", "authorization", "auth_token", "api_key", "Bearer", "verify_token"])

    if has_tools and not has_auth:
        findings.append(Finding(
            rule_id="AUTH-01",
            severity="medium",
            title="No authentication detected on tool handlers",
            message="MCP tool handlers found but no authentication/authorization logic detected",
            file=filepath,
            suggestion="Add authentication middleware. Verify caller identity before executing tool actions.",
            cwe="CWE-306"
        ))

    return findings


def _check_secrets(code: str, lines: list[str], filepath: str) -> list[Finding]:
    findings = []

    secret_patterns = [
        (r'(?:api_?key|secret|password|token)\s*=\s*["\'][A-Za-z0-9+/=_-]{16,}["\']', "Hardcoded secret"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
        (r'sk_live_[a-zA-Z0-9]{20,}', "Stripe live key"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
        (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, desc in secret_patterns:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id="AUTH-02",
                    severity="critical",
                    title=f"Hardcoded secret: {desc}",
                    message=f"Potential {desc} found in source code",
                    file=filepath, line=i,
                    suggestion="Move secrets to environment variables or a secret manager. Never commit secrets to source.",
                    cwe="CWE-798"
                ))
                break

    return findings


def _check_ssl(code: str, lines: list[str], filepath: str) -> list[Finding]:
    findings = []

    for i, line in enumerate(lines, 1):
        if "verify=False" in line or "verify = False" in line:
            findings.append(Finding(
                rule_id="SEC-01",
                severity="high",
                title="SSL verification disabled",
                message="HTTP request with verify=False disables certificate validation",
                file=filepath, line=i,
                suggestion="Remove verify=False. Fix the underlying certificate issue instead.",
                cwe="CWE-295"
            ))

        if re.search(r'Access-Control-Allow-Origin.*\*', line):
            findings.append(Finding(
                rule_id="SEC-02",
                severity="medium",
                title="Overly permissive CORS",
                message="Access-Control-Allow-Origin set to wildcard (*)",
                file=filepath, line=i,
                suggestion="Restrict CORS to specific trusted origins.",
                cwe="CWE-942"
            ))

    return findings


def _check_deserialization(code: str, lines: list[str], filepath: str) -> list[Finding]:
    """Check for unsafe deserialization of untrusted data."""
    findings = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # INJ-04: Template injection via .format() or % with user input
        if re.search(r'\.format\s*\(.*(?:arguments|params|input|args)', line, re.IGNORECASE):
            findings.append(Finding(
                rule_id="INJ-04",
                severity="high",
                title="Template injection: .format() with user input",
                message="String .format() with user-controllable input can leak internal state",
                file=filepath, line=i,
                suggestion="Use f-strings for trusted data only. For user input, use explicit escaping or template engines with sandboxing.",
                cwe="CWE-1336"
            ))

        # INJ-05: Unsafe deserialization
        if re.search(r'pickle\.loads?\s*\(', line):
            findings.append(Finding(
                rule_id="INJ-05",
                severity="critical",
                title="Unsafe deserialization: pickle",
                message="pickle.load() on untrusted data allows arbitrary code execution",
                file=filepath, line=i,
                suggestion="Never unpickle untrusted data. Use json.loads() for data exchange.",
                cwe="CWE-502"
            ))

        if re.search(r'yaml\.(?:load|unsafe_load)\s*\(', line) and "Loader" not in line and "safe" not in line.lower():
            findings.append(Finding(
                rule_id="INJ-05",
                severity="high",
                title="Unsafe deserialization: yaml.load without SafeLoader",
                message="yaml.load() without SafeLoader allows arbitrary code execution",
                file=filepath, line=i,
                suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                cwe="CWE-502"
            ))

    # SSRF-03: DNS rebinding (check if URL validation exists but hostname pinning doesn't)
    has_url_validation = "urlparse" in code or "URL" in code
    has_ip_check = "127.0.0.1" in code or "169.254" in code or "inet_aton" in code or "ipaddress" in code
    if has_url_validation and not has_ip_check and ("requests" in code or "fetch" in code):
        findings.append(Finding(
            rule_id="SSRF-03",
            severity="medium",
            title="Potential DNS rebinding: URL validated but no IP pinning",
            message="URL scheme/host may be validated but resolved IP not checked against internal ranges",
            file=filepath,
            suggestion="After resolving hostname, verify the IP is not in private ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).",
            cwe="CWE-350"
        ))

    return findings


def _check_logging(code: str, lines: list[str], filepath: str) -> list[Finding]:
    """Check for logging and audit trail issues."""
    findings = []

    has_tools = "tools/call" in code or "tool_call" in code or "CallToolResult" in code
    has_logging = any(kw in code for kw in ["logging.", "logger.", "console.log", "print(f\"[", "audit"])

    if has_tools and not has_logging:
        findings.append(Finding(
            rule_id="LOG-01",
            severity="low",
            title="No logging/audit trail on tool invocations",
            message="MCP tool handlers have no logging. Tool calls should be auditable.",
            file=filepath,
            suggestion="Add logging for each tool invocation: tool name, arguments (sanitized), caller, timestamp, result status.",
            cwe="CWE-778"
        ))

    # SEC-03: Sensitive data in error messages
    for i, line in enumerate(lines, 1):
        if re.search(r'except.*:\s*$', line):
            # Check next few lines for full traceback exposure
            context = "\n".join(lines[i:min(len(lines), i+5)])
            if "traceback" in context.lower() or "str(e)" in context or "repr(e)" in context:
                if "return" in context or "response" in context or "content" in context:
                    findings.append(Finding(
                        rule_id="SEC-03",
                        severity="medium",
                        title="Stack trace/error details exposed to client",
                        message="Exception details may be returned to the MCP client, leaking internal paths and state",
                        file=filepath, line=i,
                        suggestion="Return generic error messages to clients. Log full details server-side only.",
                        cwe="CWE-209"
                    ))
                    break

    return findings


def _check_input_validation(code: str, lines: list[str], filepath: str) -> list[Finding]:
    """Check for input validation issues."""
    findings = []

    has_tools = "tools/call" in code or "tool_call" in code
    has_length_check = any(kw in code for kw in ["len(", "maxlength", "max_length", "[:1", "truncate", "limit"])

    # SEC-04: No input length validation
    if has_tools and not has_length_check:
        findings.append(Finding(
            rule_id="SEC-04",
            severity="low",
            title="No input length validation detected",
            message="Tool arguments have no apparent length/size limits. Large inputs could cause DoS.",
            file=filepath,
            suggestion="Validate and truncate input arguments. Set reasonable maximum lengths for strings and array sizes.",
            cwe="CWE-770"
        ))

    # AUTH-03: No rate limiting
    has_rate_limit = any(kw in code for kw in ["rate_limit", "ratelimit", "throttle", "semaphore", "RateLimiter", "slowapi"])
    if has_tools and not has_rate_limit:
        findings.append(Finding(
            rule_id="AUTH-03",
            severity="low",
            title="No rate limiting on tool endpoints",
            message="Tool handlers have no rate limiting. Rapid invocation could exhaust resources.",
            file=filepath,
            suggestion="Add rate limiting per client/session. Consider token bucket or sliding window algorithms.",
            cwe="CWE-770"
        ))

    # PATH-03: Symlink following
    if ("open(" in code or "readFile" in code) and "os.path.realpath" not in code:
        if "os.path.islink" not in code and "lstat" not in code:
            has_file_ops = re.search(r'open\s*\(|readFile|writeFile', code)
            if has_file_ops:
                context_around = code[max(0, has_file_ops.start()-200):has_file_ops.end()+200]
                if any(kw in context_around.lower() for kw in ["arguments", "params", "input", "args"]):
                    findings.append(Finding(
                        rule_id="PATH-03",
                        severity="medium",
                        title="Symlink following without check",
                        message="File operations on user-provided paths without symlink detection",
                        file=filepath,
                        suggestion="Use os.path.realpath() to resolve symlinks, then verify the resolved path is within the allowed directory.",
                        cwe="CWE-59"
                    ))

    return findings


def format_report(findings: list[Finding], target: str = "") -> str:
    if not findings:
        return f"MCP Shield: {target or 'scan'} — No vulnerabilities found. All clear!"

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    icons = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
    lines = [f"MCP Shield: {target or 'scan'} — {len(findings)} finding(s)\n"]

    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in ["critical", "high", "medium", "low", "info"]:
        for f in by_sev.get(sev, []):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"  [{icons[sev]}] {f.rule_id}: {f.title}")
            lines.append(f"    {f.message}")
            if loc:
                lines.append(f"    Location: {loc}")
            if f.suggestion:
                lines.append(f"    Fix: {f.suggestion}")
            if f.cwe:
                lines.append(f"    CWE: {f.cwe}")
            lines.append("")

    crits = len(by_sev.get("critical", []))
    highs = len(by_sev.get("high", []))
    meds = len(by_sev.get("medium", []))
    grade = "F" if crits > 0 else "D" if highs > 0 else "C" if meds > 2 else "B" if meds > 0 else "A"

    lines.append(f"Grade: {grade} | {crits} critical, {highs} high, {meds} medium")
    return "\n".join(lines)
