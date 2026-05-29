#!/usr/bin/env python3
"""Integration tests for mcp-shield MCP server."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from scanner import scan_file, scan_directory, format_report, Finding
from mcp_server import handle_request

PASS = 0
FAIL = 0


def check(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


def _scan_code(code: str, ext=".py") -> list:
    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
        f.write(code)
        tmp = f.name
    findings = scan_file(tmp)
    Path(tmp).unlink()
    return findings


def test_ssrf_detection():
    """SSRF rules fire correctly."""
    print("\n--- SSRF Detection ---")

    code = '''
def fetch_data(arguments):
    url = arguments["url"]
    resp = requests.get(url)
    return resp.text
'''
    findings = _scan_code(code)
    ssrf = [f for f in findings if f.rule_id.startswith("SSRF")]
    check("SSRF-01 fires on requests.get with user URL", any(f.rule_id == "SSRF-01" for f in ssrf))

    # Static URL with literal string — no dynamic URL pattern
    code = 'resp = requests.get("https://api.example.com/data")\n'
    findings = _scan_code(code)
    ssrf = [f for f in findings if f.rule_id.startswith("SSRF")]
    check("No SSRF on fully literal URL", len(ssrf) == 0)

    # Validation-aware: SSRF-01 downgrades to SSRF-02 when urlparse/allowlist exists
    code = '''
from urllib.parse import urlparse
ALLOWED_HOSTS = {"localhost", "127.0.0.1"}

def validate_local_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("bad host")

def fetch_data(arguments):
    url = config["api_url"]
    resp = requests.get(url)
    return resp.text
'''
    findings = _scan_code(code)
    ssrf = [f for f in findings if f.rule_id.startswith("SSRF")]
    check("SSRF downgraded to SSRF-02 when validation exists", all(f.rule_id == "SSRF-02" for f in ssrf) and len(ssrf) > 0)

    # No validation: SSRF-01 stays critical
    code = '''
def fetch_data(arguments):
    url = arguments["url"]
    resp = requests.post(url, json={"data": "test"})
    return resp.text
'''
    findings = _scan_code(code)
    ssrf01 = [f for f in findings if f.rule_id == "SSRF-01"]
    check("SSRF-01 stays critical without validation", len(ssrf01) > 0)


def test_path_traversal():
    """Path traversal rules fire correctly."""
    print("\n--- Path Traversal ---")

    code = '''
def read_file(arguments):
    path = arguments["file_path"]
    with open(path) as f:
        return f.read()
'''
    findings = _scan_code(code)
    path_findings = [f for f in findings if f.rule_id.startswith("PATH")]
    check("PATH rules fire on open() with user path", len(path_findings) > 0)


def test_injection():
    """Injection rules fire correctly."""
    print("\n--- Injection Detection ---")

    # INJ-01: eval
    code = 'result = eval(user_input)\n'
    findings = _scan_code(code)
    inj01 = [f for f in findings if f.rule_id == "INJ-01"]
    check("INJ-01 fires on eval()", len(inj01) > 0)

    # INJ-02: SQL injection
    code = 'db.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    findings = _scan_code(code)
    inj02 = [f for f in findings if f.rule_id == "INJ-02"]
    check("INJ-02 fires on SQL f-string", len(inj02) > 0)

    # INJ-03: command injection
    code = 'subprocess.run(cmd, shell=True)\n'
    findings = _scan_code(code)
    inj03 = [f for f in findings if f.rule_id == "INJ-03"]
    check("INJ-03 fires on subprocess shell=True", len(inj03) > 0)

    # INJ-05: pickle
    code = 'data = pickle.loads(user_data)\n'
    findings = _scan_code(code)
    inj05 = [f for f in findings if f.rule_id == "INJ-05"]
    check("INJ-05 fires on pickle.loads()", len(inj05) > 0)

    # INJ-05: yaml unsafe
    code = 'data = yaml.load(text)\n'
    findings = _scan_code(code)
    inj05 = [f for f in findings if f.rule_id == "INJ-05"]
    check("INJ-05 fires on yaml.load without SafeLoader", len(inj05) > 0)


def test_secrets():
    """Secret detection works."""
    print("\n--- Secret Detection ---")

    code = 'api_key = "sk-abcdefghij1234567890abcdef"\n'
    findings = _scan_code(code)
    auth02 = [f for f in findings if f.rule_id == "AUTH-02"]
    check("AUTH-02 fires on hardcoded API key", len(auth02) > 0)

    code = 'AKIA1234567890ABCDEF\n'
    findings = _scan_code(code)
    aws = [f for f in findings if f.rule_id == "AUTH-02" and "AWS" in f.title]
    check("AUTH-02 detects AWS access key", len(aws) > 0)


def test_ssl():
    """SSL verification check works."""
    print("\n--- SSL Check ---")

    code = 'requests.get(url, verify=False)\n'
    findings = _scan_code(code)
    sec01 = [f for f in findings if f.rule_id == "SEC-01"]
    check("SEC-01 fires on verify=False", len(sec01) > 0)


def test_format_report():
    """Report formatting and grading works."""
    print("\n--- Format Report ---")

    findings = [
        Finding("INJ-01", "critical", "eval", "eval found", "test.py", 1),
        Finding("SEC-01", "high", "ssl", "ssl disabled", "test.py", 2),
    ]
    report = format_report(findings, "test.py")
    check("Report contains finding count", "2 finding(s)" in report)
    check("Report contains grade", "Grade:" in report)
    check("Critical finding gives F grade", "Grade: F" in report)

    clean = format_report([], "clean.py")
    check("Clean report says all clear", "All clear" in clean)


def test_directory_scan():
    """Directory scanning works."""
    print("\n--- Directory Scan ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file with a vulnerability
        vuln = Path(tmpdir) / "vuln.py"
        vuln.write_text('result = eval(user_input)\n')

        # Create a clean file
        clean = Path(tmpdir) / "clean.py"
        clean.write_text('x = 1 + 2\n')

        findings = scan_directory(tmpdir)
        check("Directory scan finds vuln in vuln.py", len(findings) > 0)
        check("Finding references vuln.py", any("vuln.py" in f.file for f in findings))


def test_mcp_protocol():
    """MCP protocol handlers work."""
    print("\n--- MCP Protocol ---")

    resp = handle_request({"method": "initialize", "id": 1})
    check("initialize returns serverInfo", "serverInfo" in resp)
    check("server name is mcp-shield", resp["serverInfo"]["name"] == "mcp-shield")

    resp = handle_request({"method": "tools/list", "id": 2})
    tools = resp["tools"]
    tool_names = [t["name"] for t in tools]
    check("3 tools listed", len(tools) == 3)
    check("shield_scan_file exists", "shield_scan_file" in tool_names)
    check("shield_scan_directory exists", "shield_scan_directory" in tool_names)
    check("shield_scan_code exists", "shield_scan_code" in tool_names)

    # shield_scan_code
    resp = handle_request({
        "method": "tools/call",
        "params": {"name": "shield_scan_code", "arguments": {"code": "eval(x)", "language": "python"}},
        "id": 3
    })
    text = resp["content"][0]["text"]
    check("shield_scan_code returns findings", "INJ-01" in text or "eval" in text.lower())


def test_nonexistent_file():
    """Scanning nonexistent file returns info finding."""
    print("\n--- Edge Cases ---")

    findings = scan_file("/nonexistent/path/file.py")
    check("Nonexistent file returns finding", len(findings) > 0)
    check("Finding is info level", findings[0].severity == "info")


if __name__ == "__main__":
    test_ssrf_detection()
    test_path_traversal()
    test_injection()
    test_secrets()
    test_ssl()
    test_format_report()
    test_directory_scan()
    test_mcp_protocol()
    test_nonexistent_file()
    print(f"\n{'='*40}")
    print(f"Results: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL > 0 else 0)
