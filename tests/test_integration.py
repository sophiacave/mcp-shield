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


def test(name, condition):
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
    test("SSRF-01 fires on requests.get with user URL", any(f.rule_id == "SSRF-01" for f in ssrf))

    # Static URL with literal string — no dynamic URL pattern
    code = 'resp = requests.get("https://api.example.com/data")\n'
    findings = _scan_code(code)
    ssrf = [f for f in findings if f.rule_id.startswith("SSRF")]
    test("No SSRF on fully literal URL", len(ssrf) == 0)


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
    test("PATH rules fire on open() with user path", len(path_findings) > 0)


def test_injection():
    """Injection rules fire correctly."""
    print("\n--- Injection Detection ---")

    # INJ-01: eval
    code = 'result = eval(user_input)\n'
    findings = _scan_code(code)
    inj01 = [f for f in findings if f.rule_id == "INJ-01"]
    test("INJ-01 fires on eval()", len(inj01) > 0)

    # INJ-02: SQL injection
    code = 'db.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    findings = _scan_code(code)
    inj02 = [f for f in findings if f.rule_id == "INJ-02"]
    test("INJ-02 fires on SQL f-string", len(inj02) > 0)

    # INJ-03: command injection
    code = 'subprocess.run(cmd, shell=True)\n'
    findings = _scan_code(code)
    inj03 = [f for f in findings if f.rule_id == "INJ-03"]
    test("INJ-03 fires on subprocess shell=True", len(inj03) > 0)

    # INJ-05: pickle
    code = 'data = pickle.loads(user_data)\n'
    findings = _scan_code(code)
    inj05 = [f for f in findings if f.rule_id == "INJ-05"]
    test("INJ-05 fires on pickle.loads()", len(inj05) > 0)

    # INJ-05: yaml unsafe
    code = 'data = yaml.load(text)\n'
    findings = _scan_code(code)
    inj05 = [f for f in findings if f.rule_id == "INJ-05"]
    test("INJ-05 fires on yaml.load without SafeLoader", len(inj05) > 0)


def test_secrets():
    """Secret detection works."""
    print("\n--- Secret Detection ---")

    code = 'api_key = "sk-abcdefghij1234567890abcdef"\n'
    findings = _scan_code(code)
    auth02 = [f for f in findings if f.rule_id == "AUTH-02"]
    test("AUTH-02 fires on hardcoded API key", len(auth02) > 0)

    code = 'AKIA1234567890ABCDEF\n'
    findings = _scan_code(code)
    aws = [f for f in findings if f.rule_id == "AUTH-02" and "AWS" in f.title]
    test("AUTH-02 detects AWS access key", len(aws) > 0)


def test_ssl():
    """SSL verification check works."""
    print("\n--- SSL Check ---")

    code = 'requests.get(url, verify=False)\n'
    findings = _scan_code(code)
    sec01 = [f for f in findings if f.rule_id == "SEC-01"]
    test("SEC-01 fires on verify=False", len(sec01) > 0)


def test_format_report():
    """Report formatting and grading works."""
    print("\n--- Format Report ---")

    findings = [
        Finding("INJ-01", "critical", "eval", "eval found", "test.py", 1),
        Finding("SEC-01", "high", "ssl", "ssl disabled", "test.py", 2),
    ]
    report = format_report(findings, "test.py")
    test("Report contains finding count", "2 finding(s)" in report)
    test("Report contains grade", "Grade:" in report)
    test("Critical finding gives F grade", "Grade: F" in report)

    clean = format_report([], "clean.py")
    test("Clean report says all clear", "All clear" in clean)


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
        test("Directory scan finds vuln in vuln.py", len(findings) > 0)
        test("Finding references vuln.py", any("vuln.py" in f.file for f in findings))


def test_mcp_protocol():
    """MCP protocol handlers work."""
    print("\n--- MCP Protocol ---")

    resp = handle_request({"method": "initialize", "id": 1})
    test("initialize returns serverInfo", "serverInfo" in resp)
    test("server name is mcp-shield", resp["serverInfo"]["name"] == "mcp-shield")

    resp = handle_request({"method": "tools/list", "id": 2})
    tools = resp["tools"]
    tool_names = [t["name"] for t in tools]
    test("3 tools listed", len(tools) == 3)
    test("shield_scan_file exists", "shield_scan_file" in tool_names)
    test("shield_scan_directory exists", "shield_scan_directory" in tool_names)
    test("shield_scan_code exists", "shield_scan_code" in tool_names)

    # shield_scan_code
    resp = handle_request({
        "method": "tools/call",
        "params": {"name": "shield_scan_code", "arguments": {"code": "eval(x)", "language": "python"}},
        "id": 3
    })
    text = resp["content"][0]["text"]
    test("shield_scan_code returns findings", "INJ-01" in text or "eval" in text.lower())


def test_nonexistent_file():
    """Scanning nonexistent file returns info finding."""
    print("\n--- Edge Cases ---")

    findings = scan_file("/nonexistent/path/file.py")
    test("Nonexistent file returns finding", len(findings) > 0)
    test("Finding is info level", findings[0].severity == "info")


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
