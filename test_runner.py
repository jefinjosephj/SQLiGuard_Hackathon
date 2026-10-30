#!/usr/bin/env python3
"""Local-only SQL injection demonstration and remediation verification.

This runner intentionally refuses non-loopback hosts. Use only with the supplied
Docker lab running on your own machine.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

PROJECT_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = PROJECT_DIR / "evidence"


def validate_local_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Use a local HTTP URL such as http://127.0.0.1:8080")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Provide only the base URL, without a path, query, or fragment")

    host = parsed.hostname.lower()
    local = host == "localhost"
    if not local:
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
    if not local:
        raise ValueError("Safety check: this tool only targets localhost or a loopback IP address")
    return base_url.rstrip("/")


def extract_heading(body: str) -> str:
    match = re.search(r"<h2[^>]*>(.*?)</h2>", body, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return "No recognizable result heading"
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(1))).strip()


def post_login(base_url: str, endpoint: str, username: str, password: str) -> dict:
    url = f"{base_url}/{endpoint}"
    payload = urlencode({"username": username, "password": password}).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "SQLiGuard-LocalLab/1.0"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            status_code = response.status
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        status_code = exc.code
        body = exc.read().decode("utf-8", errors="replace")
    except URLError as exc:
        raise RuntimeError(
            f"Could not reach {url}. Start the Docker lab and confirm the page loads. Details: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise RuntimeError(f"Timed out connecting to {url}") from exc

    return {
        "http_status": status_code,
        "login_success": "Login successful" in body,
        "observed_message": extract_heading(body),
    }


def build_tests(base_url: str) -> list[dict]:
    # All probes are non-destructive and are sent only to the local training app.
    injection_username = "admin' -- "
    cases = [
        {
            "name": "Vulnerable endpoint: valid sample account",
            "endpoint": "vulnerable_login.php", "endpoint_type": "Vulnerable baseline",
            "input_category": "Authentication regression", "username": "admin", "password": "admin123",
            "expected_success": True, "purpose": "Confirm normal login works on the baseline.",
        },
        {
            "name": "Vulnerable endpoint: invalid credentials",
            "endpoint": "vulnerable_login.php", "endpoint_type": "Vulnerable baseline",
            "input_category": "Authentication regression", "username": "not-a-user", "password": "wrong-password",
            "expected_success": False, "purpose": "Confirm ordinary invalid credentials are rejected.",
        },
        {
            "name": "Vulnerable endpoint: SQL injection probe",
            "endpoint": "vulnerable_login.php", "endpoint_type": "Vulnerable baseline",
            "input_category": "SQL injection behavior", "username": injection_username, "password": "not-the-password",
            "expected_success": True, "purpose": "Reproduce the known weakness in the intentionally vulnerable local endpoint.",
        },
        {
            "name": "Secured endpoint: valid sample account",
            "endpoint": "login.php", "endpoint_type": "Parameterized-query implementation",
            "input_category": "Authentication regression", "username": "admin", "password": "admin123",
            "expected_success": True, "purpose": "Confirm the secured implementation preserves legitimate login.",
        },
        {
            "name": "Secured endpoint: invalid credentials",
            "endpoint": "login.php", "endpoint_type": "Parameterized-query implementation",
            "input_category": "Authentication regression", "username": "not-a-user", "password": "wrong-password",
            "expected_success": False, "purpose": "Confirm the secured implementation rejects invalid credentials.",
        },
        {
            "name": "Secured endpoint: same SQL injection probe",
            "endpoint": "login.php", "endpoint_type": "Parameterized-query implementation",
            "input_category": "SQL injection behavior", "username": injection_username, "password": "not-the-password",
            "expected_success": False, "purpose": "Verify the same input does not bypass authentication.",
        },
        {
            "name": "Secured endpoint: empty credentials",
            "endpoint": "login.php", "endpoint_type": "Parameterized-query implementation",
            "input_category": "Input validation / regression", "username": "", "password": "",
            "expected_success": False, "purpose": "Confirm empty fields do not authenticate.",
        },
        {
            "name": "Secured endpoint: quote-only username",
            "endpoint": "login.php", "endpoint_type": "Parameterized-query implementation",
            "input_category": "Special-character handling", "username": "'", "password": "anything",
            "expected_success": False, "purpose": "Confirm a quote character is treated as ordinary input.",
        },
        {
            "name": "Secured endpoint: SQL metacharacters in username",
            "endpoint": "login.php", "endpoint_type": "Parameterized-query implementation",
            "input_category": "Special-character handling", "username": "admin' OR '1'='1", "password": "wrong-password",
            "expected_success": False, "purpose": "Confirm SQL-like text does not alter the secured query structure.",
        },
        {
            "name": "Secured endpoint: whitespace-only credentials",
            "endpoint": "login.php", "endpoint_type": "Parameterized-query implementation",
            "input_category": "Input validation / regression", "username": "   ", "password": "   ",
            "expected_success": False, "purpose": "Confirm whitespace-only values do not authenticate.",
        },
    ]

    results = []
    for case in cases:
        observed = post_login(base_url, case["endpoint"], case["username"], case["password"])
        expected = case["expected_success"]
        actual = observed["login_success"]
        results.append({
            "name": case["name"],
            "endpoint": case["endpoint"],
            "endpoint_type": case["endpoint_type"],
            "input_category": case["input_category"],
            "purpose": case["purpose"],
            "expected_outcome": "Login successful" if expected else "Login failed",
            "actual_outcome": observed["observed_message"],
            "http_status": observed["http_status"],
            "test_status": "PASS" if expected == actual else "FAIL",
        })
    # Lightweight source-level checks complement the HTTP behavior tests. These
    # inspect the supplied secured PHP implementation; they are not a substitute
    # for a full code audit or runtime penetration test.
    secured_source_path = PROJECT_DIR / "web" / "login.php"
    try:
        secured_source = secured_source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Could not read secured implementation for source checks: {exc}") from exc

    source_checks = [
        {
            "name": "Source review: SQL uses placeholders and bound parameters",
            "input_category": "Secure coding control / static source check",
            "purpose": "Check that the secured PHP query uses placeholders and bind_param rather than interpolating user input.",
            "passed": bool(re.search(r"WHERE\s+username\s*=\s*\?\s+AND\s+password\s*=\s*\?", secured_source, re.I) and re.search(r"bind_param\s*\(\s*['\"]ss['\"]", secured_source, re.I)),
        },
        {
            "name": "Source review: HTML output is escaped",
            "input_category": "Secure coding control / static source check",
            "purpose": "Check that the displayed username is passed through htmlspecialchars with quote handling and UTF-8.",
            "passed": bool(re.search(r"htmlspecialchars\s*\(\s*\$username\s*,\s*ENT_QUOTES\s*,\s*['\"]UTF-8['\"]\s*\)", secured_source, re.I)),
        },
        {
            "name": "Source review: database errors are not returned to users",
            "input_category": "Secure coding control / static source check",
            "purpose": "Check that database errors are logged server-side and the response uses a generic service message.",
            "passed": bool("error_log(" in secured_source and "Service temporarily unavailable." in secured_source and not re.search(r"(?:echo|die|exit)\s*\(?\s*['\"](?:Database connection failed|SQL Error)\s*[:\"]", secured_source, re.I)),
        },
        {
            "name": "Source review: authentication failure message is generic",
            "input_category": "Secure coding control / static source check",
            "purpose": "Check that failed logins use a generic message rather than identifying which credential was incorrect.",
            "passed": bool("Invalid username or password." in secured_source),
        },
    ]
    for check in source_checks:
        results.append({
            "name": check["name"],
            "endpoint": "web/login.php",
            "endpoint_type": "Static source review",
            "input_category": check["input_category"],
            "purpose": check["purpose"],
            "expected_outcome": "Control pattern present",
            "actual_outcome": "Control pattern present" if check["passed"] else "Control pattern missing or not recognized",
            "http_status": None,
            "test_status": "PASS" if check["passed"] else "FAIL",
        })
    return results


def write_reports(base_url: str, results: list[dict]) -> tuple[Path, Path, dict]:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    vulnerable_probe = next(
        (r for r in results if r["name"] == "Vulnerable endpoint: SQL injection probe"), None
    )
    secured_probe = next(
        (r for r in results if r["name"] == "Secured endpoint: same SQL injection probe"), None
    )
    passed = sum(r["test_status"] == "PASS" for r in results)
    category_counts = {}
    for item in results:
        category_counts[item["input_category"]] = category_counts.get(item["input_category"], 0) + 1
    report = {
        "project": "SQLiGuard - SQL Injection Detection and Prevention Framework",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target_base_url": base_url,
        "scope": "Local, intentionally vulnerable training application only",
        "tests_passed": passed,
        "tests_total": len(results),
        "tests_failed": len(results) - passed,
        "category_counts": category_counts,
        "vulnerability_reproduced_on_baseline": bool(vulnerable_probe and vulnerable_probe["actual_outcome"] == "Login successful"),
        "mitigation_verified_on_parameterized_endpoint": bool(secured_probe and secured_probe["actual_outcome"] == "Login failed"),
        "results": results,
        "limitations": [
            "This is a small proof of concept for a single local login workflow, not a general-purpose SQL injection scanner.",
            "The suite combines HTTP behavior tests with simple source-pattern checks; source checks are not a complete code audit and can produce false positives or false negatives.",
            "Response-message checks can miss vulnerabilities that do not change the visible login result.",
            "The supplied training database uses demonstration credentials and plaintext sample passwords; do not deploy it publicly or use real accounts.",
        ],
    }
    json_path = EVIDENCE_DIR / "test_results.json"
    html_path = EVIDENCE_DIR / "test_report.html"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    rows = []
    for item in results:
        status_class = "pass" if item["test_status"] == "PASS" else "fail"
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['name'])}</td>"
            f"<td>{html.escape(item['endpoint_type'])}</td>"
            f"<td>{html.escape(item['input_category'])}</td>"
            f"<td>{html.escape(item['expected_outcome'])}</td>"
            f"<td>{html.escape(item['actual_outcome'])}" + (f" (HTTP {item['http_status']})" if item["http_status"] is not None else " (source check)") + "</td>"
            f"<td class='{status_class}'>{item['test_status']}</td>"
            "</tr>"
        )
    reproduced_text = "YES" if report["vulnerability_reproduced_on_baseline"] else "NO / UNEXPECTED"
    mitigation_text = "YES" if report["mitigation_verified_on_parameterized_endpoint"] else "NO / UNEXPECTED"
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SQLiGuard Test Report</title><style>
body{{font-family:Arial,sans-serif;max-width:1100px;margin:32px auto;padding:0 18px;color:#172033;background:#f7f9fc}}
h1{{margin-bottom:6px}}.muted{{color:#596579}}.summary{{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}}.card{{background:white;border:1px solid #dce2ec;border-radius:10px;padding:14px 18px;min-width:180px}}
table{{border-collapse:collapse;width:100%;background:white}}th,td{{padding:10px;border:1px solid #dce2ec;text-align:left;vertical-align:top}}th{{background:#eaf0f8}}.pass{{color:#137333;font-weight:bold}}.fail{{color:#b3261e;font-weight:bold}}.note{{background:#fff6dc;padding:14px;border-radius:8px;line-height:1.5}}
</style></head><body>
<h1>SQLiGuard — Test Report</h1><div class="muted">Generated (UTC): {html.escape(report['generated_at_utc'])} · Local target: {html.escape(base_url)}</div>
<div class="summary"><div class="card"><b>Tests passed</b><h2>{passed}/{len(results)}</h2></div><div class="card"><b>Tests failed</b><h2>{len(results) - passed}</h2></div><div class="card"><b>Vulnerability reproduced on baseline</b><h2>{reproduced_text}</h2></div><div class="card"><b>Mitigation verified</b><h2>{mitigation_text}</h2></div></div>
<h2>Test results</h2><table><thead><tr><th>Test</th><th>Implementation</th><th>Input category</th><th>Expected</th><th>Observed</th><th>Status</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>Interpretation</h2><p>A PASS means the observed behavior matched the expected behavior for that test. In particular, a successful injection probe against the intentionally vulnerable endpoint is evidence that the baseline weakness was reproduced; it does not mean that endpoint is secure.</p>
<div class="note"><b>Scope and limitations:</b> This report is for a local training lab. It tests one login workflow and uses visible response messages. It is not a general-purpose scanner or production security certification. The supplied sample credentials and database are for demonstration only.</div>
</body></html>"""
    html_path.write_text(page, encoding="utf-8")
    return json_path, html_path, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SQLiGuard tests against the supplied local Docker lab.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="Local lab URL (loopback only).")
    args = parser.parse_args()

    try:
        base_url = validate_local_base_url(args.base_url)
        results = build_tests(base_url)
        json_path, html_path, report = write_reports(base_url, results)
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("\nSQLiGuard — Local SQL Injection Test Run")
    print("=" * 58)
    for result in results:
        print(f"[{result['test_status']}] {result['name']}: {result['actual_outcome']}")
    print("-" * 58)
    print(f"Tests passed: {report['tests_passed']}/{report['tests_total']}")
    print(f"Tests failed: {report['tests_failed']}")
    print("Coverage by category:")
    for category, count in report["category_counts"].items():
        print(f"  - {category}: {count}")
    print(f"Injection reproduced on vulnerable endpoint: {report['vulnerability_reproduced_on_baseline']}")
    print(f"Parameterized-query mitigation verified: {report['mitigation_verified_on_parameterized_endpoint']}")
    print(f"JSON evidence: {json_path}")
    print(f"HTML report:  {html_path}")

    all_expected = report["tests_passed"] == report["tests_total"]
    controls_verified = report["vulnerability_reproduced_on_baseline"] and report["mitigation_verified_on_parameterized_endpoint"]
    return 0 if all_expected and controls_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
