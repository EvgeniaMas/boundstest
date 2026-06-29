#!/usr/bin/env python3
"""
api_scanner.py - API Vulnerability Scanner
Bug Bounty Toolkit | @samsonram

Tests for OWASP API Security Top 10:
  - Broken Object Level Authorization (BOLA/IDOR)
  - Broken Authentication (missing/weak tokens)
  - Excessive Data Exposure
  - Lack of Rate Limiting
  - Broken Function Level Authorization
  - Mass Assignment
  - Security Misconfiguration (CORS, verbose errors)
  - Injection in API params

Usage:
  python3 api_scanner.py -u https://api.example.com -e endpoints.txt
  python3 api_scanner.py -u https://api.example.com -e endpoints.txt -t YOUR_TOKEN
"""

import argparse
import json
import time
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (BugBounty-APIScanner/1.0)",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_request(method: str, url: str, headers: dict, data: dict = None, timeout: int = 10):
    try:
        r = requests.request(method, url, headers=headers, json=data,
                             timeout=timeout, verify=False, allow_redirects=True)
        return r
    except requests.exceptions.ConnectionError:
        return None
    except Exception as e:
        return None

# ─── Test 1: Unauthenticated Access ──────────────────────────────────────────

def test_unauthenticated(base_url: str, endpoints: list[str]) -> list[dict]:
    """Check if endpoints return data without any auth token."""
    findings = []
    print("\n[*] Test 1: Unauthenticated Access")
    for ep in endpoints:
        url = f"{base_url.rstrip('/')}/{ep.lstrip('/')}"
        r = make_request("GET", url, HEADERS_BASE)
        if r and r.status_code == 200:
            finding = {
                "type": "Unauthenticated Access",
                "severity": "HIGH",
                "url": url,
                "status_code": r.status_code,
                "detail": f"Endpoint returns 200 without authentication. Response size: {len(r.text)} bytes",
            }
            findings.append(finding)
            print(f"  [!] {url} => 200 OK (no auth required)")
        elif r:
            print(f"  [OK] {url} => {r.status_code}")
    return findings

# ─── Test 2: BOLA / IDOR ─────────────────────────────────────────────────────

def test_bola(base_url: str, endpoints: list[str], token: str = None) -> list[dict]:
    """
    Test for BOLA by iterating numeric IDs.
    Flags when different IDs return 200 with varying data.
    """
    findings = []
    print("\n[*] Test 2: BOLA / IDOR (ID Enumeration)")
    headers = {**HEADERS_BASE}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    id_endpoints = [ep for ep in endpoints if "{id}" in ep or "<id>" in ep]

    for ep in id_endpoints:
        responses = {}
        for obj_id in [1, 2, 3, 99, 100]:
            url = f"{base_url.rstrip('/')}/{ep.lstrip('/').replace('{id}', str(obj_id)).replace('<id>', str(obj_id))}"
            r = make_request("GET", url, headers)
            if r:
                responses[obj_id] = {"status": r.status_code, "size": len(r.text)}

        # If multiple IDs return 200, flag as potential BOLA
        ok_ids = [i for i, v in responses.items() if v["status"] == 200]
        if len(ok_ids) > 1:
            finding = {
                "type": "Potential BOLA/IDOR",
                "severity": "HIGH",
                "endpoint": ep,
                "detail": f"IDs {ok_ids} all returned 200 — verify cross-user access is restricted",
                "responses": responses,
            }
            findings.append(finding)
            print(f"  [!] {ep} — multiple IDs accessible: {ok_ids}")
        else:
            print(f"  [OK] {ep} — ID enumeration looks restricted")
    return findings

# ─── Test 3: Rate Limiting ────────────────────────────────────────────────────

def test_rate_limiting(base_url: str, endpoint: str, token: str = None,
                       requests_count: int = 30) -> list[dict]:
    """Send rapid requests and check if rate limiting kicks in."""
    findings = []
    print(f"\n[*] Test 3: Rate Limiting ({requests_count} rapid requests)")
    headers = {**HEADERS_BASE}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    status_codes = []
    for i in range(requests_count):
        r = make_request("GET", url, headers, timeout=5)
        if r:
            status_codes.append(r.status_code)

    rate_limited = any(c in [429, 503] for c in status_codes)
    success_count = status_codes.count(200)

    if not rate_limited and success_count == requests_count:
        findings.append({
            "type": "Missing Rate Limiting",
            "severity": "MEDIUM",
            "url": url,
            "detail": f"All {requests_count} rapid requests returned 200 — no rate limiting detected",
        })
        print(f"  [!] No rate limiting detected — all {requests_count} requests succeeded")
    else:
        print(f"  [OK] Rate limiting active (saw 429/503 responses)")
    return findings

# ─── Test 4: CORS Misconfiguration ───────────────────────────────────────────

def test_cors(base_url: str, endpoints: list[str]) -> list[dict]:
    """Check for overly permissive CORS headers."""
    findings = []
    print("\n[*] Test 4: CORS Misconfiguration")
    malicious_origin = "https://evil.attacker.com"

    for ep in endpoints[:5]:  # Check first 5 endpoints
        url = f"{base_url.rstrip('/')}/{ep.lstrip('/')}"
        headers = {**HEADERS_BASE, "Origin": malicious_origin}
        r = make_request("GET", url, headers)
        if not r:
            continue

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" or acao == malicious_origin:
            severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": severity,
                "url": url,
                "detail": f"Access-Control-Allow-Origin: {acao} | Credentials: {acac}",
            })
            print(f"  [!] {url} — CORS allows {acao} (credentials: {acac})")
        else:
            print(f"  [OK] {url} — CORS restricted")
    return findings

# ─── Test 5: HTTP Method Tampering ───────────────────────────────────────────

def test_http_methods(base_url: str, endpoints: list[str], token: str = None) -> list[dict]:
    """Test unexpected HTTP methods on endpoints."""
    findings = []
    print("\n[*] Test 5: HTTP Method Tampering")
    headers = {**HEADERS_BASE}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]
    for ep in endpoints[:5]:
        url = f"{base_url.rstrip('/')}/{ep.lstrip('/')}"
        for method in methods:
            r = make_request(method, url, headers)
            if r and r.status_code not in [405, 404, 401, 403]:
                findings.append({
                    "type": "Unexpected HTTP Method Allowed",
                    "severity": "MEDIUM",
                    "url": url,
                    "method": method,
                    "status_code": r.status_code,
                    "detail": f"Method {method} returned {r.status_code}",
                })
                print(f"  [!] {method} {url} => {r.status_code}")
    return findings

# ─── Test 6: Sensitive Data Exposure ─────────────────────────────────────────

SENSITIVE_KEYWORDS = ["password", "passwd", "secret", "token", "api_key", "apikey",
                      "credit_card", "ssn", "private_key", "access_token", "refresh_token"]

def test_sensitive_exposure(base_url: str, endpoints: list[str], token: str = None) -> list[dict]:
    """Check API responses for sensitive data exposure."""
    findings = []
    print("\n[*] Test 6: Sensitive Data Exposure")
    headers = {**HEADERS_BASE}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for ep in endpoints:
        url = f"{base_url.rstrip('/')}/{ep.lstrip('/')}"
        r = make_request("GET", url, headers)
        if not r or r.status_code != 200:
            continue

        body = r.text.lower()
        found_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in body]
        if found_keywords:
            findings.append({
                "type": "Sensitive Data Exposure",
                "severity": "HIGH",
                "url": url,
                "detail": f"Response contains sensitive keywords: {found_keywords}",
            })
            print(f"  [!] {url} — contains: {found_keywords}")
    return findings

# ─── Test 7: Injection in Params ─────────────────────────────────────────────

INJECTION_PAYLOADS = {
    "SQLi": ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT null,null--"],
    "NoSQLi": ['{"$gt": ""}', '{"$ne": null}'],
    "XSS": ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
    "SSTI": ['{{7*7}}', '${7*7}', '<%= 7*7 %>'],
}

def test_injection(base_url: str, endpoints: list[str], token: str = None) -> list[dict]:
    """Test query parameters for injection vulnerabilities."""
    findings = []
    print("\n[*] Test 7: Injection Testing (SQLi / NoSQLi / XSS / SSTI)")
    headers = {**HEADERS_BASE}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for ep in endpoints[:5]:
        url_base = f"{base_url.rstrip('/')}/{ep.lstrip('/')}"
        for inj_type, payloads in INJECTION_PAYLOADS.items():
            for payload in payloads:
                url = f"{url_base}?id={requests.utils.quote(payload)}&q={requests.utils.quote(payload)}"
                r = make_request("GET", url, headers)
                if not r:
                    continue
                body = r.text.lower()

                # Look for error indicators
                error_signals = ["sql syntax", "mysql", "syntax error", "unclosed quotation",
                                 "pg::", "sqlite", "traceback", "exception", "stack trace"]
                triggered = [sig for sig in error_signals if sig in body]

                # Check if payload is reflected (XSS)
                if inj_type == "XSS" and payload.lower() in r.text.lower():
                    triggered.append("REFLECTED")

                # SSTI: check if {{7*7}} evaluated to 49
                if inj_type == "SSTI" and "49" in r.text:
                    triggered.append("EVALUATED")

                if triggered:
                    findings.append({
                        "type": f"Potential {inj_type}",
                        "severity": "HIGH",
                        "url": url,
                        "payload": payload,
                        "indicators": triggered,
                    })
                    print(f"  [!] {inj_type} indicator at {url_base} — signals: {triggered}")
    return findings

# ─── Report ───────────────────────────────────────────────────────────────────

def generate_report(base_url: str, all_findings: list[dict], output_dir: str = "output"):
    import os
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"api_scan_{ts}.json")

    report = {
        "target": base_url,
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "severity_summary": {
            "HIGH":   sum(1 for f in all_findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
            "LOW":    sum(1 for f in all_findings if f.get("severity") == "LOW"),
        },
        "findings": all_findings,
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"  Total findings: {len(all_findings)}")
    print(f"  HIGH: {report['severity_summary']['HIGH']}  MEDIUM: {report['severity_summary']['MEDIUM']}")
    print(f"  Report: {path}")
    print(f"{'='*60}")
    return path


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="API Vulnerability Scanner")
    parser.add_argument("-u", "--url",       required=True,  help="Base API URL (e.g. https://api.example.com)")
    parser.add_argument("-e", "--endpoints", required=True,  help="File with one endpoint per line")
    parser.add_argument("-t", "--token",                     help="Bearer token for authenticated tests")
    parser.add_argument("-o", "--output",    default="output", help="Output directory")
    args = parser.parse_args()

    with open(args.endpoints) as f:
        endpoints = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Loaded {len(endpoints)} endpoints")
    all_findings = []

    all_findings += test_unauthenticated(args.url, endpoints)
    all_findings += test_bola(args.url, endpoints, args.token)
    all_findings += test_rate_limiting(args.url, endpoints[0] if endpoints else "/", args.token)
    all_findings += test_cors(args.url, endpoints)
    all_findings += test_http_methods(args.url, endpoints, args.token)
    all_findings += test_sensitive_exposure(args.url, endpoints, args.token)
    all_findings += test_injection(args.url, endpoints, args.token)

    generate_report(args.url, all_findings, args.output)


if __name__ == "__main__":
    main()
