#!/usr/bin/env python3
"""
recon.py - Automated Reconnaissance Script
Bug Bounty Toolkit | @samsonram

Performs:
  - Subdomain enumeration (via crt.sh + brute force wordlist)
  - DNS resolution
  - Port scanning (via socket)
  - HTTP/HTTPS probing
  - Technology fingerprinting (headers)
  - Output saved to JSON + TXT reports

Usage:
  python3 recon.py -d example.com
  python3 recon.py -d example.com -w wordlists/subdomains.txt -o output/
"""

import argparse
import socket
import json
import os
import sys
import threading
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Config ──────────────────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443, 8888]
TIMEOUT      = 3
MAX_THREADS  = 30
HEADERS      = {"User-Agent": "Mozilla/5.0 (BugBounty-Recon/1.0)"}

# ─── Subdomain Enumeration ────────────────────────────────────────────────────

def crtsh_enum(domain: str) -> list[str]:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub:
                        subs.add(sub.lower())
            return list(subs)
    except Exception as e:
        print(f"  [!] crt.sh error: {e}")
    return []


def wordlist_enum(domain: str, wordlist_path: str) -> list[str]:
    """Brute-force subdomains using a wordlist."""
    if not wordlist_path or not os.path.exists(wordlist_path):
        return []
    subs = []
    with open(wordlist_path) as f:
        words = [line.strip() for line in f if line.strip()]
    print(f"  [*] Brute-forcing {len(words)} subdomains...")

    def check(word):
        fqdn = f"{word}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except:
            return None

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        for result in ex.map(check, words):
            if result:
                subs.append(result)
    return subs


def resolve_subdomains(subdomains: list[str]) -> dict:
    """Resolve IP addresses for each subdomain."""
    resolved = {}
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            resolved[sub] = ip
        except:
            resolved[sub] = None
    return resolved

# ─── Port Scanning ────────────────────────────────────────────────────────────

def scan_port(host: str, port: int) -> tuple[int, bool]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((host, port))
        s.close()
        return (port, result == 0)
    except:
        return (port, False)


def scan_host(host: str, ports: list[int] = COMMON_PORTS) -> list[int]:
    """Scan a host for open ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for f in as_completed(futures):
            port, is_open = f.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)

# ─── HTTP Probing ─────────────────────────────────────────────────────────────

def probe_http(subdomain: str) -> dict:
    """Check if host responds over HTTP/HTTPS and grab headers."""
    result = {"http": None, "https": None, "title": None, "server": None, "technologies": []}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True, verify=False)
            result[scheme] = {"status": r.status_code, "url": r.url}
            result["server"] = r.headers.get("Server", "")
            result["x_powered_by"] = r.headers.get("X-Powered-By", "")
            result["content_type"] = r.headers.get("Content-Type", "")

            # Fingerprint technologies from headers
            techs = []
            if "wordpress" in r.text.lower():     techs.append("WordPress")
            if "x-drupal" in str(r.headers).lower(): techs.append("Drupal")
            if "laravel" in r.headers.get("Set-Cookie","").lower(): techs.append("Laravel")
            if "asp.net" in str(r.headers).lower():  techs.append("ASP.NET")
            result["technologies"] = techs

            # Grab page title
            if "<title>" in r.text.lower():
                start = r.text.lower().find("<title>") + 7
                end   = r.text.lower().find("</title>")
                result["title"] = r.text[start:end].strip()[:100]
            break  # Stop after first successful response
        except:
            pass
    return result

# ─── Security Header Check ────────────────────────────────────────────────────

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def check_security_headers(subdomain: str) -> dict:
    """Check for presence/absence of security headers."""
    findings = {}
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{subdomain}", timeout=TIMEOUT, headers=HEADERS, verify=False)
            for h in SECURITY_HEADERS:
                findings[h] = r.headers.get(h, "MISSING")
            return findings
        except:
            pass
    return {h: "UNREACHABLE" for h in SECURITY_HEADERS}

# ─── Main ─────────────────────────────────────────────────────────────────────

def run_recon(domain: str, wordlist: str = None, output_dir: str = "output") -> dict:
    os.makedirs(output_dir, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"  TARGET: {domain}")
    print(f"  START:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # 1. Subdomain enumeration
    print("[1/5] Enumerating subdomains via crt.sh...")
    crt_subs = crtsh_enum(domain)
    print(f"  Found {len(crt_subs)} from crt.sh")

    wl_subs = wordlist_enum(domain, wordlist)
    all_subs = list(set(crt_subs + wl_subs + [domain]))
    print(f"  Total unique subdomains: {len(all_subs)}")

    # 2. Resolve
    print("\n[2/5] Resolving DNS...")
    resolved = resolve_subdomains(all_subs)
    alive = {k: v for k, v in resolved.items() if v}
    print(f"  Resolved: {len(alive)} / {len(all_subs)}")

    # 3. Port scan
    print("\n[3/5] Scanning ports on live hosts...")
    port_results = {}
    for sub, ip in alive.items():
        ports = scan_host(ip)
        port_results[sub] = {"ip": ip, "open_ports": ports}
        if ports:
            print(f"  {sub} ({ip}) => {ports}")

    # 4. HTTP probe
    print("\n[4/5] Probing HTTP/HTTPS...")
    http_results = {}
    for sub in alive:
        probe = probe_http(sub)
        http_results[sub] = probe
        status = probe.get("https") or probe.get("http")
        if status:
            print(f"  {sub} => {status['status']} | {probe.get('title','')}")

    # 5. Security headers
    print("\n[5/5] Checking security headers...")
    header_results = {}
    for sub in alive:
        header_results[sub] = check_security_headers(sub)
        missing = [h for h, v in header_results[sub].items() if v == "MISSING"]
        if missing:
            print(f"  [!] {sub} missing: {', '.join(missing)}")

    # ── Build report ──────────────────────────────────────────────────────────
    report = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains_found": len(all_subs),
        "live_hosts": len(alive),
        "subdomains": {
            sub: {
                "ip": resolved.get(sub),
                "open_ports": port_results.get(sub, {}).get("open_ports", []),
                "http": http_results.get(sub, {}),
                "security_headers": header_results.get(sub, {}),
            }
            for sub in all_subs
        },
    }

    # Save JSON
    json_path = os.path.join(output_dir, f"{domain}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved: {json_path}")

    return report


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    parser = argparse.ArgumentParser(description="Bug Bounty Recon Automation")
    parser.add_argument("-d", "--domain",   required=True,  help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist",               help="Path to subdomain wordlist")
    parser.add_argument("-o", "--output",   default="output", help="Output directory")
    args = parser.parse_args()

    run_recon(args.domain, args.wordlist, args.output)
