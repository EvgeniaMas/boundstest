#!/usr/bin/env python3
"""
report_generator.py - Bug Bounty Report Generator
Bug Bounty Toolkit | @samsonram

Aggregates JSON findings from all scanner scripts into:
  - Markdown report (ready for HackerOne / Bugcrowd submission)
  - HTML report (visual, shareable)
  - Severity-sorted finding list

Usage:
  python3 report_generator.py -i output/ -o reports/ -p "ACME Corp" -t "Q1 2026 Assessment"
  python3 report_generator.py -i output/api_scan_20260419.json -o reports/
"""

import argparse
import json
import os
import glob
from datetime import datetime

# ─── Severity Colors / Scores ─────────────────────────────────────────────────

SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#8B0000",
    "HIGH":     "#FF4444",
    "MEDIUM":   "#FFA500",
    "LOW":      "#2196F3",
    "INFO":     "#4CAF50",
}
CVSS_APPROX = {
    "CRITICAL": "9.0–10.0",
    "HIGH":     "7.0–8.9",
    "MEDIUM":   "4.0–6.9",
    "LOW":      "0.1–3.9",
    "INFO":     "0.0",
}

# ─── Load Findings ────────────────────────────────────────────────────────────

def load_findings(input_path: str) -> list[dict]:
    findings = []
    if os.path.isdir(input_path):
        json_files = glob.glob(os.path.join(input_path, "*.json"))
    elif os.path.isfile(input_path):
        json_files = [input_path]
    else:
        print(f"[!] Input not found: {input_path}")
        return []

    for jf in json_files:
        try:
            with open(jf) as f:
                data = json.load(f)
            # Support both top-level findings list and nested
            if "findings" in data:
                for finding in data["findings"]:
                    finding.setdefault("source_file", os.path.basename(jf))
                    finding.setdefault("target", data.get("target", "Unknown"))
                    findings.append(finding)
        except Exception as e:
            print(f"[!] Failed to load {jf}: {e}")

    return findings

# ─── Dedup + Sort ─────────────────────────────────────────────────────────────

def process_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate by (type, url, param) and sort by severity."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("type",""), f.get("url",""), f.get("param",""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return sorted(unique, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 99))

# ─── Markdown Report ──────────────────────────────────────────────────────────

def generate_markdown(findings: list[dict], program: str, title: str, tester: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d")
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITY_ORDER}

    md = f"""# Bug Bounty Report — {title}

**Program:** {program}
**Tester:** {tester}
**Date:** {ts}
**Total Findings:** {len(findings)}

---

## Executive Summary

This report presents security vulnerabilities identified during testing of **{program}**.
All findings were identified through automated scanning and manual verification.
Each finding is mapped to the OWASP Top 10 and/or OWASP API Security Top 10 where applicable.

### Severity Summary

| Severity  | Count |
|-----------|-------|
| 🔴 CRITICAL | {counts.get('CRITICAL', 0)} |
| 🟠 HIGH     | {counts.get('HIGH', 0)} |
| 🟡 MEDIUM   | {counts.get('MEDIUM', 0)} |
| 🔵 LOW      | {counts.get('LOW', 0)} |
| ℹ️ INFO     | {counts.get('INFO', 0)} |

---

## Findings

"""

    for i, finding in enumerate(findings, 1):
        sev  = finding.get("severity", "INFO")
        ftype = finding.get("type", "Unknown")
        url  = finding.get("url", finding.get("endpoint", "N/A"))
        param = finding.get("param", "")
        payload = finding.get("payload", "")
        detail = finding.get("detail", "")
        indicators = finding.get("indicators", [])
        cvss = CVSS_APPROX.get(sev, "N/A")

        md += f"### Finding #{i}: {ftype}\n\n"
        md += f"**Severity:** `{sev}` (CVSS: {cvss})\n\n"
        md += f"**URL:** `{url}`\n\n"
        if param:
            md += f"**Parameter:** `{param}`\n\n"
        if payload:
            md += f"**Payload:**\n```\n{payload}\n```\n\n"
        md += f"**Description:** {detail or ftype}\n\n"
        if indicators:
            md += f"**Indicators:** {', '.join(indicators)}\n\n"

        # Remediation suggestions
        recs = get_remediation(ftype)
        if recs:
            md += f"**Remediation:**\n"
            for rec in recs:
                md += f"- {rec}\n"
            md += "\n"

        md += "---\n\n"

    md += f"""## Methodology

- **Reconnaissance:** Subdomain enumeration (crt.sh), DNS resolution, port scanning, HTTP probing
- **API Testing:** OWASP API Security Top 10 checks, authentication bypass, BOLA/IDOR
- **Injection Testing:** SQLi (error-based, boolean-blind, time-based), XSS (reflected, DOM), SSTI, SSRF
- **Fuzzing:** Parameter fuzzing with custom payloads, hidden parameter discovery

## Tools Used

- Custom Python automation suite
- Burp Suite (manual verification)
- OWASP methodology

## Disclaimer

This testing was performed within scope and in accordance with the program's rules of engagement.
All vulnerabilities were responsibly disclosed.

---
*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
    return md

# ─── HTML Report ──────────────────────────────────────────────────────────────

def generate_html(findings: list[dict], program: str, title: str, tester: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITY_ORDER}

    rows = ""
    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#999")
        rows += f"""
        <tr>
          <td>{i}</td>
          <td><span class="badge" style="background:{color}">{sev}</span></td>
          <td>{f.get('type','Unknown')}</td>
          <td><code>{f.get('url', f.get('endpoint','N/A'))[:80]}</code></td>
          <td>{f.get('param','—')}</td>
          <td>{f.get('detail','')[:100]}</td>
        </tr>"""

    summary_bars = ""
    total = max(len(findings), 1)
    for sev, color in SEVERITY_COLORS.items():
        cnt = counts.get(sev, 0)
        pct = int((cnt / total) * 100)
        summary_bars += f"""
        <div class="bar-row">
          <span class="bar-label">{sev}</span>
          <div class="bar-container">
            <div class="bar-fill" style="width:{pct}%;background:{color}"></div>
          </div>
          <span class="bar-count">{cnt}</span>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bug Bounty Report — {title}</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
    h1 {{ color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 10px; }}
    h2 {{ color: #79c0ff; margin-top: 30px; }}
    .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
    .summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
    .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px 25px; text-align: center; }}
    .stat-card .num {{ font-size: 36px; font-weight: bold; }}
    .stat-card .lbl {{ font-size: 12px; color: #8b949e; }}
    .bar-row {{ display: flex; align-items: center; margin: 5px 0; }}
    .bar-label {{ width: 80px; font-size: 13px; }}
    .bar-container {{ flex: 1; background: #21262d; border-radius: 4px; height: 18px; margin: 0 10px; }}
    .bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
    .bar-count {{ width: 30px; text-align: right; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; margin-top: 20px; }}
    th {{ background: #21262d; padding: 12px 10px; text-align: left; color: #8b949e; font-size: 13px; border-bottom: 1px solid #30363d; }}
    td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 13px; vertical-align: top; }}
    tr:hover {{ background: #1c2128; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; color: #fff; font-size: 11px; font-weight: bold; }}
    code {{ background: #21262d; padding: 2px 5px; border-radius: 3px; font-family: monospace; font-size: 12px; word-break: break-all; }}
    footer {{ margin-top: 40px; color: #8b949e; font-size: 12px; border-top: 1px solid #21262d; padding-top: 15px; }}
  </style>
</head>
<body>
  <h1>Bug Bounty Report — {title}</h1>
  <div class="meta">
    <strong>Program:</strong> {program} &nbsp;|&nbsp;
    <strong>Tester:</strong> {tester} &nbsp;|&nbsp;
    <strong>Generated:</strong> {ts}
  </div>

  <div class="summary">
    <div class="stat-card"><div class="num">{len(findings)}</div><div class="lbl">Total Findings</div></div>
    <div class="stat-card"><div class="num" style="color:#8B0000">{counts.get('CRITICAL',0)}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num" style="color:#FF4444">{counts.get('HIGH',0)}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num" style="color:#FFA500">{counts.get('MEDIUM',0)}</div><div class="lbl">Medium</div></div>
    <div class="stat-card"><div class="num" style="color:#2196F3">{counts.get('LOW',0)}</div><div class="lbl">Low</div></div>
  </div>

  <h2>Severity Distribution</h2>
  {summary_bars}

  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Param</th><th>Detail</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <footer>
    Generated by Bug Bounty Toolkit | Responsible disclosure only | {ts}
  </footer>
</body>
</html>"""

# ─── Remediation DB ───────────────────────────────────────────────────────────

REMEDIATION_MAP = {
    "SQL Injection":              ["Use parameterized queries / prepared statements", "Apply input validation and allowlisting", "Use an ORM", "Disable verbose database errors in production"],
    "XSS":                        ["HTML-encode all user-supplied output", "Implement a strict Content Security Policy (CSP)", "Use framework auto-escaping", "Validate and sanitize inputs server-side"],
    "Reflected XSS":              ["HTML-encode all user-supplied output", "Implement a strict Content Security Policy (CSP)", "Use framework auto-escaping"],
    "IDOR":                       ["Enforce object-level authorization on every request", "Use indirect reference maps instead of direct database IDs", "Validate ownership server-side before returning data"],
    "BOLA":                       ["Validate object ownership server-side", "Implement access control middleware", "Log and alert on cross-user access attempts"],
    "CORS Misconfiguration":      ["Set explicit allowlisted origins rather than wildcard", "Never combine Access-Control-Allow-Origin: * with credentials", "Validate Origin header against a server-side allowlist"],
    "Missing Rate Limiting":      ["Implement rate limiting per IP and per user", "Use exponential backoff for failed auth attempts", "Alert on abuse patterns"],
    "Unauthenticated Access":     ["Require authentication on all sensitive endpoints", "Enforce authorization middleware at the router level"],
    "Sensitive Data Exposure":    ["Remove sensitive fields from API responses", "Implement field-level access control", "Audit response payloads in API design"],
    "SSTI":                       ["Avoid passing user input directly to template engines", "Use sandboxed template environments", "Validate and sanitize template variables"],
    "SSRF":                       ["Validate and allowlist internal URLs", "Block requests to RFC 1918 ranges and metadata IPs", "Use an outbound proxy with strict allowlisting"],
    "Path Traversal":             ["Canonicalize file paths and validate against a base directory", "Never use user input directly in file operations", "Use allowlists for accessible files"],
    "Hidden Parameter Discovered":["Audit unused parameters and remove them", "Ensure undocumented parameters are not processed server-side"],
    "DOM XSS":                    ["Avoid passing user-controlled values to dangerous sinks", "Use safe DOM APIs (textContent vs innerHTML)", "Implement a strict CSP"],
}

def get_remediation(finding_type: str) -> list[str]:
    for key, recs in REMEDIATION_MAP.items():
        if key.lower() in finding_type.lower():
            return recs
    return ["Review the finding, implement appropriate input validation and authorization controls."]

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Report Generator")
    parser.add_argument("-i", "--input",   required=True,  help="Input JSON file or directory of JSON files")
    parser.add_argument("-o", "--output",  default="reports", help="Output directory")
    parser.add_argument("-p", "--program", default="Target Program", help="Bug bounty program name")
    parser.add_argument("-t", "--title",   default="Security Assessment", help="Report title")
    parser.add_argument("--tester",        default="Security Researcher", help="Your name/handle")
    args = parser.parse_args()

    print(f"[*] Loading findings from: {args.input}")
    raw = load_findings(args.input)
    findings = process_findings(raw)
    print(f"[*] {len(findings)} unique findings (from {len(raw)} total)")

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Markdown
    md = generate_markdown(findings, args.program, args.title, args.tester)
    md_path = os.path.join(args.output, f"report_{ts}.md")
    with open(md_path, "w") as f:
        f.write(md)
    print(f"[+] Markdown report: {md_path}")

    # HTML
    html = generate_html(findings, args.program, args.title, args.tester)
    html_path = os.path.join(args.output, f"report_{ts}.html")
    with open(html_path, "w") as f:
        f.write(html)
    print(f"[+] HTML report:     {html_path}")

    # JSON summary
    summary = {
        "program": args.program,
        "title": args.title,
        "generated": datetime.now().isoformat(),
        "total": len(findings),
        "severity_counts": {s: sum(1 for f in findings if f.get("severity")==s) for s in SEVERITY_ORDER},
        "findings": findings,
    }
    json_path = os.path.join(args.output, f"report_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] JSON summary:    {json_path}")


if __name__ == "__main__":
    main()
