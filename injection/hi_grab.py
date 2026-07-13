#!/usr/bin/env python3
import socket
import ssl
import re
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
DEFAULT_TIMEOUT = 3
DEFAULT_RECV = 4096
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"
PROTOCOL_PROBES = {
80: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
443: b"HEAD / HTTP/1.0\r\n\r\n",
8080: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
8443: b"HEAD / HTTP/1.0\r\n\r\n",
21: None, # FTP сам отправляет баннер
22: None, # SSH сам отправляет баннер
23: None, # Telnet
25: b"EHLO hacker.local\r\n",
110: b"USER test\r\n",
143: b"A1 CAPABILITY\r\n",
3306: None, # MySQL сам отправляет handshake
5432: None, # PostgreSQL - сложный протокол, просто читаем
6379: b"INFO server\r\n",
27017: None,
}
VERSION_PATTERNS = [
(r"Apache[/ ]([\d.]+)",
 "Apache"),
(r"nginx[/ ]([\d.]+)",
 "nginx"),
(r"OpenSSH[_ ]([\d.p]+)",
 "OpenSSH"),
(r"SSH-([\d.]+)-",
 "SSH"),
(r"Microsoft-IIS[/ ]([\d.]+)", "IIS"),
(r"vsftpd ([\d.]+)",
 "vsftpd"),
(r"ProFTPD ([\d.]+)",
 "ProFTPD"),
(r"Postfix ([\w.]+)",
 "Postfix"),
— 33 —
(r"MySQL[ \-]([\d.]+)",
 "MySQL"),
(r"([\d]+\.[\d]+\.[\d]+-MariaDB)", "MariaDB"),
(r"Redis server v=([\d.]+)",
 "Redis"),
(r"X-Powered-By: (PHP[/\d.]+)", "PHP"),
(r"Server: ([\w/. ]+)",
 "Server"),
]
def grab_banner(host: str, port: int, timeout: float,
use_ssl: bool = False) -> Optional[str]:
"""
Подключается к хосту:порту и читает баннер.
Возвращает декодированную строку или None.
"""
try:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(timeout)
if use_ssl:
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = ctx.wrap_socket(sock, server_hostname=host)
sock.connect((host, port))
# Шлём протокол-специфичный зонд
probe = PROTOCOL_PROBES.get(port)
if probe:
if b"{host}" in probe:
probe = probe.replace(b"{host}", host.encode())
sock.send(probe)
# Ждём и читаем баннер
banner = b""
sock.settimeout(timeout)
try:
while True:
chunk = sock.recv(DEFAULT_RECV)
if not chunk:
break
banner += chunk
if len(banner) > 8192:
break
except socket.timeout:
pass
sock.close()
return banner.decode("utf-8", errors="replace").strip()
except (ConnectionRefusedError, socket.timeout, OSError, ssl.SSLError):
return None
except Exception as e:
return None
def extract_versions(banner: str) -> list[tuple[str, str]]:
"""Извлекает имена и версии из строки баннера."""
versions = []
for pattern, name in VERSION_PATTERNS:
match = re.search(pattern, banner, re.IGNORECASE)
if match:
versions.append((name, match.group(1)))
return versions
def scan_port(host: str, port: int, timeout: float) -> dict:
"""Сканирует один порт: пробуем обычный, затем SSL."""
result = {
"port": port,
"banner": None,
"versions": [],
"ssl": False
}
# Сначала пробуем обычное соединение
banner = grab_banner(host, port, timeout)
# Если не получилось или порт SSL (443, 8443, 993, 995, etc.)
ssl_ports = {443, 465, 636, 993, 995, 8443}
if banner is None and port in ssl_ports:
banner = grab_banner(host, port, timeout, use_ssl=True)
if banner:
result["ssl"] = True
result["banner"] = banner
if banner:
result["versions"] = extract_versions(banner)
return result
30 Python-скриптов для Хакинга
def main():
parser = argparse.ArgumentParser(description="Banner Grabber & Version
Detector")
parser.add_argument("-t", "--target", required=True, help="IP или hostname
цели")
parser.add_argument("-p", "--ports", required=True,
help="Порты через запятую: 22,80,443,3306")
parser.add_argument("-T", "--timeout", type=float, default=DEFAULT_TIMEOUT,
help="Таймаут соединения (секунды)")
parser.add_argument("--threads",
 type=int, default=10,
help="Кол-во потоков")
args = parser.parse_args()
# Парсим порты
try:
ports = [int(p.strip()) for p in args.ports.split(",")]
except ValueError:
print(f"{RED}[!] Неверный формат портов{RESET}")
sys.exit(1)
print(f"{CYAN}{'='*60}")
print(f" Banner Grabber → {args.target}")
print(f" Портов: {len(ports)} | Таймаут: {args.timeout}s | Потоков:
{args.threads}")
print(f"{'='*60}{RESET}\n")
results = []
with ThreadPoolExecutor(max_workers=args.threads) as executor:
futures = {executor.submit(scan_port, args.target, p, args.timeout): p
for p in ports}
for future in as_completed(futures):
result = future.result()
results.append(result)
— 36 —
# Сортируем по порту и выводим
results.sort(key=lambda x: x["port"])
for r in results:
port = r["port"]
banner = r["banner"]
ssl_mark = " [SSL]" if r["ssl"] else ""
if banner:
# Первые 150 символов баннера
banner_preview = banner.replace("\n", " ").replace("\r", "")[:150]
print(f"{GREEN}[+] Port {port:<5}{ssl_mark}")
print(f" Banner: {banner_preview}{RESET}")
if r["versions"]:
for name, ver in r["versions"]:
print(f" {YELLOW}→ {name}: {ver}{RESET}")
print()
else:
print(f"{RED}[-] Port {port:<5} — нет ответа{RESET}")
# Итоговые версии
all_versions = [(r["port"], name, ver)
for r in results
for name, ver in r["versions"]]
if all_versions:
print(f"\n{CYAN}{'='*60}")
print(" Обнаруженные версии:")
print(f"{'='*60}{RESET}")
for port, name, ver in all_versions:
print(f" {GREEN}Port {port}: {name} {ver}{RESET}")
print(f"\n{YELLOW} Ищи CVE на: https://nvd.nist.gov/vuln/search{RESET}")
if __name__ == "__main__":
main()
