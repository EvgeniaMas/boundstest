#!/usr/bin/env python3

importimportimportimportimportasyncio
argparse
sys
aiodns
aiohttp

───────────────────────────────────────────────────────────────
DEFAULT_WORDLIST = "subdomains.txt"
DEFAULT_TIMEOUT = 2
DEFAULT_CONC = 100
DEFAULT_DNS = ["8.8.8.8", "1.1.1.1"]
# ── Цвета для вывода
───────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
found = []
async def resolve_subdomain(resolver: aiodns.DNSResolver,
subdomain: str,
semaphore: asyncio.Semaphore) -> tuple[str, list[str]] | None:
"""Резолвим поддомен через DNS. Возвращает (subdomain, [IP]) или
None."""
async with semaphore:
try:
result = await asyncio.wait_for(
resolver.query(subdomain, "A"),
timeout=2.0
)
ips = [r.host for r in result]
return (subdomain, ips)
except (aiodns.error.DNSError, asyncio.TimeoutError):
return None
except Exception:
return None
async def check_http(session: aiohttp.ClientSession,
subdomain: str,
semaphore: asyncio.Semaphore) -> tuple[str, int] | None:
async with semaphore:
for scheme in ["https", "http"]:
url = f"{scheme}://{subdomain}"
try:
async with session.get(url, timeout=aiohttp.ClientTimeout(total=3),
ssl=False, allow_redirects=True) as resp:
return (url, resp.status)
except Exception:
continue
return None
async def brute_force(domain: str, wordlist_path: str,
timeout: int, concurrency: int) -> None:

# Читаем словарь
try:
with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
words = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
print(f"{RED}[!] Словарь не найден: {wordlist_path}{RESET}")
sys.exit(1)
print(f"{YELLOW}[*] Домен:
 {domain}{RESET}")
print(f"{YELLOW}[*] Словарь: {len(words)} записей{RESET}")
print(f"{YELLOW}[*] Параллельно: {concurrency}{RESET}")
print("-" * 50)
# Создаём DNS resolver
resolver = aiodns.DNSResolver(nameservers=DEFAULT_DNS, timeout=timeout)
semaphore = asyncio.Semaphore(concurrency)
# Генерируем список поддоменов
subdomains = [f"{word}.{domain}" for word in words]
# Запускаем все DNS задачи параллельно
tasks = [resolve_subdomain(resolver, sub, semaphore) for sub in subdomains]
resolved = []
completed = 0
for coro in asyncio.as_completed(tasks):
— 21 —
result = await coro
completed += 1

if completed % 500 == 0:
print(f"\r{YELLOW}[*] Проверено: {completed}/{len(subdomains)}{RESET}",
end="")
if result:
subdomain, ips = result
ip_str = ", ".join(ips)
print(f"\n{GREEN}[+] НАЙДЕН: {subdomain:<40} → {ip_str}{RESET}")
resolved.append((subdomain, ips))
print(f"\n{YELLOW}[*] DNS резолвинг завершён. Найдено:
{len(resolved)}{RESET}")
if not resolved:
print(f"{RED}[!] Поддомены не найдены{RESET}")
return
# Проверяем HTTP доступность
print(f"\n{YELLOW}[*] Проверяем HTTP/HTTPS доступность...{RESET}")
print("-" * 50)
connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
async with aiohttp.ClientSession(connector=connector) as session:
http_tasks = [check_http(session, sub, semaphore) for sub, _ in resolved]
for coro in asyncio.as_completed(http_tasks):
result = await coro
if result:
url, status = result
color = GREEN if status == 200 else YELLOW
print(f"{color}[+] {url:<50} HTTP {status}{RESET}")
found.append((url, status))
# Итоговый отчёт
print("\n" + "=" * 50)
print(f"{GREEN}[✓] ИТОГ: найдено {len(resolved)} поддоменов, {len(found)}
живых хостов{RESET}")

def main():
parser = argparse.ArgumentParser(
description="Async Subdomain Bruteforcer",
formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("-d", "--domain", required=True, help="Целевой домен
(target.com)")
parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST,
help=f"Путь к словарю (по умолчанию: {DEFAULT_WORDLIST})")
parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
help="DNS таймаут в секундах")
parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONC,
help="Кол-во параллельных запросов")
args = parser.parse_args()
try:
asyncio.run(brute_force(args.domain, args.wordlist,
args.timeout, args.concurrency))
except KeyboardInterrupt:
print(f"\n{RED}[!] Прервано пользователем{RESET}")
if __name__ == "__main__":
main()
