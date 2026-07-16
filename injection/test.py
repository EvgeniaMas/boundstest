#!/usr/bin/env python3
importimportimportimportrequests
time
random
argparse
— 47 import sys
from urllib.parse import urlencode, quote_plus
import warnings
warnings.filterwarnings("ignore")
30 Python-скриптов для Хакинга
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"

DORKS = {
"admin": [
'site:{domain} inurl:admin',
'site:{domain} inurl:administrator',
'site:{domain} intitle:"admin panel"',
'site:{domain} inurl:login intitle:admin',
'site:{domain} inurl:dashboard',
'site:{domain} inurl:wp-admin',
'site:{domain} inurl:phpmyadmin',
'site:{domain} inurl:cpanel',
'site:{domain} intitle:"Control Panel"',
'site:{domain} inurl:manage',
],
"files": [
'site:{domain} filetype:env',
'site:{domain} filetype:log',
'site:{domain} filetype:xml inurl:config',
'site:{domain} filetype:ini inurl:config',
'site:{domain} filetype:conf',
'site:{domain} ext:php inurl:config',
'site:{domain} inurl:".git"',
'site:{domain} intitle:"index of" inurl:config',
'site:{domain} filetype:json inurl:credentials',
'site:{domain} inurl:".DS_Store"',
],
"backup": [
'site:{domain} filetype:sql',
'site:{domain} filetype:bak',
'site:{domain} filetype:backup',
'site:{domain} filetype:old',
'site:{domain} filetype:zip inurl:backup',
'site:{domain} intitle:"index of" inurl:backup',
'site:{domain} inurl:backup filetype:tar',
'site:{domain} inurl:dump filetype:sql',
'site:{domain} ext:bak | ext:backup | ext:old | ext:orig',
],
"sensitive": [
'site:{domain} "password" filetype:txt',
'site:{domain} "api_key" OR "api_secret"',
'site:{domain} "access_token"',
'site:{domain} "secret_key"',
'site:{domain} inurl:key filetype:pem',
'site:{domain} "Authorization: Bearer"',
'site:{domain} filetype:xml "password"',
'site:{domain} "DB_PASSWORD" OR "DB_HOST"',
],
"login": [
'site:{domain} inurl:login',
'site:{domain} inurl:signin',
'site:{domain} inurl:auth',
'site:{domain} intitle:"Login" inurl:user',
'site:{domain} inurl:account/login',
'site:{domain} inurl:portal',
'site:{domain} intitle:"Sign in"',
],
"errors": [
'site:{domain} "Warning: mysql_fetch"',
'site:{domain} "Fatal error"',
'site:{domain} "You have an error in your SQL syntax"',
'site:{domain} "Notice: Undefined variable"',
'site:{domain} "stack trace"',
'site:{domain} inurl:error 500',
'site:{domain} "DEBUG" inurl:debug',
],
"docs": [
'site:{domain} filetype:pdf',
'site:{domain} filetype:docx',
'site:{domain} filetype:xlsx',
'site:{domain} intitle:"index of" filetype:pdf',
'site:{domain} inurl:internal filetype:pdf',
],
— 49 —
}
# Ротация User-Agent
USER_AGENTS = [
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
"Googlebot/2.1 (+http://www.google.com/bot.html)",
]
def search_google(query: str, num_results: int = 10) -> list[dict]:
"""
Выполняет поиск в Google через unofficially scraping.
Возвращает список {'title': ..., 'url': ..., 'snippet': ...}
"""
params = {
"q": query,
"num": num_results,
"hl": "en",
"start": 0,
}
headers = {
"User-Agent": random.choice(USER_AGENTS),
"Accept": "text/html,application/xhtml+xml",
"Accept-Language": "en-US,en;q=0.9",
"Referer": "https://www.google.com/",
}
url = "https://www.google.com/search?" + urlencode(params)
try:
resp = requests.get(url, headers=headers, timeout=10, verify=False)
if resp.status_code == 429:
print(f"{RED}[!] Google заблокировал запросы (429 Too Many
Requests){RESET}")
print(f"{YELLOW}[!] Подожди несколько минут или используй
VPN/Tor{RESET}")
return []
results = []
# Простой парсинг результатов Googleimport re
# Паттерн для URL результатов
url_pattern = r'<a href="/url\?q=([^&"]+)'
# Паттерн для заголовков
title_pattern = r'<h3[^>]*>(.*?)</h3>'
urls = re.findall(url_pattern, resp.text)
titles = re.findall(title_pattern, resp.text)
for i, (u, t) in enumerate(zip(urls, titles)):
if "google.com" not in u and "webcache" not in u:
clean_url = requests.utils.unquote(u)
clean_title = re.sub(r'<[^>]+>', '', t)
results.append({"url": clean_url, "title": clean_title})
return results[:num_results]
except requests.RequestException as e:
print(f"{RED}[!] Ошибка запроса: {e}{RESET}")
return []
def run_dorks(domain: str, categories: list[str],
delay: float = 3.0, results_per_dork: int = 5) -> None:
"""Запускает коллекцию дорков для домена."""
all_results = {}
total_dorks = sum(len(DORKS[c]) for c in categories if c in DORKS)
print(f"{CYAN}[*] Домен: {domain}{RESET}")
print(f"{CYAN}[*] Категории: {', '.join(categories)}{RESET}")
print(f"{CYAN}[*] Дорков: {total_dorks}{RESET}")
print(f"{CYAN}[*] Задержка: {delay}s между запросами{RESET}")
print("-" * 60)
for category in categories:
if category not in DORKS:
print(f"{YELLOW}[!] Категория '{category}' не найдена{RESET}")
continue
print(f"\n{YELLOW}[*] Категория: {category.upper()}{RESET}")
cat_results = []
for dork_template in DORKS[category]:
dork = dork_template.format(domain=domain)
print(f" {CYAN}→ {dork[:60]}...{RESET}")
results = search_google(dork, results_per_dork)
for r in results:
print(f" {GREEN}[+] {r['title'][:50]:<50}{RESET}")
print(f"
 {r['url'][:80]}")
cat_results.append(r)
if not results:
print(f" {RED}[-] Нет результатов{RESET}")
# Задержка между запросами чтобы не получить бан
jitter = delay + random.uniform(0.5, 1.5)
time.sleep(jitter)
all_results[category] = cat_results
# Итоговый отчёт
print(f"\n{GREEN}{'='*60}")
print(" ИТОГОВЫЙ ОТЧЁТ")
print(f"{'='*60}{RESET}")
total = sum(len(v) for v in all_results.values())
print(f"{GREEN} Всего найдено URL: {total}{RESET}")
for cat, res in all_results.items():
print(f" {YELLOW}{cat}: {len(res)} результатов{RESET}")
def main():
parser = argparse.ArgumentParser(description="Google Dorker - автоматизация
OSINT")
parser.add_argument("-d", "--domain", required=True,
help="Целевой домен (без https://)")
parser.add_argument("-c", "--categories", default="admin,files,sensitive",
help="Категории через запятую:
admin,files,backup,sensitive,login,errors,docs")
parser.add_argument("--delay",
 type=float, default=3.0,
help="Задержка между запросами (сек)")
parser.add_argument("--results",
 type=int, default=5,
help="Результатов на дорк")
parser.add_argument("--list-categories", action="store_true",
help="Показать доступные категории")
args = parser.parse_args()
if args.list_categories:
print(f"{CYAN}Доступные категории:{RESET}")
for cat, dorks in DORKS.items():
print(f" {GREEN}{cat:<12}{RESET} — {len(dorks)} дорков")
sys.exit(0)
categories = [c.strip() for c in args.categories.split(",")]
run_dorks(args.domain, categories, args.delay, args.results)
if __name__ == "__main__":
main()
