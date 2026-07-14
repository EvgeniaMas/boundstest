#!/usr/bin/env python3
import requests
import re
import argparse
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"
# Формат: { "Название": { "headers": [...], "cookies": [...], "html": [...], "paths": [...]
} }
SIGNATURES = {

"WordPress": {
"html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
"headers": [],
"cookies": ["wordpress_", "wp-settings"],
"paths": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
"meta": [r'name=["\']generator["\'][^>]*WordPress ([\d.]+)'],
},
"Joomla": {
"html": [r"/components/com_", r"Joomla"],
"headers": [],
"cookies": ["joomla_"],
"paths": ["/administrator/"],
"meta": [r'name=["\']generator["\'][^>]*Joomla! ([\d.]+)'],
},
"Drupal": {
"html": [r"/sites/default/files/", r"Drupal.settings"],
"headers": ["X-Generator: Drupal"],
"cookies": ["SESS", "SSESS"],
"paths": ["/user/login", "/admin/"],
"meta": [r'name=["\']Generator["\'][^>]*Drupal ([\d.]+)'],
},
"Bitrix": {
"html": [r"/bitrix/", r"BX\."],
"headers": [],
"cookies": ["BITRIX_SM_"],
"paths": ["/bitrix/admin/"],
"meta": [],
},

"PHP": {
"headers": ["X-Powered-By: PHP"],
"cookies": ["PHPSESSID"],
"html": [],
"paths": [],
"meta": [],
},
"ASP.NET": {
"headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"],
"cookies": ["ASP.NET_SessionId", "ASPSESSION"],
"html": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
"paths": [],
"meta": [],
},
"Java/Spring": {
"cookies": ["JSESSIONID"],
"headers": [],
"html": [],
"paths": ["/actuator", "/actuator/health"],
"meta": [],
},

"Laravel": {
"cookies": ["laravel_session", "XSRF-TOKEN"],
"html": [r"laravel"],
"headers": [],
"paths": ["/.env", "/telescope", "/horizon"],
"meta": [],
},
"Django": {
"cookies": ["csrftoken", "sessionid"],
"html": [r"django", r"csrfmiddlewaretoken"],
"headers": [],
"paths": ["/admin/", "/django-admin/"],
"meta": [],
},
"Ruby on Rails": {
"cookies": ["_session_id"],
"html": [r"data-turbo", r"rails-ujs"],
"headers": ["X-Runtime"],
"paths": [],
"meta": [],
},

"React": {
"html": [r"react\.development\.js", r"react\.production\.min\.js",
r"__REACT_", r"data-reactroot"],
"headers": [], "cookies": [], "paths": [], "meta": [],
},
"Angular": {
"html": [r"ng-version", r"angular\.js", r"@angular"],
"headers": [], "cookies": [], "paths": [], "meta": [],
},
"Vue.js": {
"html": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"v-app"],
"headers": [], "cookies": [], "paths": [], "meta": [],
},

"Apache": {
"headers": ["Server: Apache"],
"html": [], "cookies": [], "paths": [], "meta": [],
},
"Nginx": {
"headers": ["Server: nginx"],
"html": [], "cookies": [], "paths": [], "meta": [],
},
"Cloudflare": {
"headers": ["CF-Ray", "CF-Cache-Status", "Server: cloudflare"],
"cookies": ["__cfduid", "cf_clearance"],
"html": [], "paths": [], "meta": [],
},
}
class TechFingerprinter:
def __init__(self, url: str):
self.url = url.rstrip("/")
self.session = requests.Session()
self.session.headers.update({
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
"AppleWebKit/537.36 (KHTML, like Gecko) "
"Chrome/121.0.0.0 Safari/537.36"
})
self.detected = {} # { "Tech": ["причина 1", "причина 2"] }
def _add(self, tech: str, reason: str):
if tech not in self.detected:
self.detected[tech] = []
if reason not in self.detected[tech]:
self.detected[tech].append(reason)
def analyze_response(self, resp: requests.Response) -> None:
"""Анализирует HTTP-ответ на сигнатуры."""
headers_str = str(resp.headers).lower()
cookies_str = " ".join(resp.cookies.keys()).lower()
html
 = resp.text
for tech, sigs in SIGNATURES.items():
# Проверяем заголовки
for h in sigs.get("headers", []):
if h.lower() in headers_str:
self._add(tech, f"Header: {h}")
# Проверяем cookies
for c in sigs.get("cookies", []):
if c.lower() in cookies_str:
self._add(tech, f"Cookie: {c}")
# Проверяем HTML
for pattern in sigs.get("html", []):
if re.search(pattern, html, re.IGNORECASE):
self._add(tech, f"HTML pattern: {pattern}")
# Проверяем мета-теги (с извлечением версии)
for pattern in sigs.get("meta", []):
m = re.search(pattern, html, re.IGNORECASE)
if m:
try:
version = m.group(1)
self._add(tech, f"Meta generator: v{version}")
except IndexError:
self._add(tech, "Meta generator")
30 Python-скриптов для Хакинга
def check_paths(self) -> None:
"""Проверяет наличие характерных путей."""
for tech, sigs in SIGNATURES.items():
for path in sigs.get("paths", []):
url = urljoin(self.url, path)
try:
r = self.session.head(url, timeout=3, verify=False,
allow_redirects=False)
if r.status_code not in (404, 400):
self._add(tech, f"Path exists: {path} [{r.status_code}]")
except Exception:
pass
def check_js_libraries(self, html: str) -> None:
"""Парсит JS-файлы для определения версий библиотек."""
js_patterns = {
"jQuery": r'jquery[.-]?([\d.]+)(?:\.min)?\.js',
"Bootstrap": r'bootstrap[.-]?([\d.]+)(?:\.min)?\.js',
"Lodash": r'lodash[.-]?([\d.]+)(?:\.min)?\.js',
}
for lib, pattern in js_patterns.items():
m = re.search(pattern, html, re.IGNORECASE)
if m:
self._add(lib, f"JS: v{m.group(1)}")
def run(self) -> dict:
print(f"{CYAN}[*] Анализируем: {self.url}{RESET}")
try:
resp = self.session.get(self.url, timeout=10, verify=False)
except requests.RequestException as e:
print(f"{RED}[!] Ошибка запроса: {e}{RESET}")
return {}
print(f"{CYAN}[*] HTTP {resp.status_code} | {len(resp.text)} байт{RESET}")
print("-" * 50)
self.analyze_response(resp)
self.check_js_libraries(resp.text)
print(f"{CYAN}[*] Проверяем характерные пути...{RESET}")
self.check_paths()
return self.detected
def main():
parser = argparse.ArgumentParser(description="Technology Fingerprinter")
parser.add_argument("-u", "--url", required=True, help="Целевой URL")
args = parser.parse_args()
fp = TechFingerprinter(args.url)
detected = fp.run()
if not detected:
print(f"{RED}[!] Технологии не определены{RESET}")
return
print(f"\n{GREEN}{'='*60}")
print(" ОБНАРУЖЕННЫЕ ТЕХНОЛОГИИ")
print(f"{'='*60}{RESET}")
for tech, reasons in sorted(detected.items()):
print(f"\n{GREEN}[+] {tech}{RESET}")
for reason in reasons:
print(f" {YELLOW}→ {reason}{RESET}")
print(f"\n{CYAN}Итого обнаружено: {len(detected)} технологий{RESET}")
if __name__ == "__main__":
main()
