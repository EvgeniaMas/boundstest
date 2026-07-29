#!/usr/bin/env python3
importimportimportimportsocket
struct
argparse
sys
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
SMB_PORT = 445
# SMB Command коды
SMB_COM_NEGOTIATE
 = 0x72
SMB_COM_SESSION_SETUP = 0x73
SMB_COM_TREE_CONNECT = 0x75
SMB_COM_TRANSACTION2 = 0x32
# NetBIOS Session Service заголовок (4 байта предшествует SMB)
def netbios_header(length: int) -> bytes:
"""Добавляем NetBIOS Session Service заголовок."""
return struct.pack(">I", length) # 4 байта big-endian длина
def smb_header(command: int, flags2: int = 0xC807,
pid: int = 0xFEFF, uid: int = 0,
tid: int = 0, mid: int = 1) -> bytes:
return struct.pack(
"<4sBIBH2s8s2sHHHH",
b"\xffSMB", # Protocol identifier
command, # SMB command
0,
 # Status: Success
0x18,
 # Flags: PATH_NAMES_CASELESS | CANONICALIZED_PATHS
flags2, # Flags2
b"\x00\x00", # PID High
— 143 —
30 Python-скриптов для Хакинга
)
b"\x00" * 8, # SecurityFeatures (encryption key / response)
b"\x00\x00", # Reserved
tid,
 # TreeID
pid,
 # ProcessID
uid,
 # UserID
mid,
 # MultiplexID
def negotiate_request() -> bytes:
dialects = [
b"\x02NT LM 0.12\x00", # NTLM
b"\x02SMB 2.002\x00",
 # SMB2
b"\x02SMB 2.???\x00",
 # SMB2 wildcard
]
dialect_bytes = b"".join(dialects)
# WordCount=0, ByteCount=len(dialects)
smb_params = struct.pack("<BH", 0, len(dialect_bytes))
payload = smb_params + dialect_bytes
header = smb_header(SMB_COM_NEGOTIATE)
nb_hdr = netbios_header(len(header) + len(payload))
return nb_hdr + header + payload
def session_setup_request(uid: int = 0) -> bytes:
# Extended Security = 0, анонимная аутентификация
account = b"\x00" # Anonymous/Guest
password = b"\x00" # Пустой пароль
domain = b"WORKGROUP\x00".upper()
os_name = b"Unix\x00"
lanman = b"Samba\x00"
security_blob = b"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02" # SPNEGO OID
(упрощённо)
# Параметры
word_count = 13
max_buffer = 65535
max_mpx = 2
vc_number = 1
session_key = 0
capabilities= 0x80000054 # Unicode, NT Status, NT Find, Ext Security
params = struct.pack(
"<BHHHHIHHI",
word_count,
0xFF,
 # AndXCommand: None
0,
 # AndXOffset
max_buffer,
max_mpx,
vc_number,
session_key,
len(security_blob),
0,
 # Reserved
)
params += struct.pack("<IH", capabilities, 0) # Capabilities + ByteCount
placeholder
byte_count = len(security_blob) + len(os_name) + len(lanman) + len(domain)
params = params[:-2] + struct.pack("<H", byte_count)
data = security_blob + os_name + lanman + domain
payload = params + data
header = smb_header(SMB_COM_SESSION_SETUP, uid=uid)
nb_hdr = netbios_header(len(header) + len(payload))
return nb_hdr + header + payload
def tree_connect_request(uid: int, share_path: bytes) -> bytes:
service = b"IPC\x00"
word_count = 4
flags = 0x0008 # Extended Response
password = b"\x00" # Null password
path = share_path + b"\x00" # \\server\IPC$
byte_count = len(password) + len(path) + len(service)
params = struct.pack(
"<BHHHHH",
word_count,
0xFF,
 # AndXCommand: None
0,
 # AndXOffset
flags,
len(password),
byte_count,
)
data = password + path + service
payload = params + data
header = smb_header(SMB_COM_TREE_CONNECT, uid=uid)
nb_hdr = netbios_header(len(header) + len(payload))
return nb_hdr + header + payload
def send_recv(sock: socket.socket, data: bytes) -> bytes:
sock.sendall(data)
# Читаем NetBIOS заголовок (4 байта) для получения размера
nb_hdr = sock.recv(4)
if len(nb_hdr) < 4:
return b""
length = struct.unpack(">I", nb_hdr)[0]
# Читаем весь пакет
data = b""
while len(data) < length:
chunk = sock.recv(length - len(data))
if not chunk:
break
data += chunk
return data
def parse_smb_status(response: bytes) -> int:
"""Извлекаем NT Status из SMB ответа."""
if len(response) < 8:
return -1
# Status находится в байтах 4-8 SMB заголовка (5-9 в ответе без NetBIOS)
status = struct.unpack("<I", response[4:8])[0]
return status
def enumerate_shares_via_rpc(sock: socket.socket, target: str,
uid: int, tid: int) -> list[str]:
shares = []
# Для полной реализации нужен DCERPC over SMB
# Упрощённо: пробуем подключиться к типичным расшаренным именам
common_shares = [
"ADMIN$", "C$", "D$", "IPC$", "SYSVOL", "NETLOGON",
"print$", "public", "shared", "backup", "data",
"Users", "Documents", "homes",
]
for share in common_shares:
# Пробуем Tree Connect к каждой шаре
path = f"\\\\{target}\\{share}".encode("utf-16-le")
try:
tree_req = tree_connect_request(uid, path)
response = send_recv(sock, tree_req)
if response:
status = parse_smb_status(response)
if status == 0x00000000: # STATUS_SUCCESS
shares.append((share, "ACCESSIBLE"))
elif status == 0xC0000022: # ACCESS_DENIED — шара существует!
shares.append((share, "EXISTS (Access Denied)"))
elif status == 0xC00000CC: # BAD_NETWORK_NAME — не существует
pass
except Exception:
pass
return shares
def smb_enum(target: str, port: int = SMB_PORT, timeout: int = 5) -> None:
"""Основная функция перечисления SMB."""
print(f"{CYAN}[*] SMB Enumeration → {target}:{port}{RESET}")
print("-" * 50)
try:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(timeout)
sock.connect((target, port))
print(f"{GREEN}[+] Подключились к {target}:{port}{RESET}")
except Exception as e:
print(f"{RED}[!] Не удалось подключиться: {e}{RESET}")
return
try:
# 1. Negotiate
print(f"{CYAN}[*] SMB Negotiate...{RESET}")
neg_req = negotiate_request()
neg_resp = send_recv(sock, neg_req)
if not neg_resp:
print(f"{RED}[!] Нет ответа на Negotiate{RESET}")
return
status = parse_smb_status(neg_resp)
# Определяем диалект из ответа
dialect = struct.unpack("<H", neg_resp[36:38])[0] if len(neg_resp) > 38 else -1
print(f"{GREEN}[+] Negotiate OK | Status: 0x{status:08x} | "
f"Dialect index: {dialect}{RESET}")
# Извлекаем challenge для NTLM (если SMB1)
if len(neg_resp) > 50:
# Байты 48-56 обычно содержат challenge
pass
# 2. Session Setup (анонимный)
print(f"{CYAN}[*] Session Setup (Anonymous)...{RESET}")
setup_req = session_setup_request()
setup_resp = send_recv(sock, setup_req)
setup_status = parse_smb_status(setup_resp) if setup_resp else -1
uid = 0
if setup_resp and len(setup_resp) > 28:
uid = struct.unpack("<H", setup_resp[28:30])[0]
if setup_status in (0, 0xC000006D): # Success или Logon Failure
print(f"{GREEN}[+] Session Setup | UID: {uid} | "
f"Status: 0x{setup_status:08x}{RESET}")
else:
print(f"{YELLOW}[?] Session Setup status: 0x{setup_status:08x}{RESET}")
# 3. Перечисляем шары
print(f"\n{CYAN}[*] Перечисляем расшаренные ресурсы...{RESET}")
shares = enumerate_shares_via_rpc(sock, target, uid, 0)
if shares:
print(f"\n{GREEN}Найдено расшаренных ресурсов: {len(shares)}{RESET}")
for share, access in shares:
access_color = GREEN if "ACCESSIBLE" in access else YELLOW
print(f" {access_color}[+] \\\\{target}\\{share:<20} → {access}{RESET}")
else:
print(f"{RED}[-] Расшаренные ресурсы не найдены или
недоступны{RESET}")
# Советы
print(f"\n{YELLOW}[!] Попробуй impacket для более полного
перечисления:{RESET}")
print(f" smbclient -L //{target}/ -N")
print(f" nmap --script smb-enum-shares -p445 {target}")
print(f" crackmapexec smb {target} --shares")
except Exception as e:
print(f"{RED}[!] Ошибка: {e}{RESET}")
finally:
sock.close()
def main():
parser = argparse.ArgumentParser(description="SMB Enumerator (raw sockets)")
parser.add_argument("-t", "--target", required=True, help="IP или hostname")
parser.add_argument("-p", "--port", type=int, default=SMB_PORT,
help=f"SMB порт (по умолчанию {SMB_PORT})")
parser.add_argument("--timeout",
 type=int, default=5)
args = parser.parse_args()
smb_enum(args.target, args.port, args.timeout)
if __name__ == "__main__":
main()
