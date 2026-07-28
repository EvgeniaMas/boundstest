#!/usr/bin/env python3
importimportimportimportimportimportimportimportimportsocket
ssl
threading
select
re
argparse
time
os
subprocess
from datetime import datetime
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BUFFER_SIZE = 8192
LOG_FILE = None
def log(message: str) -> None:
"""Логируем запросы и ответы."""
timestamp = datetime.now().strftime("%H:%M:%S.%f")[:12]
line = f"[{timestamp}] {message}"
print(line)
if LOG_FILE:
with open(LOG_FILE, "a") as f:
f.write(line + "\n")
def generate_ssl_cert(certfile: str, keyfile: str) -> None:
"""Генерируем самоподписной SSL сертификат для HTTPS перехвата."""
if os.path.exists(certfile) and os.path.exists(keyfile):
return
log(f"{YELLOW}[*] Генерируем SSL сертификат...{RESET}")
subprocess.run([
"openssl", "req", "-new", "-x509",
"-keyout", keyfile,
"-out", certfile,
"-days", "365",
"-nodes", "-subj", "/CN=MITM-Proxy"
], capture_output=True)
def parse_http_request(raw: bytes) -> dict:
"""Парсируем HTTP запрос. Возвращает словарь с method, host, port, path."""
try:
header_end = raw.find(b"\r\n\r\n")
headers_raw = raw[:header_end].decode("utf-8", errors="replace")
lines = headers_raw.split("\r\n")
# Первая строка: METHOD PATH HTTP/1.x
method, path, version = lines[0].split(" ", 2)
# Ищем Host заголовок
host = ""
port = 80
for line in lines[1:]:
if line.lower().startswith("host:"):
host_val = line.split(":", 1)[1].strip()
if ":" in host_val:
host, port = host_val.rsplit(":", 1)
port = int(port)
else:
host = host_val
break
return {
"method": method,
"path": path,
"version": version,
"host": host,
"port": port,
"headers": lines,
"body": raw[header_end + 4:]
}
except Exception:
return {}
def forward_data(src: socket.socket, dst: socket.socket) -> None:
"""Пересылаем данные между двумя сокетами (для HTTPS туннеля)."""
try:
while True:
data = src.recv(BUFFER_SIZE)
if not data:
break
dst.sendall(data)
except Exception:
pass
def handle_https_connect(client_sock: socket.socket, host: str,
port: int, certfile: str, keyfile: str) -> None:
# Подтверждаем CONNECT
client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
# SSL-обёртка клиентского соединения
try:
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile, keyfile)
ssl_client = ctx.wrap_socket(client_sock, server_side=True)
except ssl.SSLError as e:
log(f"{RED}[!] SSL wrap failed: {e}{RESET}")
return
# Подключаемся к реальному серверу
try:
server_sock = socket.create_connection((host, port), timeout=10)
server_ctx = ssl.create_default_context()
server_ctx.check_hostname = False
server_ctx.verify_mode = ssl.CERT_NONE
ssl_server = server_ctx.wrap_socket(server_sock, server_hostname=host)
except Exception as e:
log(f"{RED}[!] Не удалось подключиться к {host}:{port}: {e}{RESET}")
ssl_client.close()
return
# Читаем первый запрос (уже расшифрованный)
try:
raw_request = ssl_client.recv(BUFFER_SIZE * 4)
if raw_request:
req = parse_http_request(raw_request)
log(f"{GREEN}[HTTPS] {req.get('method', '?')} https://{host}{req.get('path',
'/')}{RESET}")
# Логируем заголовки запроса
— 136 —
for line in req.get("headers", [])[1:6]:
if line:
log(f" {CYAN}→ {line}{RESET}")
ssl_server.sendall(raw_request)
# Получаем ответ
response = ssl_server.recv(BUFFER_SIZE * 4)
if response:
# Парсим первую строку ответа
first_line = response.split(b"\r\n")[0].decode("utf-8", errors="ignore")
log(f"{YELLOW} ← {first_line}{RESET}")
ssl_client.sendall(response)
# Продолжаем пересылку оставшихся данных
t1 = threading.Thread(target=forward_data, args=(ssl_client, ssl_server),
daemon=True)
t2 = threading.Thread(target=forward_data, args=(ssl_server, ssl_client),
daemon=True)
t1.start()
t2.start()
t1.join(timeout=30)
t2.join(timeout=30)
except Exception as e:
pass
finally:
try: ssl_client.close()
except: pass
try: ssl_server.close()
except: pass
def handle_http(client_sock: socket.socket, raw_request: bytes) -> None:
req = parse_http_request(raw_request)
if not req or not req.get("host"):
client_sock.close()
return
host = req["host"]
port = req["port"]
log(f"{GREEN}[HTTP] {req['method']} http://{host}{req['path']}{RESET}")
for line in req.get("headers", [])[1:4]:
if line:
log(f" {CYAN}→ {line}{RESET}")
try:
server_sock = socket.create_connection((host, port), timeout=10)
server_sock.sendall(raw_request)
# Получаем ответ
response_parts = []
server_sock.settimeout(5)
while True:
try:
chunk = server_sock.recv(BUFFER_SIZE)
if not chunk:
break
response_parts.append(chunk)
except socket.timeout:
break
response = b"".join(response_parts)
if response:
first_line = response.split(b"\r\n")[0].decode("utf-8", errors="ignore")
log(f"{YELLOW} ← {first_line} ({len(response)} байт){RESET}")
client_sock.sendall(response)
server_sock.close()
except Exception as e:
log(f"{RED}[!] Ошибка подключения к {host}: {e}{RESET}")
finally:
client_sock.close()
def handle_client(client_sock: socket.socket, client_addr: tuple,
certfile: str, keyfile: str) -> None:
"""Обрабатываем одно клиентское соединение."""
try:
raw = client_sock.recv(BUFFER_SIZE * 4)
if not raw:
client_sock.close()
return
first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="ignore")
# CONNECT метод = HTTPS туннель
if first_line.startswith("CONNECT"):
parts = first_line.split()
if len(parts) >= 2:
host_port = parts[1]
if ":" in host_port:
host, port = host_port.rsplit(":", 1)
port = int(port)
else:
host, port = host_port, 443
handle_https_connect(client_sock, host, port, certfile, keyfile)
else:
# Обычный HTTP
handle_http(client_sock, raw)
except Exception as e:
log(f"{RED}[!] handle_client error: {e}{RESET}")
finally:
try: client_sock.close()
except: pass
def main():
global LOG_FILE
parser = argparse.ArgumentParser(description="MITM HTTP/HTTPS Proxy")
parser.add_argument("--port", type=int, default=8080, help="Порт прокси")
parser.add_argument("--host", default="0.0.0.0", help="Адрес прокси")
parser.add_argument("--log", default=None, help="Файл для логов")
parser.add_argument("--cert", default="/tmp/mitm_cert.pem", help="SSL
cert")
parser.add_argument("--key", default="/tmp/mitm_key.pem", help="SSL
key")
args = parser.parse_args()
if args.log:
LOG_FILE = args.log
generate_ssl_cert(args.cert, args.key)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((args.host, args.port))
server.listen(50)
log(f"{CYAN}[*] MITM Proxy запущен на {args.host}:{args.port}{RESET}")
log(f"{YELLOW}[!] Настрой браузер: Прокси → 127.0.0.1:{args.port}{RESET}")
log(f"{YELLOW}[!] Для HTTPS установи сертификат {args.cert} в
браузер{RESET}")
try:
while True:
client_sock, client_addr = server.accept()
t = threading.Thread(
target=handle_client,
args=(client_sock, client_addr, args.cert, args.key),
daemon=True
)
t.start()
except KeyboardInterrupt:
log(f"\n{GREEN}[✓] Прокси остановлен{RESET}")
finally:
server.close()
if __name__ == "__main__":
main()
