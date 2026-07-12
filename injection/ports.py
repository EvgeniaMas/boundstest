#!/usr/bin/env python3
importimportimportimportargparse
sys
threading
time
import random
from queue import Queue
from scapy.all import IP, TCP, sr1, conf
30 Python-скриптов для Хакинга
# Отключаем вывод scapy
conf.verb = 0
SYN = 0x002 # Synchronize
ACK = 0x010 # Acknowledge
SYN_ACK = 0x012 # SYN + ACK
RST = 0x004 # Reset
RST_ACK = 0x014 # RST + ACK
FIN = 0x001 # Finish
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
open_ports = []
filtered_ports = []
lock = threading.Lock()
def syn_scan_port(target_ip: str, port: int, timeout: float) -> str:
"""
Отправляет SYN пакет на порт и анализирует ответ.
Возвращает: 'open', 'closed', 'filtered'
"""
# Собираем SYN пакет: случайный src port чтобы не конфликтовать с ОС
src_port = random.randint(1024, 65535)
pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")
# Отправляем и ждём один ответ
response = sr1(pkt, timeout=timeout, verbose=False)
if response is None:
return "filtered"
if response.haslayer(TCP):
flags = response.getlayer(TCP).flags
if flags == SYN_ACK:
# Порт открыт — отправляем RST чтобы завершить "half-open"
rst_pkt = IP(dst=target_ip) / TCP(
sport=src_port, dport=port, flags="R"
)
sr1(rst_pkt, timeout=1, verbose=False)
return "open"
elif flags in (RST, RST_ACK):
return "closed"
# ICMP unreachable = фильтруется
if response.haslayer("ICMP"):
icmp_type = response.getlayer("ICMP").type
if icmp_type == 3: # Destination Unreachable
return "filtered"
return "unknown"
def worker(target_ip: str, port_queue: Queue, timeout: float,
show_closed: bool) -> None:
"""Worker-поток: берёт порт из очереди и сканирует."""
while not port_queue.empty():
try:
port = port_queue.get_nowait()
except Exception:
break
status = syn_scan_port(target_ip, port, timeout)
with lock:
if status == "open":
service = get_service_name(port)
print(f"{GREEN}[+] {port:<6}/tcp OPEN
open_ports.append(port)
elif status == "filtered":
{service}{RESET}")
filtered_ports.append(port)
if show_closed:
print(f"{YELLOW}[?] {port:<6}/tcp FILTERED{RESET}")
elif status == "closed" and show_closed:
print(f"{RED}[-] {port:<6}/tcp closed{RESET}")
port_queue.task_done()
def parse_port_range(port_str: str) -> list[int]:
"""Парсит строку портов: '80', '80,443', '1-1024', '22,80,443,8080-8090'."""
ports = []
for part in port_str.split(","):
part = part.strip()
if "-" in part:
start, end = part.split("-")
ports.extend(range(int(start), int(end) + 1))
else:
ports.append(int(part))
return sorted(set(ports))
def get_service_name(port: int) -> str:
"""Возвращает известное имя сервиса для порта."""
services = {
21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
53: "dns", 80: "http", 110: "pop3", 143: "imap",
443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
1433: "mssql", 3306: "mysql", 3389: "rdp",
5432: "postgresql", 5900: "vnc", 6379: "redis",
8080: "http-alt", 8443: "https-alt", 27017: "mongodb"
}
return services.get(port, "unknown")
# Таблица скоростей (timeout, threads)
TIMING = {
1: (2.0, 10), # Paranoid
2: (1.5, 25), # Sneaky
3: (1.0, 50), # Normal
4: (0.5, 100), # Aggressive
5: (0.2, 200), # Insane
}
def main():
parser = argparse.ArgumentParser(description="SYN Port Scanner (requires root)")
parser.add_argument("-t", "--target", required=True, help="IP цели")
parser.add_argument("-p", "--ports",
 default="1-1024",
help="Диапазон портов: 80 | 80,443 | 1-65535")
parser.add_argument("-T", "--timing", type=int, default=3, choices=[1,2,3,4,5],
help="Скорость сканирования 1-5 (3=normal)")
parser.add_argument("--show-closed",
 action="store_true",
help="Показывать закрытые и фильтруемые порты")
args = parser.parse_args()
# Проверяем root
import os
if os.geteuid() != 0:
print(f"{RED}[!] Нужны права root для raw sockets{RESET}")
sys.exit(1)
timeout, num_threads = TIMING[args.timing]
ports = parse_port_range(args.ports)
print(f"{CYAN}[*] Цель: {args.target}{RESET}")
print(f"{CYAN}[*] Портов: {len(ports)}{RESET}")
print(f"{CYAN}[*] Режим: T{args.timing} | timeout={timeout}s |
threads={num_threads}{RESET}")
print(f"{CYAN}[*] Метод: SYN (half-open){RESET}")
print("-" * 50)
start_time = time.time()
# Заполняем очередь
port_queue: Queue = Queue()
for p in ports:
port_queue.put(p)
# Запускаем потоки
threads = []
for _ in range(min(num_threads, len(ports))):
t = threading.Thread(
target=worker,
args=(args.target, port_queue, timeout, args.show_closed),
daemon=True
)
t.start()
threads.append(t)
for t in threads:
t.join()
elapsed = time.time() - start_time
print("-" * 50)
print(f"{GREEN}[✓] Открытых портов: {len(open_ports)}{RESET}")
print(f"{YELLOW}[✓] Отфильтровано: {len(filtered_ports)}{RESET}")
print(f"{CYAN}[✓] Время:
 {elapsed:.2f}s{RESET}")
if open_ports:
print(f"\n{GREEN}Открытые порты: {', '.join(map(str,
sorted(open_ports)))}{RESET}")
if __name__ == "__main__":
main()
