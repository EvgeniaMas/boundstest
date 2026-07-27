#!/usr/bin/env python3
importimportimportimportimportimportimportsocket
struct
argparse
textwrap
sys
os
time
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
RESET = "\033[0m"
# EtherType константы
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
# IP Protocol константы
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
# TCP флаги
TCP_FLAGS = {
0x001: "FIN", 0x002: "SYN", 0x004: "RST",
0x008: "PSH", 0x010: "ACK", 0x020: "URG",
}
packet_count = 0
start_time = time.time()
def format_mac(raw_mac: bytes) -> str:
"""Конвертируем 6 байт в строку XX:XX:XX:XX:XX:XX."""
return ":".join(f"{b:02x}" for b in raw_mac)
def parse_ethernet(raw: bytes) -> tuple[str, str, int, bytes]:
dst_mac = format_mac(raw[:6])
src_mac = format_mac(raw[6:12])
ethertype = struct.unpack("!H", raw[12:14])[0]
return (dst_mac, src_mac, ethertype, raw[14:])
def parse_ipv4(raw: bytes) -> dict:
# Первый байт: версия (старшие 4 бита) и IHL (младшие 4 бита)
version_ihl = raw[0]
version = version_ihl >> 4
ihl = (version_ihl & 0x0F) * 4 # IHL в 32-битных словах → в байтах
# Распаковываем: TTL, Protocol, Src IP, Dst IP
ttl, proto = struct.unpack("!BB", raw[8:10])
src_ip = socket.inet_ntoa(raw[12:16])
dst_ip = socket.inet_ntoa(raw[16:20])
total_len = struct.unpack("!H", raw[2:4])[0]
return {
"version": version,
"ihl":
 ihl,
"ttl":
 ttl,
"proto": proto,
"src":
 src_ip,
"dst":
 dst_ip,
"total_len": total_len,
"payload": raw[ihl:] # Данные начинаются после заголовка
}
def parse_tcp(raw: bytes) -> dict:
src_port, dst_port = struct.unpack("!HH", raw[0:4])
seq = struct.unpack("!I", raw[4:8])[0]
ack = struct.unpack("!I", raw[8:12])[0]
# Data offset (старшие 4 бита байта 12) — размер заголовка в 32-битных
словах
data_offset = (raw[12] >> 4) * 4
# Флаги: 9 бит (байты 12-13), берём только младшие 9 бит
flags_raw = struct.unpack("!H", raw[12:14])[0] & 0x01FF
flags_str = " ".join(name for bit, name in TCP_FLAGS.items()
if flags_raw & bit)
window = struct.unpack("!H", raw[14:16])[0]
return {
"sport":
 src_port,
"dport":
 dst_port,
"seq":
 seq,
"ack":
 ack,
"flags":
 flags_str,
"flags_raw": flags_raw,
"window": window,
"data_offset": data_offset,
"payload": raw[data_offset:]
}
def parse_udp(raw: bytes) -> dict:
"""UDP заголовок: Src Port, Dst Port, Length, Checksum (всего 8 байт)."""
src_port, dst_port, length = struct.unpack("!HHH", raw[0:6])
return {
"sport": src_port,
"dport": dst_port,
"length": length,
"payload": raw[8:]
}
def parse_icmp(raw: bytes) -> dict:
"""ICMP: Type (1 байт) + Code (1 байт) + Checksum (2 байта)."""
icmp_type, icmp_code = struct.unpack("!BB", raw[0:2])
icmp_types = {
0: "Echo Reply", 3: "Dest Unreachable",
8: "Echo Request", 11: "Time Exceeded"
}
type_name = icmp_types.get(icmp_type, f"Type {icmp_type}")
return {"type": icmp_type, "code": icmp_code, "name": type_name}
def extract_http(payload: bytes) -> str | None:
"""Извлекаем HTTP данные из TCP payload."""
try:
text = payload.decode("utf-8", errors="ignore")
if text.startswith(("GET", "POST", "PUT", "DELETE", "HEAD",
"HTTP/1.", "HTTP/2")):
# Берём первые несколько строк
lines = text.split("\r\n")
return "\n".join(f" {l}" for l in lines[:8] if l)
except Exception:
pass
return None
def print_packet(eth: tuple, ip: dict, transport: dict, proto_name: str,
show_payload: bool = True) -> None:
"""Форматированный вывод пакета."""
global packet_count
packet_count += 1
dst_mac, src_mac, ethertype, _ = eth
elapsed = time.time() - start_time
# Цвет по протоколу
color = {
"TCP": GREEN,
"UDP": CYAN,
"ICMP": YELLOW,
}.get(proto_name, RESET)
print(f"{color}[#{packet_count:05d}] [{elapsed:8.2f}s] {proto_name:<4} "
f"{ip['src']}:{transport.get('sport', 0)} → "
f"{ip['dst']}:{transport.get('dport', 0)} "
f"| TTL={ip['ttl']} | ", end="")
if proto_name == "TCP":
print(f"Flags=[{transport['flags']}] Seq={transport['seq']} "
f"Win={transport['window']}{RESET}")
elif proto_name == "UDP":
print(f"Len={transport['length']}{RESET}")
elif proto_name == "ICMP":
print(f"{transport['name']}{RESET}")
else:
print(f"{RESET}")
# HTTP payload
if show_payload and proto_name == "TCP":
payload = transport.get("payload", b"")
if payload:
http = extract_http(payload)
if http:
print(f"{BLUE} [HTTP]\n{http}{RESET}")
def main():
parser = argparse.ArgumentParser(description="Raw Packet Sniffer")
parser.add_argument("-i", "--iface", default="eth0", help="Интерфейс")
parser.add_argument("--filter",
 default="all",
choices=["all", "tcp", "udp", "icmp", "http"],
help="Фильтр протокола")
parser.add_argument("--port",
 type=int, default=None,
help="Фильтр по порту")
parser.add_argument("--host",
 default=None,
help="Фильтр по IP адресу")
parser.add_argument("--count",
 type=int, default=0,
help="Остановить после N пакетов (0 = бесконечно)")
parser.add_argument("--no-payload", action="store_true",
help="Не показывать payload")
args = parser.parse_args()
if os.geteuid() != 0:
print(f"{RED}[!] Нужен root для AF_PACKET{RESET}")
sys.exit(1)
# Создаём raw socket — принимаем ВСЕ пакеты интерфейса
try:
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
socket.htons(0x0003))
s.bind((args.iface, 0))
except PermissionError:
print(f"{RED}[!] Нет прав для raw socket{RESET}")
sys.exit(1)
print(f"{CYAN}[*] Raw Packet Sniffer | iface: {args.iface} | "
f"filter: {args.filter}{RESET}")
print(f"{CYAN}[*] Нажми Ctrl+C для остановки{RESET}")
print("-" * 80)
try:
while True:
raw_data, _ = s.recvfrom(65535)
# Парсим Ethernet
dst_mac, src_mac, ethertype, eth_payload = parse_ethernet(raw_data)
if ethertype != ETH_IPV4:
continue # Пропускаем не-IPv4
# Парсим IP
ip = parse_ipv4(eth_payload)
# Применяем фильтр по хосту
if args.host and args.host not in (ip["src"], ip["dst"]):
continue
proto = ip["proto"]
transport = {}
proto_name = "OTHER"
if proto == PROTO_TCP:
proto_name = "TCP"
transport = parse_tcp(ip["payload"])
elif proto == PROTO_UDP:
proto_name = "UDP"
transport = parse_udp(ip["payload"])
elif proto == PROTO_ICMP:
proto_name = "ICMP"
transport = parse_icmp(ip["payload"])
transport["sport"] = 0
transport["dport"] = 0
else:
continue
# Применяем фильтры
if args.filter == "http":
if proto_name != "TCP" or transport.get("dport") not in (80, 8080):
if transport.get("sport") not in (80, 8080):
continue
elif args.filter != "all" and proto_name.lower() != args.filter:
continue
if args.port:
if (transport.get("sport") != args.port and
transport.get("dport") != args.port):
continue
print_packet((dst_mac, src_mac, ethertype, eth_payload),
ip, transport, proto_name,
not args.no_payload)
if args.count and packet_count >= args.count:
break
except KeyboardInterrupt:
print(f"\n{GREEN}[✓] Захвачено пакетов: {packet_count}{RESET}")
finally:
s.close()
if __name__ == "__main__":
main()
