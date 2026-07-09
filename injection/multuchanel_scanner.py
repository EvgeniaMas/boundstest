import threading
def scan_port(host, port):
try:
s = socket.socket()
s.settimeout(0.5)
s.connect((host, port))
print(f"[+] {port} OPEN")
s.close()
except:
pass
threads = []
for port in range(1, 1001):
t = threading.Thread(target=scan_port, args=("target.com", port))
threads.append(t)
t.start()
