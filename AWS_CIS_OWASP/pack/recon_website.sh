#!/usr/bin/env bash
# recon_website.sh — Ubuntu 22.04 LTS website & security reconnaissance
# SAFE: strictly read-only. No writes outside of its own log directory.
# OUTPUTS: evidence bundle + tiny-gap-summary.json + inventory.json
# OPTIONS: --fast (skip heavier checks), --output-dir <path>

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------
# Helpers
# -----------------------------
msg() { printf '%s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fatal() { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || fatal "Run as root (sudo)."; }
now() { date +"%Y%m%d-%H%M%S"; }
json_escape() { python3 - <<'PY' 2>/dev/null || sed 's/"/\\"/g'
import json,sys
print(json.dumps(sys.stdin.read().rstrip("\n")))
PY
}
cmd_ok() { command -v "$1" >/dev/null 2>&1; }

# -----------------------------
# Args
# -----------------------------
FAST=0
OUT_BASE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast) FAST=1; shift;;
    --output-dir) OUT_BASE="$2"; shift 2;;
    *) fatal "Unknown arg: $1";;
  esac
done

# -----------------------------
# Prep
# -----------------------------
require_root
TS="$(now)"
BASE_DEFAULT="/var/log/website_hardening/RECON-$TS"
BASE="${OUT_BASE:-$BASE_DEFAULT}"
mkdir -p "$BASE"/{sys,web,sec,aws,pkgs,net,auth}
chmod 0750 "$BASE"
msg "[+] Recon bundle: $BASE"

# -----------------------------
# 1) System & packages
# -----------------------------
{
  uname -a || true
  printf '\n[os-release]\n'; cat /etc/os-release 2>/dev/null || true
  printf '\n[lsb_release]\n'; lsb_release -a 2>/dev/null || true
  printf '\n[hostnamectl]\n'; hostnamectl 2>/dev/null || true
} >"$BASE/sys/system.txt"

dpkg -l >"$BASE/pkgs/dpkg-list.txt" 2>/dev/null || true

# CIS-relevant kernel params (read-only)
{
  for k in \
    net.ipv4.ip_forward \
    net.ipv4.conf.all.send_redirects \
    net.ipv4.conf.default.send_redirects \
    net.ipv4.conf.all.accept_source_route \
    net.ipv4.conf.default.accept_source_route \
    net.ipv4.conf.all.accept_redirects \
    net.ipv4.conf.default.accept_redirects \
    net.ipv4.conf.all.log_martians \
    net.ipv6.conf.all.accept_redirects \
    net.ipv6.conf.default.accept_redirects; do
    printf '%s=' "$k"; sysctl -n "$k" 2>/dev/null || echo "<unavailable>"
  done
} >"$BASE/sys/cis-kernel-network.txt"

# -----------------------------
# 2) Web stack discovery
# -----------------------------
WEB_STACK="unknown"
APACHE=0; NGINX=0
if cmd_ok apache2 || [[ -x /usr/sbin/apache2 ]]; then APACHE=1; WEB_STACK="apache"; fi
if cmd_ok nginx; then NGINX=1; WEB_STACK=$([[ $WEB_STACK == apache ]] && echo "apache+nginx" || echo "nginx"); fi

# Versions & enabled modules (no secrets)
if [[ $APACHE -eq 1 ]]; then
  (apache2 -v || /usr/sbin/apache2 -v || true) >"$BASE/web/apache-version.txt" 2>&1 || true
  apachectl -M >"$BASE/web/apache-modules.txt" 2>/dev/null || true
  cp -a /etc/apache2/apache2.conf "$BASE/web/apache2.conf" 2>/dev/null || true
  if [[ -d /etc/apache2/sites-enabled ]]; then
    awk '/DocumentRoot/ {print $2}' /etc/apache2/sites-enabled/* 2>/dev/null \
      | sort -u >"$BASE/web/apache-document-roots.txt" || true
  fi
fi

if [[ $NGINX -eq 1 ]]; then
  nginx -v >"$BASE/web/nginx-version.txt" 2>&1 || true
  nginx -T >"$BASE/web/nginx-conf-dump.txt" 2>/dev/null || true
  # Extract roots (no sed backrefs to avoid editor issues)
  grep -RIs "^[[:space:]]*root[[:space:]]\\+" /etc/nginx 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="root"){print $(i+1)}}' \
    | tr -d ';' | sort -u >"$BASE/web/nginx-roots.txt" || true
fi

# PHP inventory (only paths; no content copied)
(php -v || true) >"$BASE/web/php-version.txt" 2>&1 || true
find /etc/php -type f -name php.ini 2>/dev/null | sort >"$BASE/web/php-ini-paths.txt" || true

# Derive web roots (fallback)
WEB_ROOTS=( )
[[ -f "$BASE/web/apache-document-roots.txt" ]] && mapfile -t AR <"$BASE/web/apache-document-roots.txt" || AR=()
[[ -f "$BASE/web/nginx-roots.txt" ]] && mapfile -t NR <"$BASE/web/nginx-roots.txt" || NR=()
WEB_ROOTS=(${AR[@]:-} ${NR[@]:-})
[[ ${#WEB_ROOTS[@]} -eq 0 ]] && WEB_ROOTS=("/var/www/html")
printf '%s\n' "${WEB_ROOTS[@]}" | sort -u >"$BASE/web/web-roots.txt"

# Per-root quick checks (bounded depth; no secrets)
mkdir -p "$BASE/web/roots"
for root in "${WEB_ROOTS[@]}"; do
  R="${root%/}"
  SAFE_NAME=$(echo "$R" | tr '/ ' '__')
  {
    printf '[ROOT] %s\n' "$R"
    printf '\n[Perms]\n'; stat -c '%A %U:%G %n' "$R" 2>/dev/null || true
    printf '\n[.htaccess & .user.ini]\n'; find "$R" -maxdepth 2 -type f \( -name '.htaccess' -o -name '.user.ini' \) 2>/dev/null
    printf '\n[World-writable files]\n'; find "$R" -xdev -type f -perm -0002 2>/dev/null | head -n 200
    printf '\n[Dangerous extensions]\n'; find "$R" -xdev -type f \( -name '*.phar' -o -name '*.phtml' \) 2>/dev/null | head -n 200
    printf '\n[Git/SVN artifacts]\n'; find "$R" -xdev -type d \( -name '.git' -o -name '.svn' \) -prune -print 2>/dev/null | head -n 50
  } >"$BASE/web/roots/${SAFE_NAME}.txt"
done

# TLS/Certs — list paths only, never copy private keys
{
  printf '[Certificates]\n'
  find /etc -type f \( -name '*.crt' -o -name 'fullchain*' -o -name '*.pem' \) 2>/dev/null \
    | grep -viE '/private/|\.key$' | sort
  printf '\n[Private key paths (names only)]\n'
  find /etc -type f -name '*.key' 2>/dev/null | sed 's/$/ (NOT COPIED)/' | sort
} >"$BASE/web/tls-locations.txt"

# Security headers presence (grep-only hints)
SEC_HDRS_APACHE=$(grep -RIn "Header[[:space:]]\\+always\\?\\s\\+set\\|Header[[:space:]]\\+set" /etc/apache2 2>/dev/null | wc -l || echo 0)
SEC_HDRS_NGINX=$(grep -RIn "add_header[[:space:]]\\+" /etc/nginx 2>/dev/null | wc -l || echo 0)

# -----------------------------
# 3) Security stack state
# -----------------------------
{
  printf '=== ufw ===\n'; ufw status verbose 2>/dev/null || echo 'ufw not present'
  printf '\n=== nft list ruleset ===\n'; nft list ruleset 2>/dev/null || echo 'nftables not present'
  printf '\n=== iptables -S ===\n'; iptables -S 2>/dev/null || echo 'iptables not present'
  printf '\n=== ip6tables -S ===\n'; ip6tables -S 2>/dev/null || echo 'ip6tables not present'
} >"$BASE/sec/firewall.txt"

(fail2ban-client status 2>&1; for j in /etc/fail2ban/jail*.local; do [[ -f "$j" ]] && { echo "--- $j"; sed 's/.*/&/g' "$j"; }; done) >"$BASE/sec/fail2ban.txt" 2>&1 || true
(apparmor_status 2>&1 || true; aa-status 2>&1 || true) >"$BASE/sec/apparmor.txt" || true
(systemctl status auditd 2>&1 || true; grep -RIn "-w /var/log" /etc/audit/ 2>/dev/null || true) >"$BASE/sec/auditd.txt"

# SSH snapshot (no secrets)
{
  printf 'Active sshd units:\n'; systemctl status ssh 2>/dev/null | head -n 30 || true
  printf '\nEffective config includes:\n'; ls -1 /etc/ssh/sshd_config{,.d/*.conf} 2>/dev/null || true
  printf '\nKey options (grep):\n'; egrep -i '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|KbdInteractiveAuthentication|MaxAuthTries|PermitEmptyPasswords)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
} >"$BASE/auth/ssh.txt"

# Accounts quick audit
{
  printf '[Users with uid<1000 and real shells]\n'
  awk -F: '($3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false"){print $1":"$7}' /etc/passwd
  printf '\n[Passwordless sudo matches]\n'; grep -RIn "NOPASSWD" /etc/sudoers* 2>/dev/null || true
} >"$BASE/auth/accounts.txt"

# Listening sockets
(ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true) >"$BASE/net/listening.txt"

# SUID/SGID summary (FAST mode: counts only)
if [[ $FAST -eq 1 ]]; then
  {
    printf 'SUID count: '; find / -xdev -perm -4000 -type f 2>/dev/null | wc -l
    printf 'SGID count: '; find / -xdev -perm -2000 -type f 2>/dev/null | wc -l
  } >"$BASE/sec/suid_sgid.txt"
else
  {
    printf '[SUID files]\n'; find / -xdev -perm -4000 -type f 2>/dev/null | sort | head -n 400
    printf '\n[SGID files]\n'; find / -xdev -perm -2000 -type f 2>/dev/null | sort | head -n 400
  } >"$BASE/sec/suid_sgid.txt"
fi

# Cron & systemd timers
(crontab -l 2>/dev/null || true; ls -1 /etc/cron.{hourly,daily,weekly,monthly} 2>/dev/null || true) >"$BASE/sys/cron.txt"
(systemctl list-timers --all 2>/dev/null || true) >"$BASE/sys/timers.txt"

# -----------------------------
# 4) AWS IMDSv2 (best effort)
# -----------------------------
AWS_META="unknown"
IMDS_TOKEN=""
if cmd_ok curl; then
  IMDS_TOKEN=$(curl -s --max-time 1 -H "X-aws-ec2-metadata-token-ttl-seconds: 60" -X PUT http://169.254.169.254/latest/api/token || true)
  if [[ -n "$IMDS_TOKEN" ]]; then
    IID=$(curl -s --max-time 1 -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-id || true)
    AZ=$(curl -s --max-time 1 -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone || true)
    SG=$(curl -s --max-time 1 -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/security-groups || true)
    AWS_META="instance=$IID, az=$AZ, sgs=$SG"
  fi
fi
printf '%s\n' "$AWS_META" >"$BASE/aws/metadata.txt"

# -----------------------------
# 5) JSON outputs
# -----------------------------
TINY="$BASE/tiny-gap-summary.json"
INV="$BASE/inventory.json"
OSREL=$(tr -d '\r' </etc/os-release 2>/dev/null | sed ':a;N;$!ba;s/\n/; /g' || echo 'unknown')
KERN=$(uname -r)
UFWS="$(ufw status 2>/dev/null | head -n1 | tr -s ' ')"
AA_PRESENT=$([[ -x "$(command -v apparmor_status || true)" ]] && echo true || echo false)
AUDITD_ACTIVE=$([[ "$(systemctl is-active auditd 2>/dev/null || echo inactive)" == active ]] && echo true || echo false)
UNATT_PRESENT=$([[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] && echo true || echo false)

# Tiny JSON (no jq requirement)
{
  printf '{\n'
  printf '  "timestamp": "%s",\n' "$TS"
  printf '  "os_release": %s,\n' "$(printf '%s' "$OSREL" | json_escape)"
  printf '  "kernel": %s,\n' "$(printf '%s' "$KERN" | json_escape)"
  printf '  "web_server": %s,\n' "$(printf '%s' "$WEB_STACK" | json_escape)"
  printf '  "web_roots": ['
  i=0; while read -r r; do [[ -z "$r" ]] && continue; [[ $i -gt 0 ]] && printf ','; printf '%s' "$(printf '%s' "$r" | json_escape)"; i=$((i+1)); done <"$BASE/web/web-roots.txt"
  printf '],\n'
  printf '  "php_ini_paths_count": %s,\n' "$(wc -l <"$BASE/web/php-ini-paths.txt" 2>/dev/null || echo 0)"
  printf '  "security_headers_hint": {"apache_matches": %s, "nginx_matches": %s},\n' "$SEC_HDRS_APACHE" "$SEC_HDRS_NGINX"
  printf '  "firewall": {"ufw_status": %s},\n' "$(printf '%s' "$UFWS" | json_escape)"
  printf '  "apparmor_present": %s,\n' "$AA_PRESENT"
  printf '  "auditd_active": %s,\n' "$AUDITD_ACTIVE"
  printf '  "unattended_upgrades_present": %s,\n' "$UNATT_PRESENT"
  printf '  "aws_metadata": %s\n' "$(printf '%s' "$AWS_META" | json_escape)"
  printf '}\n'
} >"$TINY"

# Rich inventory JSON (paths to evidence files)
{
  printf '{\n'
  printf '  "timestamp": "%s",\n' "$TS"
  printf '  "system": {"os_release": %s, "kernel": %s},\n' "$(printf '%s' "$OSREL" | json_escape)" "$(printf '%s' "$KERN" | json_escape)"
  printf '  "web": {"stack": %s, "roots_file": %s},\n' "$(printf '%s' "$WEB_STACK" | json_escape)" "$(printf '%s' "$BASE/web/web-roots.txt" | json_escape)"
  printf '  "security": {"ufw_file": %s, "fail2ban_file": %s, "apparmor_file": %s, "auditd_file": %s},\n' \
    "$(printf '%s' "$BASE/sec/firewall.txt" | json_escape)" \
    "$(printf '%s' "$BASE/sec/fail2ban.txt" | json_escape)" \
    "$(printf '%s' "$BASE/sec/apparmor.txt" | json_escape)" \
    "$(printf '%s' "$BASE/sec/auditd.txt" | json_escape)"
  printf '  "network": {"listening_file": %s},\n' "$(printf '%s' "$BASE/net/listening.txt" | json_escape)"
  printf '  "auth": {"ssh_file": %s, "accounts_file": %s},\n' "$(printf '%s' "$BASE/auth/ssh.txt" | json_escape)" "$(printf '%s' "$BASE/auth/accounts.txt" | json_escape)"
  printf '  "aws": {"metadata_file": %s}\n' "$(printf '%s' "$BASE/aws/metadata.txt" | json_escape)"
  printf '}\n'
} >"$INV"

# -----------------------------
# 6) Compress evidence for portability (exclude keys)
# -----------------------------
( cd "$(dirname "$BASE")" && tar --exclude='*.key' -czf "$(basename "$BASE").tgz" "$(basename "$BASE")" ) || true

msg "[+] Tiny summary: $TINY"
msg "[+] Rich inventory: $INV"
msg "[+] Evidence archive: ${BASE}.tgz"
