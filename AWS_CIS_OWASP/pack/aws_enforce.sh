#!/usr/bin/env bash
# aws_enforce.sh — Additive-only hardening for Ubuntu 22.04 (CIS + OWASP aligned)
# Modes: --plan (default), --apply, --config <json>
# Design: idempotent, backups, config-tests, no destructive edits

set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<USAGE
Usage: $0 --config /path/to/config.json [--plan|--apply]

Examples:
  $0 --config ./config.json --plan      # dry-run (no changes)
  $0 --config ./config.json --apply     # enforce (additive-only)
USAGE
}

PLAN_ONLY=1
CONFIG=""
TS=$(date +"%Y%m%d-%H%M%S")
BACKUP_DIR="/var/backups/website_hardening/$TS"
LOG_DIR="/var/log/website_hardening"
mkdir -p "$BACKUP_DIR" "$LOG_DIR"
LOGFILE="$LOG_DIR/enforce-$TS.log"
exec > >(tee -a "$LOGFILE") 2>&1

die()    { echo "[FATAL] $*" >&2; exit 1; }
info()   { echo "[INFO] $*"; }
change() { echo "[CHANGE] $*"; }

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }
need_jq()      { command -v jq >/dev/null 2>&1 || die "jq is required. apt-get install -y jq"; }
have()         { command -v "$1" >/dev/null 2>&1; }

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local rel="${f#/}"
  local dest="$BACKUP_DIR/$rel.$TS.bak"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest"
  info "Backed up $f -> $dest"
}

write_file_if_diff() {
  local target="$1"; shift
  local content="$1"; shift || true
  local tmp; tmp=$(mktemp)
  printf '%s' "$content" >"$tmp"
  if [[ ! -f "$target" ]] || ! cmp -s "$tmp" "$target"; then
    backup_file "$target"
    if [[ $PLAN_ONLY -eq 0 ]]; then
      mkdir -p "$(dirname "$target")"
      cp "$tmp" "$target"
      change "Updated $target"
    else
      change "Would update $target"
    fi
  else
    info "No change for $target"
  fi
  rm -f "$tmp"
}

reload_service_safe() {
  local svc="$1"
  if [[ $PLAN_ONLY -eq 0 ]]; then
    systemctl reload "$svc" && info "Reloaded $svc" || info "Reload of $svc failed (check config test)."
  else
    info "Would reload $svc"
  fi
}

# -----------------------------
# Web detection
# -----------------------------
IS_APACHE=0; IS_NGINX=0
if have apache2 || [[ -x /usr/sbin/apache2 ]]; then IS_APACHE=1; fi
if have nginx; then IS_NGINX=1; fi

test_apache() { apache2ctl -t; }
test_nginx()  { nginx -t; }

enable_apache_conf() {
  local name="$1"
  a2enconf "$name" >/dev/null 2>&1 || true
  test_apache && reload_service_safe apache2
}
include_nginx_conf() {
  test_nginx && reload_service_safe nginx
}

# -----------------------------
# Core controls
# -----------------------------
apply_ufw_rules() {
  local allow_ssh=$(jq -r '.firewall.allow_ssh // true' "$CONFIG")
  local allow_http=$(jq -r '.firewall.allow_http // true' "$CONFIG")
  local allow_https=$(jq -r '.firewall.allow_https // true' "$CONFIG")
  local rate_limit_ssh=$(jq -r '.firewall.rate_limit_ssh // true' "$CONFIG")
  local enable=$(jq -r '.firewall.enable // true' "$CONFIG")

  if have ufw; then
    [[ "$allow_ssh"   == "true" ]] && { [[ $PLAN_ONLY -eq 0 ]] && ufw allow OpenSSH || change "Would: ufw allow OpenSSH"; }
    [[ "$allow_http"  == "true" ]] && { [[ $PLAN_ONLY -eq 0 ]] && ufw allow 80/tcp   || change "Would: ufw allow 80/tcp"; }
    [[ "$allow_https" == "true" ]] && { [[ $PLAN_ONLY -eq 0 ]] && ufw allow 443/tcp  || change "Would: ufw allow 443/tcp"; }
    [[ "$rate_limit_ssh" == "true" ]] && { [[ $PLAN_ONLY -eq 0 ]] && ufw limit OpenSSH || change "Would: ufw limit OpenSSH"; }
    if [[ "$enable" == "true" ]]; then
      if [[ $PLAN_ONLY -eq 0 ]]; then ufw --force enable; else change "Would enable ufw"; fi
    fi
  else
    info "ufw not installed — skipping firewall (add to packages.install to use)."
  fi
}

ensure_packages() {
  local pkgs; pkgs=$(jq -r '.packages.install[]? | @sh' "$CONFIG" | tr -d "'")
  [[ -z "$pkgs" ]] && return 0
  if [[ $PLAN_ONLY -eq 0 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs
    info "Installed packages: $pkgs"
  else
    change "Would install packages: $pkgs"
  fi
}

configure_fail2ban() {
  local enable=$(jq -r '.fail2ban.enable // true' "$CONFIG")
  [[ "$enable" != "true" ]] && { info "fail2ban disabled in config"; return; }
  have fail2ban-server || { info "fail2ban not installed"; return; }
  local jail="/etc/fail2ban/jail.d/website-hardening.local"
  local content="[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[apache-auth]
enabled = true
"
  write_file_if_diff "$jail" "$content"
  if [[ $PLAN_ONLY -eq 0 ]]; then systemctl restart fail2ban || true; else info "Would restart fail2ban"; fi
}

configure_unattended_upgrades() {
  local enable=$(jq -r '.unattended_upgrades.enable // true' "$CONFIG")
  [[ "$enable" != "true" ]] && { info "unattended-upgrades disabled in config"; return; }
  local pkg="unattended-upgrades"
  dpkg -s "$pkg" >/dev/null 2>&1 || { [[ $PLAN_ONLY -eq 0 ]] && apt-get install -y "$pkg" || change "Would install $pkg"; }
  local auto="/etc/apt/apt.conf.d/20auto-upgrades"
  write_file_if_diff "$auto" "APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
"
}

configure_ssh() {
  local cfg="/etc/ssh/sshd_config.d/01-website-hardening.conf"
  local allow_password=$(jq -r '.ssh.allow_password // null' "$CONFIG")
  local permit_root=$(jq -r '.ssh.permit_root_login // null' "$CONFIG")
  local lines="Protocol 2
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
"
  if [[ "$allow_password" == "false" ]]; then
    lines+="PasswordAuthentication no
"
  fi
  if [[ "$permit_root" != "null" ]]; then
    # allowed values: yes | prohibit-password | forced-commands-only | no
    lines+="PermitRootLogin $permit_root
"
  fi
  write_file_if_diff "$cfg" "$lines"
  if [[ $PLAN_ONLY -eq 0 ]]; then systemctl reload ssh || true; else info "Would reload sshd"; fi
}

apache_headers_conf() {
  local enable_csp=$(jq -r '.http_headers.enable_csp // false' "$CONFIG")
  local csp_value=$(jq -r '.http_headers.csp_value // "default-src '\''self'\'' https: data:; frame-ancestors '\''self'\''; object-src '\''none'\''; base-uri '\''self'\'';"' "$CONFIG")
  local f="/etc/apache2/conf-available/website-security-headers.conf"
  local hdrs="Header always set X-Content-Type-Options \"nosniff\"
Header always set X-Frame-Options \"SAMEORIGIN\"
Header always set Referrer-Policy \"strict-origin-when-cross-origin\"
Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"
Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains\"
"
  if [[ "$enable_csp" == "true" ]]; then
    hdrs+="Header always set Content-Security-Policy \"$csp_value\"
"
  fi
  write_file_if_diff "$f" "$hdrs"
  enable_apache_conf "website-security-headers"
}

nginx_headers_conf() {
  local enable_csp=$(jq -r '.http_headers.enable_csp // false' "$CONFIG")
  local csp_value=$(jq -r '.http_headers.csp_value // "default-src '\''self'\'' https: data:; frame-ancestors '\''self'\''; object-src '\''none'\''; base-uri '\''self'\'';"' "$CONFIG")
  local f="/etc/nginx/conf.d/website-security-headers.conf"
  local hdrs="add_header X-Content-Type-Options \"nosniff\" always;
add_header X-Frame-Options \"SAMEORIGIN\" always;
add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;
add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;
add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;
"
  if [[ "$enable_csp" == "true" ]]; then
    hdrs+="add_header Content-Security-Policy \"$csp_value\" always;
"
  fi
  write_file_if_diff "$f" "$hdrs"
  include_nginx_conf
}

apply_web_headers() {
  [[ $IS_APACHE -eq 1 ]] && apache_headers_conf
  [[ $IS_NGINX  -eq 1 ]] && nginx_headers_conf
}

# -----------------------------
# Optional modules (all OFF by default)
# -----------------------------
configure_auditd_rules() {
  local enable=$(jq -r '.auditd.enable // false' "$CONFIG")
  [[ "$enable" != "true" ]] && { info "auditd rules disabled"; return; }

  local pkg="auditd"
  dpkg -s "$pkg" >/dev/null 2>&1 || { [[ $PLAN_ONLY -eq 0 ]] && apt-get install -y "$pkg" || change "Would install $pkg"; }

  local rules="/etc/audit/rules.d/99-website-hardening.rules"
  # Minimal, CIS-friendly watch set (safe & additive)
  local content="-w /etc/passwd -p wa -k identity
-w /etc/group  -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /var/log/ -p wa -k logchange
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S chmod,chown,fchmod,fchmodat,fchown,fchownat,lchown -k perm_mod
-a always,exit -F arch=b32 -S chmod,chown,fchmod,fchmodat,fchown,fchownat,lchown -k perm_mod
"
  write_file_if_diff "$rules" "$content"

  if [[ $PLAN_ONLY -eq 0 ]]; then
    # load rules safely
    if have augenrules; then augenrules --load || true; fi
    systemctl restart auditd || true
  else
    info "Would load audit rules and restart auditd"
  fi
}

configure_aide() {
  local enable=$(jq -r '.aide.enable // false' "$CONFIG")
  [[ "$enable" != "true" ]] && { info "AIDE disabled"; return; }

  local pkg="aide"
  dpkg -s "$pkg" >/dev/null 2>&1 || { [[ $PLAN_ONLY -eq 0 ]] && apt-get install -y "$pkg" || change "Would install $pkg"; }

  if [[ $PLAN_ONLY -eq 0 ]]; then
    if [[ ! -f /var/lib/aide/aide.db ]]; then
      info "Initializing AIDE database..."
      aideinit || true
      if [[ -f /var/lib/aide/aide.db.new ]]; then
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        change "AIDE baseline created"
      fi
    else
      info "AIDE database already present — skipping init"
    fi
  else
    info "Would initialize AIDE baseline if absent"
  fi
}

configure_modsecurity() {
  local enable=$(jq -r '.modsecurity.enable // false' "$CONFIG")
  [[ "$enable" != "true" ]] && { info "ModSecurity disabled"; return; }

  # Apache variant
  if [[ $IS_APACHE -eq 1 ]]; then
    local pkg="libapache2-mod-security2"
    dpkg -s "$pkg" >/dev/null 2>&1 || { [[ $PLAN_ONLY -eq 0 ]] && apt-get install -y "$pkg" || change "Would install $pkg"; }

    # Optionally enable OWASP CRS
    local crs_enable=$(jq -r '.modsecurity.owasp_crs // false' "$CONFIG")
    if [[ "$crs_enable" == "true" ]]; then
      local crs_pkg="modsecurity-crs"
      dpkg -s "$crs_pkg" >/dev/null 2>&1 || { [[ $PLAN_ONLY -eq 0 ]] && apt-get install -y "$crs_pkg" || change "Would install $crs_pkg"; }
      # Enable CRS ruleset via include file
      local inc="/etc/modsecurity/crs-include.conf"
      local content="IncludeOptional /usr/share/modsecurity-crs/*.conf
IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
"
      write_file_if_diff "$inc" "$content"

      # Apache loader snippet
      local ap_conf="/etc/apache2/conf-available/website-modsecurity.conf"
      local ap_body="<IfModule security2_module>
  IncludeOptional /etc/modsecurity/*.conf
  IncludeOptional /etc/modsecurity/crs-include.conf
</IfModule>
"
      write_file_if_diff "$ap_conf" "$ap_body"
      enable_apache_conf "website-modsecurity"
    fi

    # Ensure modsecurity.conf exists (package provides it). Reload checked by enable_apache_conf above.
  fi

  # Nginx variant (if module packaged)
  if [[ $IS_NGINX -eq 1 ]]; then
    local npkg="libnginx-mod-security"
    if apt-cache show "$npkg" >/dev/null 2>&1; then
      dpkg -s "$npkg" >/dev/null 2>&1 || { [[ $PLAN_ONLY -eq 0 ]] && apt-get install -y "$npkg" || change "Would install $npkg"; }
      local nconf="/etc/nginx/conf.d/modsecurity.conf"
      local body="modsecurity on;
modsecurity_rules_file /etc/modsecurity/modsecurity.conf;
"
      write_file_if_diff "$nconf" "$body"
      include_nginx_conf
    else
      info "Nginx ModSecurity module not available in repo — skipped"
    fi
  fi
}

configure_sysctl_snippet() {
  local enable=$(jq -r '.sysctl.enable // false' "$CONFIG")
  [[ "$enable" != "true" ]] && { info "sysctl snippet disabled"; return; }

  local file="/etc/sysctl.d/99-website-hardening.conf"
  local params; params=$(jq -r '.sysctl.params // {} | to_entries[] | (.key + "=" + (.value|tostring))' "$CONFIG" 2>/dev/null || true)
  [[ -z "$params" ]] && { info "No sysctl params provided"; return; }

  # Build content from provided params only (additive and explicit)
  local content="# Managed by aws_enforce.sh — additive sysctl for website hardening\n"
  while IFS= read -r line; do
    content+="$line
"
  done <<< "$params"

  write_file_if_diff "$file" "$content"
  if [[ $PLAN_ONLY -eq 0 ]]; then sysctl --system >/dev/null || true; else info "Would run: sysctl --system"; fi
}

# -----------------------------
# Entry
# -----------------------------
main() {
  require_root; need_jq

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config) CONFIG="$2"; shift 2;;
      --apply) PLAN_ONLY=0; shift;;
      --plan|--dry-run) PLAN_ONLY=1; shift;;
      -h|--help) usage; exit 0;;
      *) die "Unknown arg: $1";;
    esac
  done
  [[ -f "$CONFIG" ]] || die "Missing --config <file>"

  info "Mode: $([[ $PLAN_ONLY -eq 1 ]] && echo PLAN || echo APPLY)  Config: $CONFIG"

  ensure_packages
  apply_ufw_rules
  configure_fail2ban
  configure_unattended_upgrades
  configure_ssh
  apply_web_headers

  # Optional, opt-in features
  configure_auditd_rules
  configure_aide
  configure_modsecurity
  configure_sysctl_snippet

  info "Done. Backups: $BACKUP_DIR  Log: $LOGFILE"
}

main "$@"
