# Website Hardening Pack — Ubuntu 22.04 LTS (CIS Benchmark + OWASP)

> **Scope & Certification**
> This hardening pack is designed for **website stack security**, **operating system hardening**, and **security configuration of supporting web infrastructure**. It is **additive-only**, **idempotent**, and safe for both new installations and live production environments. It does not alter application code or database configurations.
> 
> **Tested on**: Ubuntu 22.04 LTS (AWS EC2) — August 2025.

> **Specially made for greater websites** — security-first, additive-only, production-safe. Works on fresh installs and live servers.

---

## Directory tree (pack layout)
```
pack/
 ├─ recon_website.sh                  # Read‑only recon; creates tiny-gap-summary.json + inventory.json + evidence bundle
 ├─ aws_enforce.sh                    # Planner + additive-only enforcement (idempotent; backups; config tests)
 ├─ config.template.json              # Central toggles; copy to config.json and edit
 └─ iam/
     ├─ instance-role-trust.json      # EC2 assume role trust policy (minimal, safe)
     ├─ instance-role-policy.min.json # Minimal SSM core + CloudWatch Logs for instance role
     └─ operator-sendcommand-policy.json # Least-priv operator policy (tag-scoped)
```

---

## Purpose (why this exists)
Modern production websites need hardened, **repeatable** security without downtime. This pack lets you:
- Bring Ubuntu 22.04 LTS web servers on AWS toward **CIS** + **OWASP** guidance.
- Enforce a **bank‑grade baseline** with zero destructive actions.
- Control everything centrally via a single **config.json**.
- Execute safely on **fresh** instances or long‑running **production** workloads.
- Prove what changed with **plan mode**, **backups**, and **logs**.

### Security philosophy
- **Additive-only:** We add scoped drop-ins/snippets; we never overwrite your primary configs.
- **Idempotent:** Re-running produces no change when already compliant.
- **Fail‑safe:** Apache/Nginx configs are validated before reload; SSH uses `sshd_config.d`.
- **Separation of concerns:** Recon is *read‑only*; enforcement is *explicitly configured*.
- **Least privilege:** Minimal IAM for instances; tag‑scoped operator rights.

---

## Advantages (what you gain)
1. **Production‑friendly:** Safe to run on live traffic; `--plan` shows every intended change.
2. **Compliance‑oriented:** Covers practical CIS/OWASP items (firewall, SSH, headers, updates, intrusion throttling).
3. **Centralized control:** One JSON governs behavior across fleets/environments.
4. **Transparent evidence:** Recon bundles and enforcement logs support audits and IR.
5. **Automation‑ready:** First‑class with AWS Systems Manager (SSM); no inbound SSH required.
6. **Extensible modules:** Opt‑in for `auditd`, `AIDE`, `ModSecurity`(+OWASP CRS), and targeted `sysctl`.
7. **Zero lock‑in:** Plain Bash + JSON. Reviewable, portable, vendor‑neutral.

---

## Focus areas & what they do
- **Network security:** UFW rules for 22/80/443, optional SSH rate‑limit, optional sysctl net hardening.
- **Access control:** Safer SSH defaults via `sshd_config.d` (password logins disabled only if you opt in).
- **Attack surface reduction:** Fail2Ban baselines for brute‑force; strict HTTP headers (HSTS, XFO, XCTO, RP, Permissions‑Policy; CSP opt-in).
- **System integrity (opt-in):** `auditd` watches identities, sudoers, logs; `AIDE` initializes a file‑integrity baseline.
- **Update hygiene:** `unattended‑upgrades` for timely patch intake.
- **Observability:** CloudWatch Logs permissions for SSM command output; local logs for every action.

---

## What it **does not** do (by design)
- No destructive changes (no mass permission resets, deletions, or package removals).
- No DB or app‑framework hardening (MySQL/Postgres/PHP code rules are out of scope).
- No TLS issuance/renewal automation (we inventory cert locations only).
- No WAF policy tuning beyond enabling ModSecurity + optional OWASP CRS.
- No org‑level AWS guardrails (use SCPs / IAM boundaries separately).

---

## File primers
### `recon_website.sh`
- **Role:** Read‑only reconnaissance. Never copies secrets. Lists cert paths but **never** copies private keys.
- **Outputs:**
  - `tiny-gap-summary.json` — fast executive summary.
  - `inventory.json` — pointers to full evidence files.
  - Evidence bundle: `/var/log/website_hardening/RECON-<ts>/` (+ `.tgz`).
- **Flags:** `--fast` to skip heavy listings; `--output-dir <path>`.

### `aws_enforce.sh`
- **Role:** Apply additive controls governed by `config.json`.
- **Modes:** `--plan` (dry‑run; default), `--apply` (enforce with backups & config tests).
- **Core:** packages, UFW, Fail2Ban, unattended‑upgrades, SSH drop-in, Apache/Nginx security headers (CSP opt-in).
- **Optional:** `auditd`, `AIDE`, `ModSecurity`(+CRS), `sysctl` snippet (only params you set).
- **Safety:** Timestamped backups in `/var/backups/website_hardening/<ts>/`; logs in `/var/log/website_hardening/`.

### `config.template.json`
- **Role:** Central toggles. Copy to `config.json` and customize. Safe defaults; CSP off by default.

### IAM (`iam/`)
- `instance-role-trust.json` → minimal EC2 assume role.
- `instance-role-policy.min.json` → SSM core + CloudWatch Logs for the instance.
- `operator-sendcommand-policy.json` → least‑priv SendCommand for **tagged** instances only (`Project=WebsiteHardening`).

---

## Full instructions (end‑to‑end)

### 0) AWS prerequisites (once)
1. **Create EC2 instance role**
   - Trust: paste `iam/instance-role-trust.json`.
   - Permissions: attach `iam/instance-role-policy.min.json` *(or AWS managed `AmazonSSMManagedInstanceCore`)*.
2. **Operator IAM**
   - Attach `iam/operator-sendcommand-policy.json` to the human operator role/user.
   - Ensure all target instances have tag: `Project=WebsiteHardening`.
3. **EC2 / AMI**
   - Launch Ubuntu **22.04 LTS**. Attach the instance role. Add the tag above.
   - Confirm **SSM Agent** is running (Ubuntu 22.04 AWS images normally include it).

### 1) Place the pack on the instance
```bash
sudo mkdir -p /opt/hardening-pack && cd /opt/hardening-pack
# Upload: recon_website.sh  aws_enforce.sh  config.template.json  (IAM files optional for reference)
sudo chmod +x recon_website.sh aws_enforce.sh
```

### 2) Recon (safe)
```bash
# Full scan
sudo ./recon_website.sh
# or faster on busy production
sudo ./recon_website.sh --fast
```
Review: `/var/log/website_hardening/RECON-<ts>/tiny-gap-summary.json` and `inventory.json`. The whole evidence folder is compressed to `<RECON-<ts>>.tgz` for portability.

**Run via SSM (no SSH):** Systems Manager → Run Command → **AWS‑RunShellScript** → Targets: instances with tag `Project=WebsiteHardening` → Commands:
```bash
cd /opt/hardening-pack
sudo ./recon_website.sh --fast
```

### 3) Configure
```bash
cd /opt/hardening-pack
cp config.template.json config.json
# Edit config.json — choose:
#  - firewall.enable, rate_limit_ssh
#  - ssh.allow_password=false (for key‑only)
#  - http_headers.enable_csp=true (when your site is CSP‑ready)
#  - auditd/aide/modsecurity/sysctl (opt-in)
```

### 4) Planner (dry‑run)
```bash
sudo ./aws_enforce.sh --config ./config.json --plan
```
Examine the output and `/var/log/website_hardening/enforce-<ts>.log` to verify intended actions.

### 5) Apply (additive-only)
```bash
sudo ./aws_enforce.sh --config ./config.json --apply
```
- Each changed file gets a backup in `/var/backups/website_hardening/<ts>/…`.
- Web servers are config‑tested before reload.
- SSH changes are isolated to `sshd_config.d/01-website-hardening.conf`.

---

## Post‑apply verification checklist
- **Firewall**: `sudo ufw status` shows 22/tcp (Limited), 80/tcp, 443/tcp.
- **Fail2Ban**: `sudo fail2ban-client status` (and `status sshd`).
- **SSH**: `sshd -T | egrep 'passwordauthentication|maxauthtries|permitrootlogin'` reflects your config.
- **Headers (Apache/Nginx)**: from a client host, `curl -I https://your.domain` shows `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: ...`, and `Strict-Transport-Security: ...`. If CSP enabled, `Content-Security-Policy: ...` present.
- **Unattended upgrades**: `/etc/apt/apt.conf.d/20auto-upgrades` contains `Update-Package-Lists` and `Unattended-Upgrade` set to `1`.
- **auditd (opt-in)**: `sudo auditctl -l` shows rules; `systemctl status auditd` is active.
- **AIDE (opt-in)**: baseline DB exists at `/var/lib/aide/aide.db`.

---

## Rollback (surgical)
1. Identify the backup path in `/var/backups/website_hardening/<ts>/…`.
2. Restore a file, e.g. SSH drop-in:
```bash
sudo cp /var/backups/website_hardening/<ts>/etc/ssh/sshd_config.d/01-website-hardening.conf.<ts>.bak         /etc/ssh/sshd_config.d/01-website-hardening.conf
sudo systemctl reload ssh
```
3. To revert a web header snippet, restore the file and run the relevant service reload.

---

## Deep dive: how each function improves security
- **UFW rules + SSH rate‑limit**: Shrinks exposed surface; throttles brute‑force; supports CIS L1 networking basics.
- **Fail2Ban baselines**: Locks out repeated auth failures at the service layer — effective against commodity scans.
- **Security headers**: Mitigate clickjacking (X‑Frame‑Options), MIME sniffing (XCTO), data exfil/identity leakage (Referrer‑Policy), abused browser APIs (Permissions‑Policy), and SSL stripping (HSTS). CSP (when enabled) curbs XSS by restricting script sources.
- **Unattended upgrades**: Reduces patch lag, which is a major exploit vector.
- **SSH drop-in**: Tightens auth tries/timeouts; optional key‑only auth reduces credential attack risk; `sshd_config.d` avoids clobbering.
- **auditd (opt-in)**: Tracks sensitive file changes and permission modifications — helpful for forensics/compliance.
- **AIDE (opt-in)**: Baseline integrity to detect unexpected file changes.
- **ModSecurity + OWASP CRS (opt-in)**: Application‑layer detection/mitigation for common web attacks (SQLi/XSS/File Inclusion), as another defense layer in front of app code.
- **sysctl snippet (opt-in)**: Only the parameters you explicitly set; supports safer routing/redirect behaviors per CIS networking items.

---

## CSP guidance (enable with care)
- Start with **report‑only** in staging, then enforce in production once violations are clean.
- Whitelist only required origins (CDNs, APIs). Avoid wildcard `*` for `script-src`.
- Pair CSP with subresource integrity (SRI) for external scripts when possible.

Example strict CSP (adjust for your site):
```
Content-Security-Policy: default-src 'self'; connect-src 'self' https:; img-src 'self' https: data:; font-src 'self' https: data:; style-src 'self' 'unsafe-inline' https:; script-src 'self' https: 'nonce-<generated>'; frame-ancestors 'self'; base-uri 'self'; object-src 'none';
```

---

## Example configurations
**A. Minimal baseline (safe for almost all sites):**
```json
{
  "packages": { "install": ["jq", "ufw", "fail2ban", "unattended-upgrades"] },
  "firewall": { "enable": true, "allow_ssh": true, "allow_http": true, "allow_https": true, "rate_limit_ssh": true },
  "fail2ban": { "enable": true },
  "unattended_upgrades": { "enable": true },
  "ssh": { "allow_password": null, "permit_root_login": null },
  "http_headers": { "enable_csp": false, "csp_value": "default-src 'self' https: data:; frame-ancestors 'self'; object-src 'none'; base-uri 'self';" },
  "auditd": { "enable": false },
  "aide": { "enable": false },
  "modsecurity": { "enable": false, "owasp_crs": false },
  "sysctl": { "enable": false, "params": {} }
}
```

**B. Hardened profile (when app is CSP‑ready):**
```json
{
  "packages": { "install": ["jq", "ufw", "fail2ban", "unattended-upgrades", "auditd", "aide", "libapache2-mod-security2", "modsecurity-crs"] },
  "firewall": { "enable": true, "allow_ssh": true, "allow_http": true, "allow_https": true, "rate_limit_ssh": true },
  "fail2ban": { "enable": true },
  "unattended_upgrades": { "enable": true },
  "ssh": { "allow_password": false, "permit_root_login": "prohibit-password" },
  "http_headers": { "enable_csp": true, "csp_value": "default-src 'self' https: data:; frame-ancestors 'self'; object-src 'none'; base-uri 'self';" },
  "auditd": { "enable": true },
  "aide": { "enable": true },
  "modsecurity": { "enable": true, "owasp_crs": true },
  "sysctl": { "enable": true, "params": { "net.ipv4.conf.all.log_martians": 1, "net.ipv4.conf.default.accept_redirects": 0, "net.ipv6.conf.all.accept_redirects": 0 } }
}
```

---

## Troubleshooting quick wins
- **Service reload fails**: Check the enforce log and run `apache2ctl -t` / `nginx -t` manually; fix any site‑specific directives.
- **CSP blocks content**: Inspect browser devtools → Console “Content Security Policy” errors; add required sources to `csp_value`.
- **SSM command timeouts**: Verify instance role, VPC endpoints (for SSM in private subnets), and that the instance has the `Project=WebsiteHardening` tag.
- **Fail2Ban not banning**: Ensure jails are enabled and logs are present for the relevant services.

---

## Ongoing operations (recommended)
- Schedule **recon** weekly via SSM to maintain an evidence trail (retain `.tgz` bundles for change tracking).
- Treat `config.json` as **code** (commit to a private repo; PRs for changes; versioned releases).
- Stage → Plan → Apply in production with the same artifact.

---

**This pack is built for high‑value, high‑traffic, *greater* websites** that demand strong, explainable security without sacrificing uptime. When you’re ready, we can further extend it with password policies (PAM), FIM alerting, ModSecurity tuning for your app, and environment‑specific CSP generators.