# Enterprise-Grade Hardening Pack for AWS EC2 Ubuntu 22.04 LTS

*A free, additive-only security toolkit to harden AWS hosts, Ubuntu OS, and web stacks in line with CIS Benchmark & OWASP.*

---

## 1. Executive Summary

This hardening pack delivers multi-layer security for enterprises, government agencies, and high-value web applications. It focuses on **three layers simultaneously**:

* **AWS Host Layer** — Secure IAM roles, tag-based execution, Systems Manager control without open SSH.
* **Ubuntu OS Layer** — CIS-aligned firewall, SSH, Fail2Ban, sysctl tuning, audit logging.
* **Web Stack Layer** — OWASP-recommended HTTP headers, optional ModSecurity + CRS, TLS hygiene.

It is **safe for production**, idempotent, and works equally well for **fresh installations** or **long-running servers**.

---

## 2. Key Features

### AWS Host Layer

* Minimal EC2 instance trust policy.
* Tag-scoped operator IAM policy.
* Remote execution via AWS Systems Manager (SSM) — no open SSH ports.
* CloudWatch Logs integration.

### Ubuntu OS Layer

* UFW firewall with rate-limited SSH and HTTPS.
* Fail2Ban baseline protections.
* Automated security updates.
* Optional auditd & AIDE for file integrity.
* Secure sysctl parameters.

### Web Stack Layer

* Apache/Nginx drop-in configs for:

  * X-Content-Type-Options
  * X-Frame-Options
  * Referrer-Policy
  * Permissions-Policy
  * HTTP Strict Transport Security (HSTS)
  * Optional Content Security Policy (CSP)
* Optional ModSecurity + OWASP CRS.

---

## 3. Advantages

* **Safe** — additive-only, never overwrites existing configs.
* **Idempotent** — can be run multiple times without side effects.
* **Evidence-Based** — recon script gathers proof before changes.
* **Compliance-Ready** — aligns with CIS, OWASP, and supports ISO/IEC 27001, NIST CSF, PCI-DSS, HIPAA.
* **Production-Friendly** — plan mode simulates changes before applying.
* **Extensible** — enable optional modules via `config.json`.

---

## 4. Directory Tree

```
pack/
 ├─ recon_website.sh            # Read-only recon + JSON summary
 ├─ aws_enforce.sh              # Planner + additive-only enforcement
 ├─ config.template.json        # Site + policy toggles (safe defaults)
 └─ iam/
     ├─ instance-role-trust.json          # Minimal EC2 trust
     ├─ instance-role-policy.min.json     # Minimal SSM + Logs
     └─ operator-sendcommand-policy.json  # Least-privilege operator actions
```

---

## 5. Scope & Compliance

* **Primary Standards**: CIS Benchmark for Ubuntu 22.04 LTS, OWASP Secure Headers.
* **Supports**: ISO/IEC 27001, NIST Cybersecurity Framework, PCI-DSS, HIPAA.
* **Scope**:

  * AWS host-level access controls.
  * Ubuntu OS-level hardening.
  * Web server security configuration.

---

## 6. Usage Workflow

### Step 1 — Upload the Pack

```bash
sudo mkdir -p /opt/hardening-pack && cd /opt/hardening-pack
# Upload all files here
sudo chmod +x recon_website.sh aws_enforce.sh
```

### Step 2 — Recon (Safe)

```bash
sudo ./recon_website.sh --fast
```

Evidence stored in `/var/log/website_hardening/RECON-<timestamp>/`.

### Step 3 — Configure

```bash
cp config.template.json config.json
nano config.json  # Enable/disable features
```

### Step 4 — Plan (Dry-Run)

```bash
sudo ./aws_enforce.sh --config ./config.json --plan
```

### Step 5 — Apply (Harden)

```bash
sudo ./aws_enforce.sh --config ./config.json --apply
```

---

## 7. IAM Requirements

* **instance-role-trust.json** — Allows EC2 to assume role.
* **instance-role-policy.min.json** — Minimal permissions for SSM + Logs.
* **operator-sendcommand-policy.json** — Restricts human operators to approved, tagged instances.

---

## 8. Rollback & Safety

* Backups stored in `/var/backups/website_hardening/<timestamp>/`.
* All changes logged in `/var/log/website_hardening/`.
* Restore by copying backup files over originals and restarting services.

---

## 9. Target Audience

* Enterprises with compliance mandates.
* Government and defense web infrastructure.
* Fintech and e-commerce platforms.
* SaaS providers hosting sensitive customer data.

---

> **Free for all** — This hardening pack may be used without licensing restrictions.
