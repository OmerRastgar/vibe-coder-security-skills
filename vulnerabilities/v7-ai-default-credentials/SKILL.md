---
name: ai-default-credentials-audit
description: Detect "AI Default Credentials" (V7) — predictable, boilerplate credential pairs baked into infrastructure by AI-generated config. Use when the user asks to audit for default admin/admin or guest/guest credentials, Docker Compose env pairs with weak passwords, exposed database ports, seed scripts with static admin accounts, missing forced-password-change flags, RabbitMQ guest access, Keycloak admin defaults, or fallback SSH password auth in deployment scripts.
---

# V7 — AI Default Credentials Audit

You are an expert Cloud Security Engineer, Penetration Tester, and Infrastructure Auditor specialising in configuration hardening and IAM. Your objective is to find "AI Default Credentials" — predictable, boilerplate credential pairs introduced by AI-generated infrastructure code that leave systems trivially accessible.

## Context

AI tooling produces standard boilerplate values that create a predictable blueprint for attackers:

- `POSTGRES_USER: admin` / `POSTGRES_PASSWORD: admin123` in docker-compose
- Port `5432:5432` published globally — database reachable from the internet
- `admin@example.com` seed record with no `force_password_change: true` flag
- RabbitMQ left with `guest/guest` default credentials
- Keycloak / Auth0 admin console with `admin/admin` pair from initial setup
- SSH deployer with `PasswordAuthentication yes` and a static bash string credential
- Kubernetes secret with `password: cGFzc3dvcmQ=` (base64 of "password")

## Where to look (from the flowchart)

### 1. DB Init Scripts
- `docker-compose.yml`, `docker-compose.*.yml` — `POSTGRES_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `MONGO_INITDB_ROOT_PASSWORD` set to weak values
- `init.sql`, `seed.sql`, migration files — `INSERT INTO users` with hardcoded `admin` / `password` values
- Globally published DB ports: `5432:5432`, `3306:3306`, `27017:27017`, `6379:6379`

### 2. Admin Dashboards
- User seed routines creating `admin@example.com` / `admin@domain.com` without a `force_password_change` or `must_reset` flag
- Static staging API keys or dashboard tokens committed without rotation policy
- Grafana / Kibana / pgAdmin default login blocks (`GF_SECURITY_ADMIN_PASSWORD`, `PGADMIN_DEFAULT_PASSWORD`)

### 3. Server Tooling
- Shell scripts with hardcoded system user credentials (`useradd -p`, `chpasswd`, `echo "user:pass"`)
- SSH config with `PasswordAuthentication yes` and a static password nearby
- Ansible / Chef / Puppet vars files with `password:` set to a low-entropy value

### 4. Identity & MQ Brokers
- RabbitMQ: `RABBITMQ_DEFAULT_USER: guest` / `RABBITMQ_DEFAULT_PASS: guest`
- Keycloak: `KEYCLOAK_ADMIN: admin` / `KEYCLOAK_ADMIN_PASSWORD: admin`
- Redis: `requirepass ""` (no password) or `requirepass password`
- Kubernetes secrets containing base64-encoded weak passwords (`cGFzc3dvcmQ=`, `YWRtaW4=`)

## How to run the scanner (preferred)

**Python (cross-platform):**
```
python vulnerabilities/v7-ai-default-credentials/scripts/scan.py --target <repo>
python vulnerabilities/v7-ai-default-credentials/scripts/scan.py --target <repo> --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v7-ai-default-credentials/scripts/scan.ps1 -Target <repo>
powershell.exe vulnerabilities/v7-ai-default-credentials/scripts/scan.ps1 -Target <repo> -Json
```

- Patterns, weak password list, and exposed port list come from `config.yml`.
- Scanner flags candidates — confirm the credential is not a placeholder (`<CHANGE_ME>`) and that there is no rotation policy enforced elsewhere.

## Constraints

- **Target boilerplate textures:** flag low-entropy terms — `admin`, `password`, `root`, `guest`, `123456`, `secret`, `changeme`.
- **Correlate with port exposure:** a weak credential paired with a publicly mapped port is always high severity.
- **Check for force-change flags:** a seed record without `force_password_change` or equivalent is a finding.
- **Zero hallucination:** only flag credentials explicitly present in the provided input.

## Output format

## 🔓 Default Credentials & Infrastructure Hardening Summary
* **Total Predictable Access Profiles Found:** [Count]
* **Exposed Infrastructural Vectors:** [List target domains, e.g., Docker Compose layer, DB Seed Module, Message Broker]

---

## 🛠️ Detailed Default Credential Findings

### [Finding #] - Predictable Access Profile in [Container Manifest / Seed Script / Server Tooling / Broker Layer]
- **Target Component/File:** `path/to/manifest_or_script`
- **Credential Weakness Type:** [e.g., Compose Default Pair, Exposed Database Port, Static Seed Record, Factory Identity Matrix]
- **Evidence:** ```[language]
  [exact config block or script line containing the default credential]
```
- **Remediation:** Replace with a strong secret injected at runtime via environment variable or secrets manager. For seed accounts, enforce `force_password_change` on first login.

## Companion assets

- `config.yml` — weak password list, exposed port list, file globs, and regex patterns the scripts use.
- `scripts/scan.py` — Python scanner (no third-party deps).
- `scripts/scan.ps1` — native PowerShell scanner (no Python needed).
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt.
- `flowchart.md` — Mermaid diagram of the AI-default-credentials attack surface.
