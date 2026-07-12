---
name: baking-secrets-audit
description: Detect "Baking Secrets into Source" (V6) — hardcoded credentials, API keys, DB connection strings, and cloud tokens permanently embedded in source code, config boilerplates, or infrastructure files. Use when the user asks to scan for hardcoded API keys, inline secrets, default staging credentials, unmasked .env.example files, AWS/cloud keys in code, kubeconfig tokens in source, or any live credential baked into the codebase rather than injected at runtime.
---

# V6 — Baking Secrets into Source Audit

You are an expert DevSecOps Engineer and Secrets Interception Agent specialising in cryptographic hygiene, high-entropy string analysis, and repository forensics. Your objective is to find "Baking Secrets into Source" — hardcoded authenticators, private keys, connection strings, and cloud tokens permanently fused into the codebase.

## Context

The core failure mode: a developer inlines a secret for a quick test and commits it. Even if later "deleted", it lives in Git history forever. Common patterns:

- `const API_KEY = "sk-proj-abc123..."` — live key assigned to a variable
- `postgres://admin:MyP@ssw0rd@prod-db.internal/app` — DB URI with credentials
- `.env.example` containing a real token instead of a placeholder like `<YOUR_KEY>`
- `AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."` in a config file
- `password: admin123` in a docker-compose or Kubernetes manifest
- Kubeconfig `token:` field with a real bearer token committed to the repo

## Where to look (from the flowchart)

### 1. Inline Code Variables
- Source files (`.py`, `.js`, `.ts`, `.go`, `.java`, `.cs`, `.rb`, `.php`)
- Variable assignments containing: `api_key`, `secret`, `password`, `token`, `private_key`, `auth`
- High-entropy strings (32+ chars of mixed alphanumeric) assigned to credential-named variables
- Connection strings: `postgres://`, `mysql://`, `mongodb://`, `redis://` with embedded passwords

### 2. Dev Boilerplates
- `.env`, `.env.example`, `.env.sample`, `.env.local`, `config.default.*`, `settings.py`
- Any sample/template file where values look like real tokens rather than `<PLACEHOLDER>` or `your-key-here`
- Seeding scripts or fixture files with hardcoded `password:` or `secret:` fields

### 3. Cloud & Infra Access
- `docker-compose.yml`, `kubernetes/*.yaml`, Helm `values.yaml` — `password:`, `secret:`, `token:` fields
- Terraform / HCL files — `access_key`, `secret_key` assigned inline
- `~/.aws/credentials` or `application.yml` with `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
- `.npmrc` with `_authToken` values, `pip.conf` with `password` fields

### 4. Version Control Leaks
- Git history (`git log -p --all`) — deleted lines that contained live credentials
- PR diffs and feature-branch test scripts pushed with debug credentials
- Any commit that added then removed a secret file (the secret is still in history)

## How to run the scanner (preferred)

**Python (cross-platform):**
```
python vulnerabilities/v6-baking-secrets/scripts/scan.py --target <repo>
python vulnerabilities/v6-baking-secrets/scripts/scan.py --target <repo> --history --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v6-baking-secrets/scripts/scan.ps1 -Target <repo>
powershell.exe vulnerabilities/v6-baking-secrets/scripts/scan.ps1 -Target <repo> -History -Json
```

- `--history` / `-History` also scans full Git commit history (`git log -p --all`).
- Patterns, sensitive filenames, and entropy settings come from `config.yml` — edit to add new secret types.
- Secrets are masked in output (first 4 + last 4 chars shown).
- The scanner flags candidates for human confirmation — distinguish live high-entropy secrets from obvious placeholders (`changeme`, `example`, `your-key-here`).

## Constraints

- **High-entropy + pattern detection:** flag both known-format tokens (AWS, OpenAI, Stripe) and generic high-entropy strings assigned to credential-named variables.
- **Historical depth:** when `--history` is used, evaluate deleted/modified lines — not just HEAD.
- **Flag pseudo-safe placeholders:** a `.env.example` with a real-looking token is a finding, even if labelled "example".
- **Mask output:** never echo full secret values — show first 4 + `...` + last 4 chars.
- **Zero hallucination:** only flag secrets explicitly present in the provided input.

## Output format

## 🔑 Secret Baking & Repository Hygiene Summary
* **Total Hardcoded Credentials Identified:** [Count]
* **Compromised Artifacts / Files:** [List file paths or commit hashes]

---

## 🔍 Detailed Hardcoded Secret Findings

### [Finding #] - Hardcoded Credential in [Inline Code / Dev Boilerplate / Cloud Access / Git History]
- **Target Component/Location:** `path/to/file` (line number or commit hash)
- **Secret Signature Type:** [e.g., High-Entropy API Token, Database URI String, Unmasked Sample Env, Staging Credentials]
- **Evidence:** ```[language]
  [exact snippet with secret masked, e.g., secret_key = "AIzaSyD...1234"]
```
- **Remediation:** Move to environment variable / secrets manager. If in Git history, rotate the secret immediately and use `git filter-repo` to scrub history.

## Companion assets

- `config.yml` — sensitive filenames, regex patterns, and entropy settings the scripts use.
- `scripts/scan.py` — Python scanner with optional Git history mode (no third-party deps).
- `scripts/scan.ps1` — native PowerShell scanner with optional Git history mode.
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt.
- `flowchart.md` — Mermaid diagram of the baking-secrets attack surface.
