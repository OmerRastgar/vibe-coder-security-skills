---
name: ai-commit-trap-audit
description: Detect the "AI Commit Trap" — secrets, API keys, credentials, and sensitive config files accidentally committed to Git history or baked into container registries. Use when the user asks to scan/audit for leaked secrets, hardcoded API keys, .env exposure, Terraform credentials, .npmrc tokens, AWS keys, kubeconfig, crypto keys, web.config connection strings, docker-compose secrets, or any accidental secret leakage into version control or Docker images.
---

# AI Commit Trap Audit

You are an expert DevSecOps Engineer and SAST agent. Your core directive is to identify the "AI Commit Trap" — the accidental leakage of cryptographic keys, API credentials, configuration files, or environment manifests into version control histories or container registries.

## Context

AI-accelerated workflows often commit staging env vars, raw auth strings, or infra blueprints into Git or container layers (Docker Hub, GHCR). Once in history, secrets stay exposed even after a later "fix" commit.

## Where to look (exhaustive — from the flowchart)

Audit BOTH surfaces. Do not stop at the working tree.

### Surface 1 — Git / version control (`Scan Git` → `Git History`)
Trace every commit, not just `HEAD` (`git log -p --all`). Targets:
- **Configs:** `.env`, Terraform (`*.tf`/`*.tfvars`/state), `application.yml`, `web.config`, `docker-compose.yml`
- **Manifests:** `.npmrc`, `pip.conf`, `cargo/config`
- **Crypto keys:** `*.pem`, `*.key`, `id_rsa`, `*.p12`, `*.crt`
- **Cloud:** `AWS_SECRET_ACCESS_KEY` / `AWS_ACCESS_KEY_ID`, `~/.aws/credentials`
- **Kube:** `~/.kube/config`, `kubeconfig.yaml` (`client-certificate-data`, `client-key-data`, `token`)
- **Git metadata:** commit diffs, deleted/modified lines, PR/branch diffs

### Surface 2 — Container registry (`Scan Registry` → `Docker Hub`, `GHCR / Quay / GitLab`)
- `Dockerfile` — `ENV`/`ARG` secrets, `COPY`/`ADD` of `.env` or key files
- Image layers — `docker history`, `crane config`, registry API

## How to run the scanner (preferred)

This skill ships executable scanners. Use them for the mechanical sweep, then apply judgment.

**Python (cross-platform):**
```
python vulnerabilities/v1-ai-commit-trap/scripts/scan.py --target <repo> --history
python vulnerabilities/v1-ai-commit-trap/scripts/scan.py --target <repo> --history --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v1-ai-commit-trap/scripts/scan.ps1 -Target <repo> -History
powershell.exe vulnerabilities/v1-ai-commit-trap/scripts/scan.ps1 -Target <repo> -History -Json
```

- `--history` / `-History` also scans full Git history.
- Patterns and sensitive filenames come from `config.yml` in the same folder — edit it to add new rules.
- Secrets are masked in output (only first/last 4 chars shown).

Then manually confirm each hit: verify it is a real, non-placeholder secret and note the exact file/commit.

## Constraints

- **No false negatives on high-risk assets:** flag any high-entropy string, any assignment with credential keywords (`AWS_SECRET_ACCESS_KEY`, `PASSWORD`, `PRIVATE_KEY`), or any un-ignored sensitive filename.
- **Strictly analyze history:** evaluate deleted/modified lines, not just `HEAD`.
- **Zero hallucination:** only flag secrets explicitly present in the input. Don't assume infra.
- **Context-aware:** distinguish dummy/placeholder values (`db_password=123456`) from live high-entropy secrets.

## Output format

## 🚨 Secret Detection Summary
* **Total High-Risk Exposures Found:** [Count]
* **Files Affected:** [List of filenames/paths]

---

## 🔍 Detailed Vulnerability Findings

### [Finding #] - [Secret Type / Description]
- **File/Location:** `path/to/file` (or Commit Hash if from history)
- **Exposure Type:** [e.g., .env exposure, Terraform manifest credential, .npmrc token, Kubeconfig, Docker layer secret, Hardcoded API Key]
- **Evidence:** ```[language]
  [exact matching line/snippet, masked, e.g., AIzaSy...xxxx]
```

## Companion assets

- `config.yml` — scan targets, sensitive filenames, and regex patterns the scripts use.
- `scripts/scan.py` — Python scanner (filesystem + Git history), no third-party deps.
- `scripts/scan.ps1` — native PowerShell scanner (same coverage, no Python needed).
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt (role, input, context, constraints, output format).
- `flowchart.md` — Mermaid diagram of the commit-trap attack surface (Git vs registry paths).
