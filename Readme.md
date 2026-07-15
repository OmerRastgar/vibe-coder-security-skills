# AI Vibe Coding Security Vulnerabilities

This repository catalogs **11 security vulnerabilities uniquely created or amplified by AI-assisted ("vibe") coding**. When developers code at speed with LLMs like Claude, ChatGPT, or Copilot, the generated code introduces specific, predictable security weaknesses — hardcoded secrets slipped into configs, hallucinated packages pulled into manifests, client-side trust assumptions, and structural type bypasses that traditional tools miss.

Each vulnerability has its own folder under [`vulnerabilities/`](vulnerabilities/) containing:
- **README.md** — full explanation, target surfaces, and attack surface flowchart
- **prompt.md** — copy-paste audit prompt for any LLM or coding assistant
- **skill/** — skill definition + executable scanner scripts for automated detection

## Vulnerability Index

| # | Vulnerability | Primary Targets | Folder |
|---|---------------|-----------------|--------|
| 1 | **AI Commit Trap** | exposed configurations, `.env` files, and Terraform manifests to compromised API keys, AWS credentials, and Kubeconfigs. | [`v1-ai-commit-trap/`](vulnerabilities/v1-ai-commit-trap/) |
| 2 | **Package Hallucination** | dependency manifests, lockfiles, CI/CD & infra, source code imports. | [`v2-package-hallucination/`](vulnerabilities/v2-package-hallucination/) |
| 3 | **Client-Side Security Misplacements** | Auth & access navigation, forms & inputs, data flow & math. | [`v3-client-side-misplacement/`](vulnerabilities/v3-client-side-misplacement/) |
| 4 | **Disabled Data Isolation** | RDBMS, NoSQL/Document & Key-Value, Vector & Graph AI Layer, BaaS & Cloud Layers. | [`v4-disabled-data-isolation/`](vulnerabilities/v4-disabled-data-isolation/) |
| 5 | **Missing Input Validation** | JSON payloads & bodies, file & media uploads, URL params & queries, forms & headers. | [`v5-missing-input-validation/`](vulnerabilities/v5-missing-input-validation/) |
| 6 | **Baking Secrets into Source** | inline code variables, dev boilerplates, cloud & infra access, version control leaks. | [`v6-baking-secrets/`](vulnerabilities/v6-baking-secrets/) |
| 7 | **AI Default Credentials** | DB init scripts, admin dashboards, server tooling, identity & MQ brokers. | [`v7-ai-default-credentials/`](vulnerabilities/v7-ai-default-credentials/) |
| 8 | **Flawed Object Authorization** | ID hopping / BOLA, mass assignment, sequential IDs, tenant manipulation. | [`v8-flawed-object-authorization/`](vulnerabilities/v8-flawed-object-authorization/) |
| 9 | **Denial of Wallet & Rate-Limiting** | costly AI endpoints, high-compute tasks, auth portal abuse, unbounded searches. | [`v9-denial-of-wallet/`](vulnerabilities/v9-denial-of-wallet/) |
| 10 | **CORS & IAM Perimeter Dissolution** | CORS misconfigurations, IAM resource wildcards, IMDS metadata leaks, over-provisioned keys. | [`v10-cors-iam-perimeter/`](vulnerabilities/v10-cors-iam-perimeter/) |
| 11 | **Structural Type Enforcement** | JS/TS (Node.js), Python (FastAPI/Django), reflection / low-level bypasses. | [`v11-structural-type-enforcement/`](vulnerabilities/v11-structural-type-enforcement/) |

## Automated Detection

### Command Code Skills

Each vulnerability folder includes a ready-to-use skill under `skill/SKILL.md`. Drop them into your Command Code setup, then invoke like `/v1-ai-commit-trap` to have your AI assistant audit the target codebase for that specific vulnerability.

### DAST Scanning — Nuclei (Dynamic)

For **live-target scanning**, the `Nuclei Templates/` directory contains curated Nuclei template lists mapped to each vulnerability. Each `vN.txt` file references templates from the [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository that probe for the corresponding weakness on a running application.

A Dockerized Nuclei scan server is included at the project root:

```bash
docker compose up nuclei-scanner --build

# Scan a live URL for specific vulnerabilities
curl -X POST http://localhost:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://your-app.com", "vulnerabilities": ["v3", "v7", "v10"]}'

# Scan for all 11
curl -X POST http://localhost:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://your-app.com"}'
```

**Supported:** v1, v3, v4, v5, v7 (network/exposure-level coverage)

### SAST Scanning — Semgrep + TruffleHog + Checkov (Static)

For **source code analysis**, the `Semgrep Rules/` container bundles three industry-standard SAST tools plus custom Semgrep rules and scanners:

| Tool | Covers v# | Does |
|------|-----------|------|
| **Semgrep** | v3, v5, v8, v9, v11 | AST-based pattern matching across 30+ languages |
| **TruffleHog** | v1, v6 | Secrets in source files and Git history |
| **Checkov** | v4, v7, v10 | IaC policy scanning (Terraform, Kubernetes, CloudFormation) |
| **Custom scanners** | v2, v6 | Package hallucination detection, hardcoded credential regex |

```bash
docker compose up sast-scanner --build

# Scan source code for code-level vulnerabilities
curl -X POST http://localhost:5001/scan \
  -H 'Content-Type: application/json' \
  -d '{"target": "/mnt/code", "vulnerabilities": ["v2", "v6", "v8", "v11"]}'

# Mount your codebase
docker compose run --rm -v $(pwd)/my-project:/mnt/code sast-scanner
```

**Supported:** v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11 (full code-level coverage)

## Full Deployment (Both Services)

```bash
# Start both scanners
docker compose up --build

# Health checks
curl http://localhost:8080/health   # Nuclei DAST
curl http://localhost:5001/health   # SAST tools

# List available vulnerabilities and their template counts
curl http://localhost:8080/templates
curl http://localhost:5001/templates
```

| Service | Port | Purpose |
|---------|------|---------|
| `nuclei-scanner` | `8080` | Accepts a URL, probes live targets with Nuclei templates |
| `sast-scanner` | `5001` | Accepts a mounted code directory, runs Semgrep/TruffleHog/Checkov |

## Repository Structure

```
├── vulnerabilities/        # 11 vulnerability folders (v1-v11) — the source of truth
│   └── v1-ai-commit-trap/
│       ├── README.md       # Full vulnerability breakdown + attack surface flowchart
│       ├── prompt.md       # LLM audit prompt
│       └── skill/          # Command Code skill + scanner scripts
├── Nuclei Templates/       # Curated Nuclei YAML template path lists (v1-v11.txt)
│   ├── server.py           # DAST scan server (Flask)
│   └── requirements.txt
├── sast/                   # SAST container
│   ├── Dockerfile          # Semgrep + TruffleHog + Checkov
│   ├── server.py           # SAST scan server routing vulnerabilities to the right tool
│   ├── rules/              # Custom Semgrep rules (v3, v8, v11)
│   └── scanners/           # Custom Python scanners (v2, v6)
├── Dockerfile              # Nuclei DAST container
└── docker-compose.yml      # Both services
```
   # Both services
```
