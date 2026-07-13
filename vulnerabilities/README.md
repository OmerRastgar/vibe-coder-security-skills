# Security Vulnerability Audit Library

A structured library of security vulnerabilities extracted from the *Vibe Coder Guide to Security*. Each vulnerability lives in its own folder under `vulnerabilities/`, containing:

- `README.md`    — merged detail + Attack Surface Flowchart
- `prompt.md`    — copy-paste audit prompt for an LLM / coding assistant
- `skill/`       — the skill definition (`SKILL.md`, `config.yml`) and scanners (`scripts/`)

The full guide is assembled into the root [`../Readme.md`](../Readme.md) by `scripts/build_readme.py`, which combines every folder's `README.md`. Edit a folder's `README.md` and re-run the script to update everything.

## Index

| # | Folder | Vulnerability | Primary Targets |
|---|--------|---------------|-----------------|
| 1 | `v1-ai-commit-trap` | AI Commit Trap | exposed configurations, `.env` files, and Terraform manifests to compromised API keys, AWS credentials, and Kubeconfigs. |
| 2 | `v2-package-hallucination` | Package Hallucination | dependency manifests, lockfiles, CI/CD & infra, source code imports. |
| 3 | `v3-client-side-misplacement` | Client-Side Security Misplacements | Auth & access navigation, forms & inputs, data flow & math. |
| 4 | `v4-disabled-data-isolation` | Disabled Data Isolation | RDBMS, NoSQL/Document & Key-Value, Vector & Graph AI Layer, BaaS & Cloud Layers. |
| 5 | `v5-missing-input-validation` | Missing Input Validation | JSON payloads & bodies, file & media uploads, URL params & queries, forms & headers. |
| 6 | `v6-baking-secrets` | Baking Secrets into Source | inline code variables, dev boilerplates, cloud & infra access, version control leaks. |
| 7 | `v7-ai-default-credentials` | AI Default Credentials | DB init scripts, admin dashboards, server tooling, identity & MQ brokers. |
| 8 | `v8-flawed-object-authorization` | Flawed Object Authorization | ID hopping / BOLA, mass assignment, sequential IDs, tenant manipulation. |
| 9 | `v9-denial-of-wallet` | Denial of Wallet & Rate-Limiting | costly AI endpoints, high-compute tasks, auth portal abuse, unbounded searches. |
| 10 | `v10-cors-iam-perimeter` | CORS & IAM Perimeter Dissolution | CORS misconfigurations, IAM resource wildcards, IMDS metadata leaks, over-provisioned keys. |
| 11 | `v11-structural-type-enforcement` | Structural Type Enforcement | JS/TS (Node.js), Python (FastAPI/Django), reflection / low-level bypasses. |

## How a skill should consume this

1. Pick a vulnerability folder (`vulnerabilities/vN-...`).
2. Read `prompt.md` and feed it (with the target code as INPUT) to the LLM.
3. Open `README.md` in that folder to orient *where to look* before/while auditing.
