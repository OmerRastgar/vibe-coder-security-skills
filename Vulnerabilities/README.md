# Security Vulnerability Audit Library

Structured library of 11 AI vibe-coding security vulnerabilities. Each folder contains the vulnerability breakdown, audit prompt, and skill definition.

The full guide lives at the root [`../Readme.md`](../Readme.md).

## Index

| # | Vulnerability | Primary Targets | Folder |
|---|---------------|-----------------|--------|
| 1 | **AI Commit Trap** | exposed configurations, `.env` files, and Terraform manifests to compromised API keys, AWS credentials, and Kubeconfigs. | [`v1-ai-commit-trap/`](Vulnerabilities/v1-ai-commit-trap/) |
| 2 | **Package Hallucination** | dependency manifests, lockfiles, CI/CD & infra, source code imports. | [`v2-package-hallucination/`](Vulnerabilities/v2-package-hallucination/) |
| 3 | **Client-Side Security Misplacements** | Auth & access navigation, forms & inputs, data flow & math. | [`v3-client-side-misplacement/`](Vulnerabilities/v3-client-side-misplacement/) |
| 4 | **Disabled Data Isolation** | RDBMS, NoSQL/Document & Key-Value, Vector & Graph AI Layer, BaaS & Cloud Layers. | [`v4-disabled-data-isolation/`](Vulnerabilities/v4-disabled-data-isolation/) |
| 5 | **Missing Input Validation** | JSON payloads & bodies, file & media uploads, URL params & queries, forms & headers. | [`v5-missing-input-validation/`](Vulnerabilities/v5-missing-input-validation/) |
| 6 | **Baking Secrets into Source** | inline code variables, dev boilerplates, cloud & infra access, version control leaks. | [`v6-baking-secrets/`](Vulnerabilities/v6-baking-secrets/) |
| 7 | **AI Default Credentials** | DB init scripts, admin dashboards, server tooling, identity & MQ brokers. | [`v7-ai-default-credentials/`](Vulnerabilities/v7-ai-default-credentials/) |
| 8 | **Flawed Object Authorization** | ID hopping / BOLA, mass assignment, sequential IDs, tenant manipulation. | [`v8-flawed-object-authorization/`](Vulnerabilities/v8-flawed-object-authorization/) |
| 9 | **Denial of Wallet & Rate-Limiting** | costly AI endpoints, high-compute tasks, auth portal abuse, unbounded searches. | [`v9-denial-of-wallet/`](Vulnerabilities/v9-denial-of-wallet/) |
| 10 | **CORS & IAM Perimeter Dissolution** | CORS misconfigurations, IAM resource wildcards, IMDS metadata leaks, over-provisioned keys. | [`v10-cors-iam-perimeter/`](Vulnerabilities/v10-cors-iam-perimeter/) |
| 11 | **Structural Type Enforcement** | JS/TS (Node.js), Python (FastAPI/Django), reflection / low-level bypasses. | [`v11-structural-type-enforcement/`](Vulnerabilities/v11-structural-type-enforcement/) |

## Usage

1. Pick a vulnerability folder above.
2. Read its `README.md` to understand the attack surface.
3. Copy `prompt.md` and feed it to your LLM with your target code.
