# Security Vulnerability Audit Library

A structured library of 11 security vulnerabilities extracted from the *Vibe Coder Guide to Security*. Each vulnerability lives in its own folder under `vulnerabilities/`, containing:

- `README.md`    — merged detail + Attack Surface Flowchart, and a back-link to the main guide
- `prompt.md`    — copy-paste audit prompt for an LLM / coding assistant
- `skill/`       — the skill definition (`SKILL.md`, `config.yml`) and scanners (`scripts/`)

## How a skill should consume this

A skill that audits a target codebase for a vulnerability should:

1. Pick a vulnerability folder (`vulnerabilities/vN-...`).
2. Read `prompt.md` and feed it (with the target code as INPUT) to the LLM.
3. Open `README.md` to orient *where to look* in the codebase before/while auditing (it links back to the full guide in the main `../Readme.md`).

## Index

| # | Folder | Vulnerability | Primary Targets |
|---|--------|---------------|-----------------|
| 1 | `v1-ai-commit-trap` | AI Commit Trap | .env, Terraform, Git history, container registries |
| 2 | `v2-package-hallucination` | Package Hallucination | Manifests, lockfiles, CI/CD, imports |
| 3 | `v3-client-side-misplacement` | Client-Side Security Misplacements | Route guards, feature flags, checkout math, JWT |
| 4 | `v4-disabled-data-isolation` | Disabled Data Isolation | RDBMS/RLS, NoSQL, Vector/Graph, BaaS |
| 5 | `v5-missing-input-validation` | Missing Input Validation | JSON bodies, uploads, URL params, webhooks |
| 6 | `v6-baking-secrets` | Baking Secrets into Source | Inline vars, boilerplates, cloud access, VCS |
| 7 | `v7-ai-default-credentials` | AI Default Credentials | DB init, dashboards, brokers, IdP |
| 8 | `v8-flawed-object-authorization` | Flawed Object Authorization | BOLA/IDOR, mass assignment, sequential IDs |
| 9 | `v9-denial-of-wallet` | Denial of Wallet & Rate-Limiting | AI endpoints, compute, auth flooding, queries |
| 10 | `v10-cors-iam-perimeter` | CORS & IAM Perimeter Dissolution | CORS, IAM wildcards, IMDS/SSRF, keys |
| 11 | `v11-structural-type-enforcement` | Structural Type Enforcement | Spread ops, `as any`, dict unpacking, automappers |

## Source

Extracted from `Vibe Coder Guide to Security 399e635020aa807a95efed903d90ef14.md`.

### References
- https://www.sherlockforensics.com/blog/security-prompts-every-vibe-coder-needs.html
- https://snehbavarva.medium.com/secure-vibe-coding-in-2026-the-files-prompts-and-rules-of-use-and-research-e821021ee908
- https://catdoes.com/blog/vibe-coding-security-checklist
