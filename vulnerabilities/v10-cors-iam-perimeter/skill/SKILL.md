---
name: cors-iam-perimeter-audit
description: Detect "CORS & IAM Perimeter Dissolution" (V10) — overly permissive network and identity boundaries. Use when the user asks to audit for wildcard CORS origins, CORS with credentials enabled on all origins, IAM Action or Resource wildcards (s3:* / Resource *), SSRF paths that can reach the AWS instance metadata service (169.254.169.254), Supabase service-role keys exposed to clients, or over-provisioned cloud access keys committed to source.
---

# V10 — CORS & IAM Perimeter Dissolution Audit

You are an expert Cloud Security Architect, IAM Engineer, and Network Penetration Tester specialising in cross-origin security, cloud boundary enforcement, and least-privilege architecture. Your objective is to find "CORS & IAM Perimeter Dissolution" — configurations where network, origin, or IAM boundaries are wildcard-permissive, missing, or bypassed.

## Context

Key failure modes:

- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` — browser will send cookies to any origin
- CORS middleware that reflects the incoming `Origin` header back without a whitelist check
- IAM policy with `"Action": "s3:*"` and `"Resource": "*"` — full S3 access to everything
- Server-side HTTP client where `url = req.query.url` with no domain allow-list — SSRF to `169.254.169.254` harvests cloud tokens
- `SUPABASE_SERVICE_ROLE_KEY` or Firebase admin SDK key used in a frontend bundle or public config
- Kubernetes RBAC with `verbs: ["*"]` on `resources: ["*"]` — cluster-admin equivalent

## Where to look (from the flowchart)

### 1. CORS Misconfigurations
- Express `cors({ origin: '*', credentials: true })` — invalid combination, browsers block it but it signals intent
- `app.use(cors())` with no options — defaults to `*` origin
- Manual header setting: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` with no whitelist — origin reflection
- `Access-Control-Allow-Origin: *` in Nginx config, AWS API Gateway, or any proxy config

### 2. IAM Resource Wildcards
- AWS IAM JSON: `"Action": "*"` or `"Action": ["s3:*", "iam:*"]` with `"Resource": "*"`
- Terraform `aws_iam_policy` with `actions = ["*"]` or `resources = ["*"]`
- Kubernetes RBAC: `ClusterRole` with `verbs: ["*"]` and `resources: ["*"]`
- Serverless `iamRoleStatements` with `- Effect: Allow / Action: '*' / Resource: '*'`

### 3. IMDS Metadata Leaks (SSRF)
- Any outbound HTTP call where the target URL is user-controlled: `fetch(req.query.url)`, `axios.get(req.body.url)`, `requests.get(url)` with `url` from user input
- No domain allow-list or block-list for `169.254.169.254`, `metadata.google.internal`, `fd00:ec2::254`
- Server-side proxy routes that forward arbitrary URLs

### 4. Over-Provisioned Keys
- `SUPABASE_SERVICE_ROLE_KEY` in client-side code, `.env.local`, or a public config file
- Firebase admin SDK initialized in a frontend file or with a key committed to source
- AWS credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) with broad permissions used in application code instead of IAM roles
- `NEXT_PUBLIC_*` env vars containing secret keys — automatically exposed to the browser

## How to run the scanner (preferred)

**Python (cross-platform):**
```
python vulnerabilities/v10-cors-iam-perimeter/scripts/scan.py --target <repo>
python vulnerabilities/v10-cors-iam-perimeter/scripts/scan.py --target <repo> --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v10-cors-iam-perimeter/scripts/scan.ps1 -Target <repo>
powershell.exe vulnerabilities/v10-cors-iam-perimeter/scripts/scan.ps1 -Target <repo> -Json
```

- Patterns and file globs come from `config.yml` — edit to add cloud providers, proxy frameworks, or custom key names.
- Scanner flags candidates for human confirmation. Verify the full CORS config, IAM statement, and whether the URL is truly user-controlled before concluding it is a vulnerability.

## Constraints

- **Wildcard + credentials = critical:** CORS `*` origin with `credentials: true` is always high severity.
- **Origin reflection:** dynamically echoing `req.headers.origin` without a whitelist is equivalent to a wildcard.
- **IAM dual-wildcard:** `Action: *` AND `Resource: *` together is always high severity.
- **SSRF taint:** any outbound HTTP call with a user-controlled URL parameter is a finding until a strict allow-list is confirmed.
- **Service key placement:** service-role or admin keys outside isolated server backends are always high severity.
- **Zero hallucination:** only flag patterns explicitly present in the provided input.

## Output format

## 🌐 Perimeter Dissolution & Identity Architecture Summary
* **Total Border/IAM Flaws Identified:** [Count]
* **Impacted Perimeter Assets:** [List affected blocks]

---

## 🔍 Detailed Perimeter Security Findings

### [Finding #] - Edge Perimeter Breach in [CORS / IAM Policy / IMDS-SSRF / Service Key Exposure]
- **Target File/Component:** `path/to/policy_or_config`
- **Perimeter Failure Type:** [e.g., Credential Echoing CORS, Over-Scoped IAM Wildcard, IMDS Token Harvest, Leaked Service Key]
- **Evidence:** ```[language]
  [exact CORS statement, IAM rule, or SSRF-susceptible code showing the perimeter gap]
```
- **Remediation:** [explicit allow-list, least-privilege IAM policy, SSRF block-list, move key to server-side only]

## Companion assets

- `config.yml` — file extensions, SSRF sink patterns, IAM wildcard patterns, and CORS patterns the scripts use.
- `scripts/scan.py` — Python scanner (no third-party deps).
- `scripts/scan.ps1` — native PowerShell scanner (no Python needed).
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt.
- `flowchart.md` — Mermaid diagram of the CORS & IAM perimeter attack surface.
