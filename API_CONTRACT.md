## Backend Contract — SecureMyVibe Scanner API

Three scan types, two services, one report format.

---

### Service URLs

| Service | Purpose | Port |
|---------|---------|------|
| `nuclei-scanner` | URL-based DAST scanning (Nuclei) | 8080 |
| `sast-scanner` / `semgrep` | Source code SAST scanning (Semgrep + TruffleHog + Checkov) | 8080 |

---

### POST /scan — Submit a Scan

Returns `202 Accepted` immediately with `scan_id` + `token`. Frontend MUST store the token — it is never returned again.

#### Type 1: URL Scan (nuclei-scanner only)

```
POST /scan  Content-Type: application/json
```

| Field | Type | Required | Example |
|-------|------|----------|---------|
| `url` | string | Yes | `"https://myapp.com"` |
| `vulnerabilities` | string[] or null | No (null = all 11) | `["v1","v3","v7"]` or `"v1,v7"` |
| `concurrency` | int | No (default 10) | `15` |
| `timeout` | int | No (default 15) | `10` |

```json
// Request
{"url": "https://demo.cybergaar.com", "vulnerabilities": ["v3","v7"]}

// Response 202
{
  "scan_id": "a1b2c3d4e5f6",
  "token": "9f8e7d6c5b4a3210",
  "vulnerabilities": ["v3","v7"],
  "check_status": "/scan/a1b2c3d4e5f6"
}
```

#### Type 2: Zip Upload (sast-scanner only)

```
POST /scan  Content-Type: multipart/form-data
```

| Field | Type | Required | Example |
|-------|------|----------|---------|
| `file` | file (.zip) | Yes | `@codebase.zip` |
| `vulnerabilities` | string | No | `"v2,v6,v8"` or `'["v2","v6"]'` |

Response shape identical to Type 1.

#### Type 3: GitHub Repo (sast-scanner only)

```
POST /scan  Content-Type: application/json
```

| Field | Type | Required | Example |
|-------|------|----------|---------|
| `repo_url` | string | Yes | `"https://github.com/user/repo"` |
| `vulnerabilities` | string[] or null | No | `["v2","v6","v11"]` |

Response shape identical to Type 1.

---

### GET /scan/{id} — Poll for Results

```
Header: X-Scan-Token: {token}
```

#### While Running

```json
{"status": "running", "progress": 0}
```

#### Completed

```json
{
  "status": "completed",
  "report": {
    "score": 85,
    "duration_sec": 58.65,
    "summary": "3 security issue(s) found: 1 High, 1 Medium, 1 Low. Review each finding and use the AI fix prompts to resolve them quickly.",
    "severityCounts": {
      "Critical": 0,
      "High": 1,
      "Medium": 1,
      "Low": 1
    },
    "findings": [
      {
        "severity": "High",
        "title": "Hardcoded Postgres credentials in docker-compose.yml",
        "impact": "Anyone with repository access can connect to the database. All user data is at risk.",
        "fix": "Replace hardcoded values with environment variables. Move credentials to a .env file and reference via ${VAR} in docker-compose.yml.",
        "detail": "Database URI contains embedded credentials.\n\nVulnerability Category: Baking Secrets into Source (v6)\n\nEvidence Snippet:\n```\npostgresql://postgres:postgres@postgres:5432\n```\n\nScanner Template: Cloud & Infra: Connection String with Embedded Password\n\nLocation: config/docker-compose.yml:5",
        "aiPrompt": "I need help fixing a High-severity...",
        "template_id": "Cloud & Infra: Connection String with Embedded Password"
      }
    ],
    "templatesExecuted": 2,
    "templatesFailed": 0,
    "totalFindings": 3,
    "processedBy": "local",
    "timestamp": "2026-07-16T21:00:00.000Z"
  }
}
```

#### Failed

```json
{"status": "failed", "error": "Scan timed out after 300s"}
```

#### Token Missing / Wrong

```json
{"error": "invalid token"}
```
HTTP 403

---

### Report Fields — Guaranteed

Every `"completed"` response has a `report` object with ALL of these:

| Field | Type | Guarantee |
|-------|------|-----------|
| `score` | number 0-100 | Always present |
| `duration_sec` | number | Always present |
| `summary` | string | Always present (non-empty) |
| `severityCounts` | object | Always has 4 keys: Critical, High, Medium, Low |
| `findings` | array | Always an array (empty if no issues) |
| `findings[].severity` | string | Always one of: Critical, High, Medium, Low |
| `findings[].title` | string | Always present, max 100 chars |
| `findings[].impact` | string | Always present, max 200 chars |
| `findings[].fix` | string | Always present, max 200 chars |
| `findings[].detail` | string | Always present (tech detail with file/line/evidence) |
| `findings[].aiPrompt` | string | Always present (copyable AI prompt) |
| `findings[].template_id` | string | Always present (may be empty string) |
| `templatesExecuted` | number | Always present (count of tools/templates run) |
| `templatesFailed` | number | Always present (count of failures) |
| `totalFindings` | number | Always present |
| `processedBy` | string | `"gemini"` or `"local"` |
| `timestamp` | string | ISO 8601 UTC |

---

### GET /health

```json
// Nuclei scanner
{
  "status": "ok",
  "nuclei_version": "[INF] Nuclei Engine Version: v3.3.9",
  "concurrent_scans": 2,
  "max_concurrent": 5,
  "timestamp": "2026-07-16T..."
}

// SAST scanner
{
  "status": "ok",
  "versions": {
    "semgrep": "1.170.0",
    "trufflehog": "trufflehog 3.88.16",
    "checkov": "checkov 3.3.8"
  },
  "concurrent_scans": 0,
  "max_concurrent": 3,
  "github_auth": false,
  "timestamp": "2026-07-16T..."
}
```

---

### GET /templates — Available Vulnerabilities

```json
// Nuclei
{
  "v1": {"name": "AI Commit Trap", "file": "V1.txt", "template_count": 95},
  "v2": {"name": "Package Hallucination", "file": "v2.txt", "template_count": 14},
  ...
}

// SAST
{
  "v1": {"name": "AI Commit Trap", "tools": ["trufflehog"]},
  "v2": {"name": "Package Hallucination", "tools": ["scanner_v2"]},
  "v3": {"name": "Client-Side Security Misplacements", "tools": ["semgrep_v3"]},
  "v4": {"name": "Disabled Data Isolation", "tools": ["checkov"]},
  "v5": {"name": "Missing Input Validation", "tools": ["semgrep_v5"]},
  "v6": {"name": "Baking Secrets into Source", "tools": ["trufflehog","scanner_v6"]},
  "v7": {"name": "AI Default Credentials", "tools": ["checkov_credentials"]},
  "v8": {"name": "Flawed Object Authorization", "tools": ["semgrep_v8"]},
  "v9": {"name": "Denial of Wallet & Rate-Limiting", "tools": ["semgrep_v9"]},
  "v10": {"name": "CORS & IAM Perimeter Dissolution", "tools": ["checkov_iam"]},
  "v11": {"name": "Structural Type Enforcement", "tools": ["semgrep_v11"]}
}
```

---

### Error Codes

| Code | When |
|------|------|
| 202 | Scan accepted |
| 400 | Missing/invalid `url`, `file`, `repo_url`, or `vulnerabilities` |
| 403 | Wrong `X-Scan-Token` on GET /scan/{id} |
| 404 | `scan_id` not found |
| 429 | Rate limit (10 scans/min/IP for nuclei) |
| 503 | All workers busy (`retry_after_sec` in response) |
| 504 | Scan timed out (server-side timeout) |

---

### Vulnerability IDs

| v1 | AI Commit Trap |
| v2 | Package Hallucination |
| v3 | Client-Side Security Misplacements |
| v4 | Disabled Data Isolation |
| v5 | Missing Input Validation |
| v6 | Baking Secrets into Source |
| v7 | AI Default Credentials |
| v8 | Flawed Object Authorization |
| v9 | Denial of Wallet & Rate-Limiting |
| v10 | CORS & IAM Perimeter Dissolution |
| v11 | Structural Type Enforcement |
