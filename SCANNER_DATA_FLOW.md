# Scanner Raw Output → AI Prompt → Frontend Report Mapping

Every scanner produces different raw JSON. This document maps each one through the entire pipeline.

---

## 1. v2 Scanner — Package Hallucination

**Found via:** Custom Python scanner (`scanners/v2/scan.py`)  
**Runs for:** v2  
**Output format:**

```json
{
  "package": "python-string-utils",
  "file": "requirements.txt",
  "ecosystem": "pypi",
  "type": "AI-hallucination name",
  "severity": "high",
  "detail": "Matches common AI-fictionalized package name pattern 'string-utils'"
}
```

```json
{
  "package": "fs",
  "file": "(source import)",
  "ecosystem": "npm",
  "type": "Unlisted import",
  "severity": "medium",
  "detail": "Imported 'fs' but not found in npm manifest"
}
```

**Extractors in ai_processor.py:**

```
Field           → Source in raw finding
─────────────────────────────────────
title           → f"{type}: {package}"           e.g. "Unlisted import: fs"
template_id     → f"{type}: {package}"
location        → f"{ecosystem}:{package}"        e.g. "npm:fs"
description     → detail                          e.g. "Imported 'fs' but not found..."
evidence        → detail
```

**Gemini prompt receives:**
```
FINDING #1:
  severity: Medium
  scanner_template: Unlisted import: fs
  file_or_url: npm:fs
  description: Imported 'fs' but not found in npm manifest
  evidence_found: Imported 'fs' but not found in npm manifest
  vulnerability_category: Package Hallucination (v2)
  raw_scanner_output: {"package":"fs","file":"(source import)","ecosystem":"npm",...}
```

**Expected Gemini output:**
```json
{
  "severity": "Medium",
  "title": "Package 'fs' imported but not declared in package.json",
  "impact": "If 'fs' is a typosquatted package, an attacker could execute arbitrary code when the package is installed from npm.",
  "fix": "Verify 'fs' exists in the npm registry. If unintentional, remove the import or add it to package.json dependencies. Search for known typosquats.",
  "aiPrompt": "# Package Hallucination: fs\n\n**Description:** Imported 'fs' but not found in npm manifest\n\n**Location:** npm:fs\n\n**Risk:** If 'fs' is not a real package, an attacker could claim it..."
}
```

**Frontend receives:**
```json
{
  "severity": "Medium",
  "title": "Package 'fs' imported but not declared in package.json",
  "impact": "If 'fs' is a typosquatted package, an attacker could...",
  "fix": "Verify 'fs' exists in the npm registry...",
  "detail": "Imported 'fs' but not found in npm manifest\n\nVulnerability Category: Package Hallucination (v2)\n\nScanner Template: Unlisted import: fs\n\nLocation: npm:fs",
  "aiPrompt": "# Package Hallucination: fs\n\n...",
  "template_id": "Unlisted import: fs"
}
```

---

## 2. v6 Scanner — Baking Secrets into Source

**Found via:** Custom Python scanner (`scanners/v6/scan.py`)  
**Runs for:** v6  
**Output format:**

```json
{
  "file": "config/docker-compose.yml",
  "line": 5,
  "name": "Connection String with Embedded Password",
  "category": "Cloud & Infra",
  "severity": "high",
  "note": "Database URI contains embedded credentials. Use environment variable substitution.",
  "evidence": "postgresql://postgres:postgres@postgres:5432",
  "source": "filesystem"
}
```

```json
{
  "file": "src/config.ts",
  "line": 12,
  "name": "AWS Access Key ID",
  "category": "Cloud & Infra",
  "severity": "high",
  "note": "AWS Access Key ID found. Rotate immediately via IAM and remove from source.",
  "evidence": "AKIA1234567890ABCDEF",
  "source": "filesystem"
}
```

**Extractors in ai_processor.py:**

```
Field           → Source in raw finding
─────────────────────────────────────
title           → f"[{category}] {name}"         e.g. "[Cloud & Infra] Connection String with Embedded Password"
template_id     → f"{category}: {name}"
location        → f"{file}:{line}"                e.g. "config/docker-compose.yml:5"
description     → note
evidence        → evidence (original, before masking)
```

**Gemini prompt receives:**
```
FINDING #1:
  severity: High
  scanner_template: Cloud & Infra: Connection String with Embedded Password
  file_or_url: config/docker-compose.yml:5
  description: Database URI contains embedded credentials. Use environment variable substitution.
  evidence_found: postgresql://postgres:postgres@postgres:5432
  vulnerability_category: Baking Secrets into Source (v6)
  raw_scanner_output: {"file":"config/docker-compose.yml","line":5,"name":"Connection String with Embedded Password",...}
```

**Expected Gemini output:**
```json
{
  "severity": "High",
  "title": "Hardcoded Postgres credentials in docker-compose.yml line 5",
  "impact": "Anyone with access to the git repository can connect to the production database and read, modify, or delete all user data.",
  "fix": "Move credentials to a .env file. Add POSTGRES_USER and POSTGRES_PASSWORD to .env, add .env to .gitignore, reference as ${POSTGRES_USER}:${POSTGRES_PASSWORD} in docker-compose.yml.",
  "aiPrompt": "# Baking Secrets: Hardcoded credentials\n\n**Vulnerability Category:** Baking Secrets into Source (v6)\n\n**Location:** config/docker-compose.yml:5\n\n**Evidence:** postgresql://postgres:xxxx@postgres:5432\n\n**Steps:**\n1. Create a .env file...\n2. Add POSTGRES_USER and POSTGRES_PASSWORD...\n3. Update docker-compose.yml to use ${POSTGRES_USER}...\n4. Add .env to .gitignore...\n5. Rotate the exposed password immediately"
}
```

---

## 3. TruffleHog — Secret Detection

**Found via:** trufflehog binary  
**Runs for:** v1, v6  
**Output format:**

```json
{
  "SourceMetadata": {
    "Data": {
      "Filesystem": {
        "file": "config/aws-credentials.txt",
        "line": 3
      }
    }
  },
  "DetectorName": "AWS",
  "Raw": "AKIA1234567890ABCDEF",
  "Redacted": "AKIA************CDEF",
  "Verified": false
}
```

```json
{
  "SourceMetadata": {
    "Data": {
      "Filesystem": {
        "file": "docker-compose.yml",
        "line": 5
      }
    }
  },
  "DetectorName": "PostgreSQL",
  "Raw": "postgresql://postgres:postgres@postgres:5432",
  "Redacted": "postgresql://postgres:*****@postgres:5432",
  "Verified": false
}
```

**Extractors in ai_processor.py:**

```
Field           → Source in raw finding
─────────────────────────────────────
title           → f"{DetectorName} secret found"             e.g. "AWS: AKIA1234567890ABCDEF"
template_id     → DetectorName                                e.g. "AWS"
location        → SourceMetadata.Data.Filesystem.file:line    e.g. "config/aws-credentials.txt:3"
description     → Raw (first 500 chars)
evidence        → Redacted (or Raw if not set)
```

**Gemini prompt receives:**
```
FINDING #1:
  severity: High
  scanner_template: AWS
  file_or_url: config/aws-credentials.txt:3
  description: (truncated)
  evidence_found: AKIA1234567890ABCDEF
  vulnerability_category: AI Commit Trap (v1)
  raw_scanner_output: {"DetectorName":"AWS","Raw":"AKIA1234567890ABCDEF","Redacted":"AKIA************CDEF","Verified":false,"SourceMetadata":{...}}
```

---

## 4. Semgrep — AST Pattern Matching

**Found via:** semgrep binary  
**Runs for:** v3 (custom rules + auto), v5 (auto), v8 (custom rules), v9 (auto), v11 (custom rules)  
**Output format:**

```json
{
  "check_id": "v8-spread-req-body-into-query",
  "path": "src/controllers/userController.ts",
  "start": {"line": 45, "col": 8},
  "end": {"line": 45, "col": 32},
  "extra": {
    "message": "Spreading request body directly into ORM call — mass assignment risk. Whitelist allowed fields.",
    "severity": "ERROR",
    "metadata": {"category": "mass-assignment", "vulnerability": "v8"}
  }
}
```

**Extractors in ai_processor.py:**

```
Field           → Source in raw finding
─────────────────────────────────────
title           → check_id                                    e.g. "v8-spread-req-body-into-query"
template_id     → check_id
location        → f"{path}:{start.line}"                      e.g. "src/controllers/userController.ts:45"
description     → extra.message
evidence        → extra.message
```

**Gemini prompt receives:**
```
FINDING #1:
  severity: High
  scanner_template: v8-spread-req-body-into-query
  file_or_url: src/controllers/userController.ts:45
  description: Spreading request body directly into ORM call — mass assignment risk
  evidence_found: Spreading request body directly into ORM call — mass assignment risk
  vulnerability_category: Flawed Object Authorization (v8)
  raw_scanner_output: {"check_id":"v8-spread-req-body-into-query","path":"src/controllers/userController.ts",...}
```

---

## 5. Checkov — IaC Policy Scanning

**Found via:** checkov binary  
**Runs for:** v4, v7, v10  
**Output format:**

```json
{
  "check_id": "CKV_AWS_41",
  "check_name": "Ensure no hardcoded AWS access key exists",
  "file_path": "terraform/main.tf",
  "file_line_range": [10, 12],
  "resource": "aws_iam_access_key.user_key",
  "guideline": "https://docs.bridgecrew.io/docs/..."
}
```

**Extractors in ai_processor.py:**

```
Field           → Source in raw finding
─────────────────────────────────────
title           → check_name                                 e.g. "Ensure no hardcoded AWS access key exists"
template_id     → check_id                                   e.g. "CKV_AWS_41"
location        → f"{file_path}:{file_line_range[0]}"        e.g. "terraform/main.tf:10"
description     → guideline (URL to docs)
evidence        → check_name + resource
```

---

## 6. Nuclei — Live Target Scanning

**Found via:** nuclei binary  
**Runs for:** v1, v3, v4, v5, v7  
**Output format:**

```json
{
  "template-id": "cors-misconfig",
  "template-path": "http/vulnerabilities/generic/cors-misconfig.yaml",
  "info": {
    "name": "CORS Misconfiguration",
    "severity": "info",
    "description": "The server reflects arbitrary Origin headers...",
    "reference": ["https://portswigger.net/web-security/cors"],
    "tags": ["cors","generic","misconfig"],
    "classification": {"cwe-id": ["cwe-346","cwe-942"]}
  },
  "type": "http",
  "host": "httpbin.org",
  "matched-at": "https://httpbin.org/get",
  "request": "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nOrigin: https://evil.com\r\n...",
  "response": "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com\r\n...",
  "ip": "3.217.23.77",
  "curl-command": "curl -X 'GET' ...",
  "matcher-name": "arbitrary-origin",
  "matcher-status": true
}
```

**Extractors in ai_processor.py:**

```
Field           → Source in raw finding
─────────────────────────────────────
title           → info.name                                  e.g. "CORS Misconfiguration"
template_id     → template-id                                e.g. "cors-misconfig"
location        → matched-at                                 e.g. "https://httpbin.org/get"
description     → info.description
evidence        → request (first 500 chars)
```

**Gemini prompt receives:**
```
FINDING #1:
  severity: Info
  scanner_template: cors-misconfig
  file_or_url: https://httpbin.org/get
  description: The server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true
  evidence_found: GET /get HTTP/1.1\r\nHost: httpbin.org\r\nOrigin: https://evil.com\r\n...
  vulnerability_category: Client-Side Security Misplacements (v3)
  raw_scanner_output: {"template-id":"cors-misconfig","info":{"name":"CORS Misconfiguration","severity":"info",...},...}
```

---

## Complete Data Flow

```
                   ┌─────────────────────┐
                   │  Scanner runs       │
                   │  (nuclei/semgrep/   │
                   │   trufflehog/       │
                   │   checkov/custom)   │
                   └────────┬────────────┘
                            │
                   ┌────────▼────────────┐
                   │  Raw scanner output │
                   │  (6 different       │
                   │   JSON shapes)      │
                   └────────┬────────────┘
                            │
                   ┌────────▼────────────┐
                   │  Extractors         │
                   │  extract_title()    │
                   │  extract_location() │
                   │  extract_desc()     │
                   │  extract_evidence() │
                   │  extract_template() │
                   └────────┬────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
     ┌────────▼──────┐ ┌───▼────────┐    │
     │ GEMINI key?   │ │ No key     │    │
     │ Yes → AI path │ │ Fallback   │    │
     └──────┬────────┘ └───┬────────┘    │
            │              │             │
   ┌────────▼────────┐     │             │
   │ Gemini receives │     │             │
   │ per finding:    │     │             │
   │ • raw_scanner   │     │             │
   │ • evidence      │     │             │
   │ • file/line     │     │             │
   │ • vuln category │     │             │
   │ • description   │     │             │
   └────────┬────────┘     │             │
            │              │             │
   ┌────────▼────────┐     │             │
   │ Gemini returns  │     │             │
   │ JSON:           │     │             │
   │ • title         │     │             │
   │ • impact        │     │             │
   │ • fix           │     │             │
   │ • aiPrompt      │     │             │
   └────────┬────────┘     │             │
            │              │             │
            └──────┬───────┘             │
                   │                     │
          ┌────────▼────────┐            │
          │ MERGE:          │            │
          │ AI: title,      │            │
          │   impact, fix,  │            │
          │   aiPrompt      │            │
          │ Raw: detail,    │            │
          │   template_id,  │            │
          │   severity      │◄───────────┘
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │ Frontend report │
          │ {               │
          │   score,         │
          │   summary,       │
          │   severityCounts,│
          │   findings[]: {  │
          │     severity,    │
          │     title,       │
          │     impact,      │
          │     fix,         │
          │     detail,      │
          │     aiPrompt,    │
          │     template_id  │
          │   },             │
          │   totalFindings  │
          │ }               │
          └─────────────────┘
```
