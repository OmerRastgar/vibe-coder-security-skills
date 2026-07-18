# Scanner Raw Data → AI Processor → Frontend Report

## Complete Field Mapping Per Scanner

Every scanner produces different raw JSON. This document traces exactly which fields exist in the raw output, how they're extracted, and what the final report looks like.

---

## Scanner 1: v2 Custom Scanner (Package Hallucination)

**What it does:** Scans dependency manifests and source imports for hallucinated/typosquatted packages.  
**Output format:** JSON array via Python `scan.py --json`  
**Runs for vulnerability:** v2

### Raw Output Fields

Each finding has these exact keys:

| Key | Type | Example Value | Description |
|-----|------|---------------|-------------|
| `package` | string | `"python-string-utils"` | Package name detected |
| `file` | string | `"requirements.txt"` or `"(source import)"` | File where found |
| `ecosystem` | string | `"npm"`, `"pypi"`, `"go"`, `"cargo"`, `"rubygems"` | Package registry |
| `type` | string | `"AI-hallucination name"`, `"Unlisted import"`, `"Typosquat candidate"` | Detection type |
| `severity` | string | `"high"`, `"medium"` | Scanner severity |
| `detail` | string | `"Matches common AI-fictionalized package name pattern..."` | Human explanation |

### Example Raw Output (Actual)

```json
[
  {
    "package": "python-string-utils",
    "file": "requirements.txt",
    "ecosystem": "pypi",
    "type": "AI-hallucination name",
    "severity": "high",
    "detail": "Matches common AI-fictionalized package name pattern 'string-utils'"
  },
  {
    "package": "fs",
    "file": "(source import)",
    "ecosystem": "npm",
    "type": "Unlisted import",
    "severity": "medium",
    "detail": "Imported 'fs' but not found in npm manifest"
  }
]
```

### ai_processor.py Extractor Mapping

```
Raw Field           → Normalized Field      → Method
──────────────────────────────────────────────────────
package             → title part            → extract_title()
                      f"{type}: {package}"    → "Unlisted import: fs"

type                → template_id           → extract_template_id()
                      f"{type}: {package}"    → "Unlisted import: fs"

ecosystem + package → location              → extract_location()
                      f"{ecosystem}:{package}" → "npm:fs"

detail              → description           → extract_description()
                                              → "Imported 'fs' but not found..."

detail              → evidence              → extract_evidence()
```

### What Gemini Receives

```json
{
  "severity": "Medium",
  "scanner_template": "Unlisted import: fs",
  "file_or_url": "npm:fs",
  "description": "Imported 'fs' but not found in npm manifest",
  "evidence_found": "Imported 'fs' but not found in npm manifest",
  "vulnerability_category": "Package Hallucination (v2)",
  "raw_scanner_output": {
    "package": "fs",
    "file": "(source import)",
    "ecosystem": "npm",
    "type": "Unlisted import",
    "severity": "medium",
    "detail": "Imported 'fs' but not found in npm manifest"
  }
}
```

### Final Frontend Report Field

```json
{
  "severity": "Medium",
  "title": "Package 'fs' imported but not declared in package.json",
  "impact": "If 'fs' is a typosquatted package, an attacker could...",
  "fix": "Verify 'fs' exists in the npm registry...",
  "detail": "Imported 'fs' but not found in npm manifest\n\nVulnerability Category: Package Hallucination (v2)\n\nScanner Template: Unlisted import: fs\n\nLocation: npm:fs",
  "aiPrompt": "I need help fixing a Medium-severity security issue...\n\n**Vulnerability Category:** Package Hallucination...\n\n**Location:** npm:fs\n\n**Steps:**\n1. Verify...",
  "template_id": "Unlisted import: fs"
}
```

---

## Scanner 2: v6 Custom Scanner (Baking Secrets)

**What it does:** Scans source files and Git history for hardcoded credentials using regex patterns.  
**Output format:** JSON array via Python `scan.py --json`  
**Runs for vulnerability:** v6

### Raw Output Fields

Each finding has these exact keys:

| Key | Type | Example Value | Description |
|-----|------|---------------|-------------|
| `file` | string | `"docker-compose.yml"` | Relative file path |
| `line` | int | `5` | Line number |
| `name` | string | `"Connection String with Embedded Password"` | Pattern name that matched |
| `category` | string | `"Cloud & Infra"`, `"Inline Code"`, `"Dev Boilerplate"`, `"VCS Leak"` | Vulnerability category |
| `severity` | string | `"high"`, `"medium"` | Scanner severity |
| `note` | string | `"Database URI contains embedded credentials..."` | Remediation note |
| `evidence` | string | `"postgresql://postgres:postgres@postgres:5432"` | The matched text (or masked) |
| `source` | string | `"filesystem"`, `"git-history"` | Where found |

### Example Raw Output (Actual)

```json
[
  {
    "file": "docker-compose.yml",
    "line": 5,
    "name": "Connection String with Embedded Password",
    "category": "Cloud & Infra",
    "severity": "high",
    "note": "Database URI contains embedded credentials. Use environment variable substitution.",
    "evidence": "postgresql://postgres:postgres@postgres:5432",
    "source": "filesystem"
  },
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
]
```

### ai_processor.py Extractor Mapping

```
Raw Field           → Normalized Field      → Method
──────────────────────────────────────────────────────
category + name     → title                 → extract_title()
                      f"[{category}] {name}"  → "[Cloud & Infra] Connection String with Embedded Password"

category + name     → template_id           → extract_template_id()
                      f"{category}: {name}"   → "Cloud & Infra: Connection String with Embedded Password"

file + line         → location              → extract_location()
                      f"{file}:{line}"        → "docker-compose.yml:5"

note                → description           → extract_description()
                                              → "Database URI contains embedded credentials..."

evidence            → evidence              → extract_evidence()
                                              → "postgresql://postgres:postgres@postgres:5432"
```

### What Gemini Receives

```json
{
  "severity": "High",
  "scanner_template": "Cloud & Infra: Connection String with Embedded Password",
  "file_or_url": "docker-compose.yml:5",
  "description": "Database URI contains embedded credentials. Use environment variable substitution.",
  "evidence_found": "postgresql://postgres:postgres@postgres:5432",
  "vulnerability_category": "Baking Secrets into Source (v6)",
  "raw_scanner_output": {
    "file": "docker-compose.yml",
    "line": 5,
    "name": "Connection String with Embedded Password",
    "category": "Cloud & Infra",
    "severity": "high",
    "note": "Database URI contains embedded credentials...",
    "evidence": "postgresql://postgres:postgres@postgres:5432",
    "source": "filesystem"
  }
}
```

### Final Frontend Report Field

```json
{
  "severity": "High",
  "title": "Hardcoded Postgres credentials in docker-compose.yml line 5",
  "impact": "Anyone with access to the repository can connect to the database. All user data at risk.",
  "fix": "Move credentials to a .env file. Reference as ${POSTGRES_USER}:${POSTGRES_PASSWORD} in docker-compose.yml.",
  "detail": "Database URI contains embedded credentials.\n\nVulnerability Category: Baking Secrets into Source (v6)\n\nEvidence Snippet:\n```\npostgresql://postgres:postgres@postgres:5432\n```\n\nScanner Template: Cloud & Infra: Connection String with Embedded Password\n\nLocation: docker-compose.yml:5",
  "aiPrompt": "I need help fixing a High-severity security issue...\n\n**Vulnerability Category:** Baking Secrets into Source (v6)\n\n**Location:** docker-compose.yml:5\n\n**Evidence:** postgresql://postgres:xxxx@postgres:5432\n\n**Steps:**\n1. Create a .env file...",
  "template_id": "Cloud & Infra: Connection String with Embedded Password"
}
```

---

## Scanner 3: TruffleHog (Secret Detection)

**What it does:** Scans filesystem and Git history for high-entropy strings and known secret patterns.  
**Output format:** JSONL (one JSON object per line) via `trufflehog filesystem --json`  
**Runs for vulnerability:** v1, v6

### Raw Output Fields

Each finding has these exact keys:

| Key | Type | Example Value | Description |
|-----|------|---------------|-------------|
| `SourceMetadata.Data.Filesystem.file` | string | `"config/aws-credentials.txt"` | File path |
| `SourceMetadata.Data.Filesystem.line` | int | `3` | Line number |
| `DetectorName` | string | `"AWS"`, `"GitHub"`, `"PostgreSQL"`, `"Stripe"` | Secret type detected |
| `Raw` | string | `"AKIA1234567890ABCDEF"` | Unredacted finding |
| `Redacted` | string | `"AKIA************CDEF"` | Redacted finding |
| `Verified` | bool | `false` | Whether trufflehog verified the key is live |
| `SourceID` | int | `0` | Internal source index |

### Example Raw Output (Actual)

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
  "SourceID": 0,
  "DetectorName": "AWS",
  "DetectorType": 1,
  "Raw": "AKIA1234567890ABCDEF",
  "Redacted": "AKIA************CDEF",
  "Verified": false
}
```

### ai_processor.py Extractor Mapping

```
Raw Field                     → Normalized Field      → Method
──────────────────────────────────────────────────────────────
DetectorName                  → title                 → extract_title()
                                f"{DetectorName} secret found"  → "AWS secret found"

DetectorName                  → template_id           → extract_template_id()
                                                         → "AWS"

SourceMetadata.Data.          → location              → extract_location()
  Filesystem.file + .line       f"{file}:{line}"        → "config/aws-credentials.txt:3"

Raw                           → description           → extract_description()
                                (first 500 chars)

Redacted (or Raw)             → evidence              → extract_evidence()
```

### What Gemini Receives

```json
{
  "severity": "High",
  "scanner_template": "AWS",
  "file_or_url": "config/aws-credentials.txt:3",
  "description": "AKIA1234567890ABCDEF",
  "evidence_found": "AKIA************CDEF",
  "vulnerability_category": "Baking Secrets into Source (v6)",
  "raw_scanner_output": {
    "DetectorName": "AWS",
    "Raw": "AKIA1234567890ABCDEF",
    "Redacted": "AKIA************CDEF",
    "Verified": false,
    "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws-credentials.txt", "line": 3}}}
  }
}
```

---

## Scanner 4: Semgrep (AST Pattern Matching)

**What it does:** Matches code patterns against AST rules (custom + community).  
**Output format:** JSON via `semgrep scan --json`  
**Runs for vulnerability:** v3, v5, v8, v9, v11

### Raw Output Fields

Each finding has these exact keys:

| Key | Type | Example Value | Description |
|-----|------|---------------|-------------|
| `check_id` | string | `"v8-spread-req-body-into-query"` | Rule identifier |
| `path` | string | `"src/controllers/userController.ts"` | File path |
| `start.line` | int | `45` | Line where match starts |
| `start.col` | int | `8` | Column where match starts |
| `end.line` | int | `45` | Line where match ends |
| `end.col` | int | `32` | Column where match ends |
| `extra.message` | string | `"Spreading request body..."` | Rule message |
| `extra.severity` | string | `"ERROR"`, `"WARNING"` | Semgrep severity |
| `extra.metadata` | object | `{"category":"mass-assignment","vulnerability":"v8"}` | Rule metadata |

### Example Raw Output (Actual)

```json
{
  "check_id": "v8-spread-req-body-into-query",
  "path": "src/controllers/userController.ts",
  "start": {"line": 45, "col": 8, "offset": 1234},
  "end": {"line": 45, "col": 32, "offset": 1258},
  "extra": {
    "message": "Spreading request body directly into ORM call — mass assignment risk. Whitelist allowed fields.",
    "severity": "ERROR",
    "metadata": {
      "category": "mass-assignment",
      "vulnerability": "v8"
    },
    "lines": "  await UserModel.update(...req.body);"
  }
}
```

### ai_processor.py Extractor Mapping

```
Raw Field           → Normalized Field      → Method
──────────────────────────────────────────────────────
check_id            → title                 → extract_title()
                                              → "v8-spread-req-body-into-query"

check_id            → template_id           → extract_template_id()
                                              → "v8-spread-req-body-into-query"

path + start.line   → location              → extract_location()
                      f"{path}:{start.line}"  → "src/controllers/userController.ts:45"

extra.message       → description           → extract_description()
                                              → "Spreading request body..."

extra.message       → evidence              → extract_evidence()
```

---

## Scanner 5: Checkov (IaC Policy Scanning)

**What it does:** Scans Terraform, CloudFormation, Kubernetes manifests for misconfigurations.  
**Output format:** JSON via `checkov --output json`  
**Runs for vulnerability:** v4, v7, v10

### Raw Output Fields

Each finding has these exact keys:

| Key | Type | Example Value | Description |
|-----|------|---------------|-------------|
| `check_id` | string | `"CKV_AWS_41"` | Policy check ID |
| `check_name` | string | `"Ensure no hardcoded AWS access key exists"` | Human-readable check name |
| `file_path` | string | `"terraform/main.tf"` | File where issue found |
| `file_line_range` | array[int] | `[10, 12]` | Start and end lines |
| `resource` | string | `"aws_iam_access_key.user_key"` | Affected resource |
| `guideline` | string | `"https://docs.bridgecrew.io/..."` | Documentation URL |
| `severity` | string | `"HIGH"`, `"MEDIUM"` | Check severity |

### Example Raw Output (Actual)

```json
{
  "check_id": "CKV_AWS_41",
  "check_name": "Ensure no hardcoded AWS access key exists",
  "file_path": "terraform/main.tf",
  "file_line_range": [10, 12],
  "resource": "aws_iam_access_key.user_key",
  "guideline": "https://docs.bridgecrew.io/docs/ensure-aws-iam-policy-documents-do-not-contain-hardcoded-access-keys",
  "severity": "HIGH"
}
```

### ai_processor.py Extractor Mapping

```
Raw Field           → Normalized Field      → Method
──────────────────────────────────────────────────────
check_name          → title                 → extract_title()
                                              → "Ensure no hardcoded AWS access key exists"

check_id            → template_id           → extract_template_id()
                                              → "CKV_AWS_41"

file_path +         → location              → extract_location()
  file_line_range[0]  f"{file_path}:{line}"   → "terraform/main.tf:10"

guideline           → description           → extract_description()
                                              → "https://docs.bridgecrew.io/..."

check_name          → evidence              → extract_evidence()
```

---

## Scanner 6: Nuclei (Live Target DAST Scanning)

**What it does:** Probes live URLs with YAML-based templates for known vulnerabilities.  
**Output format:** JSONL (one JSON object per line) via `nuclei -jsonl`  
**Runs for vulnerability:** v1, v3, v4, v5, v7

### Raw Output Fields

Each finding has these exact keys:

| Key | Type | Example Value | Description |
|-----|------|---------------|-------------|
| `template-id` | string | `"cors-misconfig"` | Template identifier |
| `template-path` | string | `"http/vulnerabilities/generic/cors-misconfig.yaml"` | Template file path |
| `info.name` | string | `"CORS Misconfiguration"` | Human-readable name |
| `info.severity` | string | `"info"`, `"medium"`, `"high"`, `"critical"` | Finding severity |
| `info.description` | string | `"The server reflects arbitrary Origin headers..."` | Description |
| `info.reference` | array[string] | `["https://portswigger.net/..."]` | Reference URLs |
| `type` | string | `"http"` | Protocol type |
| `host` | string | `"httpbin.org"` | Target host |
| `matched-at` | string | `"https://httpbin.org/get"` | Exact URL matched |
| `request` | string | `"GET /get HTTP/1.1\r\n..."` | Raw HTTP request |
| `response` | string | `"HTTP/1.1 200 OK\r\n..."` | Raw HTTP response |
| `matcher-name` | string | `"arbitrary-origin"` | Matcher that triggered |
| `matcher-status` | bool | `true` | Whether matcher passed |
| `curl-command` | string | `"curl -X 'GET' ..."` | Reproducible curl |
| `ip` | string | `"3.217.23.77"` | Resolved IP |
| `timestamp` | string | `"2026-07-15T..."` | ISO timestamp |

### Example Raw Output (Actual)

```json
{
  "template-id": "cors-misconfig",
  "template-path": "/tmp/scans/abc123/http/vulnerabilities/generic/cors-misconfig.yaml",
  "template-url": "https://cloud.projectdiscovery.io/public/cors-misconfig",
  "info": {
    "name": "CORS Misconfiguration",
    "author": ["nadino", "pdteam"],
    "tags": ["cors", "generic", "misconfig"],
    "reference": ["https://portswigger.net/web-security/cors"],
    "severity": "info",
    "description": "The server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true, allowing credentialed cross-origin requests from any domain.",
    "classification": {"cve-id": null, "cwe-id": ["cwe-346", "cwe-942"]},
    "metadata": {"max-request": 29}
  },
  "type": "http",
  "host": "httpbin.org",
  "port": "443",
  "scheme": "https",
  "url": "https://httpbin.org/get",
  "path": "/get",
  "matched-at": "https://httpbin.org/get",
  "request": "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: Mozilla/5.0...\r\nOrigin: https://httpbin.org.evil.com\r\nAccept-Encoding: gzip\r\n\r\n",
  "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 409\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Origin: https://httpbin.org.evil.com\r\n...",
  "ip": "3.217.23.77",
  "matcher-name": "arbitrary-origin",
  "matcher-status": true,
  "curl-command": "curl -X 'GET' -d '' -H 'Host: httpbin.org' -H 'Origin: https://httpbin.org.evil.com' 'https://httpbin.org/get'",
  "timestamp": "2026-07-15T16:02:52.912550532Z"
}
```

### ai_processor.py Extractor Mapping

```
Raw Field           → Normalized Field      → Method
──────────────────────────────────────────────────────
info.name           → title                 → extract_title()
                                              → "CORS Misconfiguration"

template-id         → template_id           → extract_template_id()
                                              → "cors-misconfig"

matched-at          → location              → extract_location()
                                              → "https://httpbin.org/get"

info.description    → description           → extract_description()
                                              → "The server reflects arbitrary Origin headers..."

request             → evidence              → extract_evidence()
                      (first 500 chars)       → "GET /get HTTP/1.1\r\n..."
```

---

## Complete ai_processor.py Field Mapping Table

This is the single table that maps every raw scanner field to the normalized fields used in the Gemini prompt and final report.

```
╔═════════════════════╦════════════════════╦════════════════════╦══════════════════╦════════════════════╦════════════════════╗
║ Normalized Field    ║ v2 Scanner         ║ v6 Scanner         ║ TruffleHog       ║ Semgrep           ║ Checkov            ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ title               ║ "{type}: {package}"║ "[{category}]      ║ "{DetectorName}  ║ check_id          ║ check_name         ║
║                     ║                    ║  {name}"           ║  secret found"   ║                    ║                    ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ template_id         ║ "{type}: {package}"║ "{category}:       ║ DetectorName     ║ check_id          ║ check_id           ║
║                     ║                    ║  {name}"           ║                  ║                    ║                    ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ location            ║ "{eco}:{package}"  ║ "{file}:{line}"    ║ SourceMetadata.  ║ "{path}:{start.   ║ "{file_path}:      ║
║                     ║                    ║                    ║ Data.Filesystem. ║  line}"           ║  {line_range[0]}"  ║
║                     ║                    ║                    ║ file:{line}      ║                    ║                    ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ description         ║ detail             ║ note               ║ Raw (500 chars)  ║ extra.message     ║ guideline          ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ evidence            ║ detail             ║ evidence           ║ Redacted or Raw  ║ extra.message     ║ check_name         ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ severity            ║ severity           ║ severity           ║ (computed)       ║ extra.severity    ║ severity           ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ vulnerability_name  ║ Package            ║ Baking Secrets     ║ (from v1 or v6)  ║ (from rule        ║ (from caller's    ║
║                     ║ Hallucination (v2) ║ into Source (v6)   ║                  ║  metadata)        ║  vuln context)    ║
╠═════════════════════╬════════════════════╬════════════════════╬══════════════════╬════════════════════╬════════════════════╣
║ _raw                ║ full dict          ║ full dict          ║ full dict        ║ full dict         ║ full dict          ║
║ (complete original) ║ (500 chars)        ║ (500 chars)        ║ (500 chars)      ║ (500 chars)       ║ (500 chars)        ║
╚═════════════════════╩════════════════════╩════════════════════╩══════════════════╩════════════════════╩════════════════════╝
```

## Nuclei Extractor Mapping

```
╔═════════════════════╦══════════════════════════════════╗
║ Normalized Field    ║ Nuclei                           ║
╠═════════════════════╬══════════════════════════════════╣
║ title               ║ info.name                       ║
║ template_id         ║ template-id                      ║
║ location            ║ matched-at                       ║
║ description         ║ info.description                 ║
║ evidence            ║ request (first 500 chars)        ║
║ severity            ║ info.severity                    ║
║ _raw                ║ full finding dict (500 chars)    ║
╚═════════════════════╩══════════════════════════════════╝
```
