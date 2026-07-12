---
name: missing-input-validation-audit
description: Detect "Missing Input Validation" (V5) — shallow or absent validation of user-controlled inputs on the backend. Use when the user asks to audit for type bypassing in JSON bodies, mass assignment vulnerabilities, file upload extension spoofing, unbounded file sizes, pagination abuse via URL params, missing webhook HMAC signature checks, header injection, or any route handler that spreads req.body without an allow-list.
---

# V5 — Missing Input Validation Audit

You are an expert Application Security Engineer specialising in secure input handling, API schema validation, and Taint Analysis. Your objective is to find "Missing Input Validation" — flaws where an application relies on a Happy Path assumption or shallow checks instead of strict data contracts.

## Context

Attackers routinely abuse shallow validation by:
- Sending an array or object where a string is expected to trigger NoSQL injection or prototype pollution
- Appending extra keys (`isAdmin: true`) to a JSON body to exploit mass assignment
- Uploading a `.php` shell renamed to `.jpg` — bypassing extension-only checks
- Sending a multipart upload with no size limit to crash the service (DoS)
- Setting `?limit=9999999` when the API passes the value directly to a DB query
- Hitting a webhook endpoint that never verifies the HMAC signature
- Injecting newlines into `User-Agent` or other logged headers

## Where to look (from the flowchart)

### 1. JSON Payloads & Bodies
- Route handlers that use `req.body` / `request.json()` / `@RequestBody` without a validation schema (Zod, Joi, Pydantic, class-validator, Yup)
- Object spread into DB calls: `...req.body`, `Object.assign(model, req.body)`, `**data` in Python
- No type check before use: `req.body.age + 1` without confirming `age` is a number

### 2. File & Media Uploads
- MIME / extension check done only by looking at `file.mimetype` or the filename extension — no magic-byte validation
- No `limits.fileSize` or equivalent on the multipart parser (multer, busboy, python-multipart)
- Uploaded files stored at a path derived from user input without sanitisation

### 3. URL Params & Queries
- `req.query.limit` / `request.args.get('limit')` passed directly into a DB query or slice without `parseInt` + bounds check
- `req.params.id` used in a query without type-casting to integer or UUID validation
- Raw query string values fed into template strings or string concatenation

### 4. Forms & Headers
- Webhook endpoints missing `crypto.timingSafeEqual` HMAC verification of the signature header
- `req.headers['user-agent']` or similar written to logs without sanitisation (newline injection)
- Form fields accepted without length limits or allowed-character checks

## How to run the scanner (preferred)

**Python (cross-platform):**
```
python vulnerabilities/v5-missing-input-validation/scripts/scan.py --target <repo>
python vulnerabilities/v5-missing-input-validation/scripts/scan.py --target <repo> --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v5-missing-input-validation/scripts/scan.ps1 -Target <repo>
powershell.exe vulnerabilities/v5-missing-input-validation/scripts/scan.ps1 -Target <repo> -Json
```

- Patterns and file globs come from `config.yml` — edit to add frameworks or custom patterns.
- The scanner flags suspicious patterns for human confirmation. Always verify whether a validation schema or middleware exists elsewhere in the request pipeline before concluding it is a vulnerability.

## Constraints

- **Taint analysis mindset:** trace user-controlled inputs from HTTP request sources to DB/filesystem sinks.
- **Look beyond presence checks:** `if (input)` is not validation — check for type, length, structure, and logical bounds.
- **Flag missing HMAC:** any webhook endpoint without cryptographic signature verification is high severity.
- **Detect mass assignment:** direct spread of `req.body` into ORM calls or model constructors is always a finding.
- **Zero hallucination:** only flag patterns explicitly present in the provided code.

## Output format

## 🛡️ Input Validation & Schema Analysis Summary
* **Total Validation Defects Found:** [Count]
* **Vulnerable Input Gateways:** [List entry points, e.g., POST /api/v1/upload, GET /items]

---

## 🎛️ Detailed Input Validation Findings

### [Finding #] - Shallow / Missing Validation in [JSON Body / File Upload / URL Parameter / Webhook]
- **Target Handler/File:** `path/to/controller_or_route`
- **Validation Failure Type:** [e.g., Type Bypassing, Mass Assignment, Extension Spoofing, Pagination DoS, Missing Webhook HMAC]
- **Evidence:** ```[language]
  [exact backend code snippet where the incoming parameter bypasses deep verification]
```
- **Remediation:** [concrete validation step to add — schema, bounds check, HMAC verify, etc.]

## Companion assets

- `config.yml` — scan targets, file extensions, and regex patterns the scripts use.
- `scripts/scan.py` — Python scanner (no third-party deps).
- `scripts/scan.ps1` — native PowerShell scanner (no Python needed).
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt.
- `flowchart.md` — Mermaid diagram of the missing-input-validation attack surface.
