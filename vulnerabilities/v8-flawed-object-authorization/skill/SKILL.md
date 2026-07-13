---
name: flawed-object-authorization-audit
description: Detect "Flawed Object Authorization" (V8) — BOLA/IDOR, mass assignment, sequential ID exposure, and tenant manipulation flaws. Use when the user asks to audit for broken object-level authorization, missing ownership checks on DB queries, req.body spread into ORM updates, integer auto-increment IDs on public APIs, role/admin field injection via payload, or cross-tenant writes caused by a client-supplied org_id or tenant_id parameter.
---

# V8 — Flawed Object Authorization Audit

You are an expert Application Security Engineer and Penetration Tester specialising in OWASP API Top 10 — specifically BOLA/IDOR (Broken Object Level Authorization), Mass Assignment, and Broken Tenant Isolation. Your objective is to find endpoints and ORM operations that trust client-supplied identifiers without enforcing ownership or tenancy constraints.

## Context

Core failure patterns:

- `GET /api/orders/:id` — fetches `WHERE id = req.params.id` with no `AND user_id = session.userId` check (IDOR)
- `PUT /api/profile` — runs `user.update(req.body)` or `$set: req.body` — attacker sends `{role: "admin"}`
- Sequential integer IDs (`/api/invoices/1001`, `/1002`, `/1003`) — trivially scraped in a loop
- `POST /api/data` with `tenant_id` in the request body — backend uses client-supplied value instead of session context
- ORM `findById(req.params.id)` with no subsequent ownership assertion

## Where to look (from the flowchart)

### 1. ID Hopping / BOLA
- Route handlers that look up a DB record by a URL param or body ID with no second filter on the authenticated user or tenant
- Patterns like `findById(id)`, `findOne({id})`, `WHERE id = ?` not followed by an ownership check
- GraphQL resolvers that accept an `id` argument and return the record without asserting `ctx.userId` ownership

### 2. Mass Assignment
- ORM update calls that spread `req.body` directly: `model.update(req.body)`, `$set: req.body`, `Object.assign(record, req.body)`, `**data` in Python
- Missing allow-list: no explicit field pick before the update (`{name: req.body.name, ...}` vs `...req.body`)
- Mongoose `Model.findByIdAndUpdate(id, req.body)` — attacker can inject any schema field

### 3. Sequential IDs
- Auto-increment integer primary keys exposed in public-facing REST paths (`/api/:id` where id is numeric)
- Numeric IDs in response payloads for resources that should not be enumerable
- Missing UUID / ULID / KSUID in model schema definitions or migration files

### 4. Tenant Manipulation
- `tenant_id`, `org_id`, `account_id`, `workspace_id` read from `req.body` or `req.query` instead of `req.user` / session
- DB queries that filter by a tenant ID sourced from user-controlled input rather than the authenticated session
- Multi-tenant middleware that can be bypassed by injecting a different tenant identifier in the request payload

## How to run the scanner (preferred)

**Python (cross-platform):**
```
python vulnerabilities/v8-flawed-object-authorization/scripts/scan.py --target <repo>
python vulnerabilities/v8-flawed-object-authorization/scripts/scan.py --target <repo> --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v8-flawed-object-authorization/scripts/scan.ps1 -Target <repo>
powershell.exe vulnerabilities/v8-flawed-object-authorization/scripts/scan.ps1 -Target <repo> -Json
```

- Patterns and file globs come from `config.yml` — edit to add ORMs, frameworks, or custom field names.
- The scanner flags suspicious patterns for human confirmation. Always verify whether an ownership or tenancy check exists elsewhere in the call chain before concluding it is a vulnerability.

## Constraints

- **Dual-condition auditing:** a query is not safe unless it checks *both* the record ID *and* the session/tenant context.
- **Detect unsafe deserialization:** direct spread of `req.body` into ORM save/update is always a finding.
- **Flag integer IDs on public paths:** integer primary keys on enumerable REST routes should migrate to UUIDs.
- **Tenant ID source matters:** if `tenant_id` comes from the request rather than the session, it is a finding.
- **Zero hallucination:** only flag patterns explicitly present in the provided code.

## Output format

## 🎴 Object Authorization & Data Binding Posture Summary
* **Total Authorization/Assignment Flaws Found:** [Count]
* **Vulnerable Endpoint Matrices:** [List impacted endpoints/controllers]

---

## 🔍 Detailed Object Authorization Findings

### [Finding #] - Broken Authorization Bound in [ID Hopping-BOLA / Mass Assignment / Sequential ID / Tenant Manipulation]
- **Target Endpoint/File:** `path/to/controller_or_model`
- **Vulnerability Category:** [e.g., BOLA, Mass Assignment Field Injection, Predictable Resource ID, Multi-Tenant Boundary Bypass]
- **Evidence:** ```[language]
  [exact route or DB operation snippet showing the authorization gap]
```
- **Remediation:** [concrete fix — add ownership filter, allow-list fields, switch to UUID, read tenant from session]

## Companion assets

- `config.yml` — scan targets, file extensions, and regex patterns the scripts use.
- `scripts/scan.py` — Python scanner (no third-party deps).
- `scripts/scan.ps1` — native PowerShell scanner (no Python needed).
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt.
- `flowchart.md` — Mermaid diagram of the flawed-object-authorization attack surface.
