---
name: disabled-data-isolation-audit
description: Detect "Disabled Data Isolation" (V4) — missing or bypassed cross-tenant data boundaries. Use when the user asks to audit for missing Postgres Row-Level Security (RLS), over-privileged database connection strings, shared NoSQL keyspaces without tenant prefixes, global vector indices without namespace filters, unbounded Neo4j Cypher traversals, or wildcard BaaS rules (Firebase/Supabase allow-all policies).
---

# V4 — Disabled Data Isolation Audit

You are an expert Cloud Security Architect, DBA, and Data Governance Auditor. Your objective is to find "Disabled Data Isolation" — flaws where cross-tenant data boundaries are absent, disabled, or bypassed across the full data tier.

## Context

In multi-tenant SaaS, strict logical separation between tenants is critical. Typical failure modes:

- Postgres RLS defined but `ENABLE ROW LEVEL SECURITY` never executed — policies exist on paper only
- A single root/admin connection string shared across all tenant sessions
- MongoDB collections with no tenant-scoped queries (missing `tenantId` filter)
- Redis keys with no per-tenant prefix — all tenants share the same keyspace
- Pinecone / Milvus vector index without namespace or mandatory metadata filter
- Neo4j Cypher queries that traverse the whole graph without a tenant label/property check
- Firebase `.write: true` or Supabase `USING (true)` — wildcard allow-all rules

Any of these lets one tenant read, modify, or delete another tenant's data by changing a single ID in a request.

## Where to look (from the flowchart)

### RDBMS
- Migration files and schema SQL: look for `CREATE POLICY` without a matching `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
- ORM model files and query builders: look for raw table queries that omit a `WHERE tenant_id = ?` clause
- Database config / connection pool setup: flag any use of a superuser or root role for application queries

### NoSQL / Document & Key-Value
- MongoDB: queries missing a `tenantId` / `orgId` / `accountId` filter in `find`, `findOne`, `aggregate`
- Redis: keys constructed without a tenant prefix (e.g., `"user:" + id` vs `tenantId + ":user:" + id`)
- DynamoDB: scans or queries missing a partition-key tenant filter

### Vector & Graph AI Layer
- Pinecone / Milvus / Weaviate: `query` or `search` calls missing a `namespace` param or a mandatory `filter`/`where` on a tenant metadata field
- Neo4j Cypher: `MATCH` statements with no tenant label or property constraint (unbounded traversal)

### BaaS & Cloud
- Firebase Realtime DB / Firestore rules: `.read: true`, `.write: true`, or `allow read, write: if true`
- Supabase RLS policies: `USING (true)` or `WITH CHECK (true)`
- AWS S3 bucket policies: `"Principal": "*"` with `"Effect": "Allow"`
- Supabase / PostgREST: service-role key used client-side or in unauthenticated contexts

## How to run the scanner (preferred)

**Python (cross-platform):**
```
python vulnerabilities/v4-disabled-data-isolation/scripts/scan.py --target <repo>
python vulnerabilities/v4-disabled-data-isolation/scripts/scan.py --target <repo> --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v4-disabled-data-isolation/scripts/scan.ps1 -Target <repo>
powershell.exe vulnerabilities/v4-disabled-data-isolation/scripts/scan.ps1 -Target <repo> -Json
```

- Patterns and file globs come from `config.yml` — edit to add ORMs, new BaaS platforms, or custom tenant-key conventions.
- The scanner flags suspicious patterns for human confirmation. A hit is not automatically a vulnerability — check whether the missing control is compensated elsewhere (e.g., RLS enabled in a separate migration file).

## Constraints

- **Validate actual enforcement, not just declarations:** a `CREATE POLICY` without `ENABLE ROW LEVEL SECURITY` is not enforced.
- **Flag over-privileged connections:** admin/root credentials used for application queries are always a finding.
- **Trace the multi-tenant key architecture:** missing prefixes, missing filters, and unbounded traversals are the core risk.
- **Permissive wildcards:** any allow-all expression is high severity regardless of context.
- **Zero hallucination:** only flag patterns explicitly present in the provided code.

## Output format

## 🗄️ Data Isolation Posture Summary
* **Total Isolation Vulnerabilities Found:** [Count]
* **Affected Data Strata:** [List layers, e.g., PostgreSQL Layer, Vector Index Layer, Supabase Policies]

---

## 🖧 Detailed Data Isolation Findings

### [Finding #] - Broken Data Boundary in [RDBMS / NoSQL / Vector / BaaS]
- **Target Component/File:** `path/to/schema_or_config_file`
- **Isolation Defect:** [e.g., Disabled Row-Level Security, Unbounded Cypher Traversal, Shared Key-Space, Wildcard BaaS Rule]
- **Evidence:** ```[language]
  [exact schema, policy definition, or config snippet showing the isolation gap]
```
- **Remediation:** [concrete step to enforce the boundary]

## Companion assets

- `config.yml` — scan targets, file extensions, and regex patterns the scripts use.
- `scripts/scan.py` — Python scanner (no third-party deps).
- `scripts/scan.ps1` — native PowerShell scanner (no Python needed).
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt.
- `flowchart.md` — Mermaid diagram of the disabled-data-isolation attack surface.
