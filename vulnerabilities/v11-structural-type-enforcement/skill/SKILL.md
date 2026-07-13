---
name: structural-type-enforcement-audit
description: Detect "Structural Type Enforcement" (V11) — loose typing and mass assignment flaws where raw user input bypasses type guards and contaminates data structures. Use when the user asks to audit for spread operators on req.body, TypeScript "as any" coercions, Python dict unpacking into ORM init calls, Pydantic models with extra = 'allow', Go unmarshalling into map[string]interface{}, blind automapper / AutoMapper profiles, or any place where unfiltered user data is merged directly into a model or DB record.
---

# V11 — Structural Type Enforcement Audit

You are an expert SAST Engineer, AST Auditor, and Secure Code Reviewer specialising in type safety, serialisation hygiene, and mass assignment prevention. Your objective is to find "Structural Type Enforcement" flaws — places where loose typing, blanket type coercion, or unfiltered dictionary transformations bypass compiler guards and let attackers inject arbitrary fields into persistence domains.

## Context

Core failure patterns by language:

**JS / TypeScript**
- `model.update({ ...req.body })` — attacker sends `{ role: "admin", isAdmin: true }`
- `const data = req.body as any` — type checker silenced, arbitrary fields flow through
- `Object.assign(entity, req.body)` — no field allow-list

**Python**
- `User(**request.json())` — any key in the JSON becomes a constructor argument
- `user.update(**data)` where `data` comes from `request.get_json()`
- `class Config: extra = 'allow'` on a Pydantic model — accepts and stores arbitrary fields

**Go**
- `json.Unmarshal(body, &map[string]interface{}{})` — structure-less, passes anything downstream
- Binding directly to a struct that has no field-level validation tags

**Compiled / Automapper**
- `_mapper.Map<UserEntity>(dto)` (AutoMapper C#) with no explicit profile — all properties mapped blindly
- `BeanUtils.copyProperties(source, target)` (Java) — copies every property including privileged ones
- Unfiltered `ModelMapper` or `MapStruct` profiles in Java/Kotlin

## Where to look (from the flowchart)

### 1. JS / TS (Node.js)
- Spread into ORM/model calls: `model.update({...req.body})`, `create({...req.body})`
- `as any` type assertions on request data: `req.body as any`, `(data as any).`
- `Object.assign(record, req.body)` without a field pick
- Missing Zod / Joi / class-validator schema before any DB mutation

### 2. Python (FastAPI / Django)
- `Model(**request.json())`, `Model(**data)`, `obj.update(**payload)`
- `**request.get_json()` passed to SQLAlchemy `__init__` or `.update()`
- Pydantic `model_config = ConfigDict(extra='allow')` or `class Config: extra = 'allow'`
- Django serializer `fields = '__all__'` on a writable endpoint

### 3. Reflection / Low-Level Bypasses
- Go `json.Unmarshal` into `map[string]interface{}` or `interface{}`
- C# AutoMapper `CreateMap<Source, Dest>()` with no `.ForMember()` restrictions
- Java `BeanUtils.copyProperties()` or `ModelMapper.map()` with no type-safe config
- Any dynamic property setter driven by a user-supplied key string

## How to run the scanner (preferred)

**Python (cross-platform):**
```
python vulnerabilities/v11-structural-type-enforcement/scripts/scan.py --target <repo>
python vulnerabilities/v11-structural-type-enforcement/scripts/scan.py --target <repo> --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe vulnerabilities/v11-structural-type-enforcement/scripts/scan.ps1 -Target <repo>
powershell.exe vulnerabilities/v11-structural-type-enforcement/scripts/scan.ps1 -Target <repo> -Json
```

- Patterns and file globs come from `config.yml` — edit to add ORMs, automapper libraries, or custom patterns.
- Scanner flags suspicious patterns for human confirmation. Verify whether an explicit field allow-list or strict schema sits between the request and the flagged call before concluding it is a vulnerability.

## Constraints

- **Deep mutation auditing:** any path where request attributes are spread, unpacked, or mapped into an ORM record without an explicit property picker is a finding.
- **Isolate type escape sinks:** `as any`, `extra = 'allow'`, `fields = '__all__'`, and `map[string]interface{}` are always findings when used with request data.
- **Automapper blindness:** implicit full-property mapping (no ForMember / allow-list) from a DTO that includes user-supplied fields is a finding.
- **Zero hallucination:** only flag patterns explicitly present in the provided code.

## Output format

## 📐 Structural Type Enforcement & Deserialization Summary
* **Total Type Enforcement Defects Found:** [Count]
* **Impacted Code Modules / Entities:** [List affected components]

---

## 🔍 Detailed Type Enforcement Findings

### [Finding #] - Unsafe Structural Type Mapping in [JS-TS / Python ORM / Compiled Reflection / Automapper]
- **Target File/Component:** `path/to/file_or_schema`
- **Enforcement Flaw Category:** [e.g., Unsafe Object Spreading, Loose Dict Unpacking, Permissive DTO Config, Blind Automapping Sink]
- **Evidence:** ```[language]
  [exact code block where type validation or property restriction is bypassed]
```
- **Remediation:** [explicit field allow-list, strict schema validation, ForMember restrictions, remove extra='allow']

## Companion assets

- `config.yml` — file extensions, language-specific patterns the scripts use.
- `scripts/scan.py` — Python scanner (no third-party deps).
- `scripts/scan.ps1` — native PowerShell scanner (no Python needed).
- `detail.md` — one-paragraph plain-language description.
- `prompt.md` — the full copy-paste audit prompt.
- `flowchart.md` — Mermaid diagram of the structural-type-enforcement attack surface.
