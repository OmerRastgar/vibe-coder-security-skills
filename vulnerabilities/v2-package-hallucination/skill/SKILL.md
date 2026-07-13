---
name: package-hallucination-audit
description: Detect AI package hallucination and dependency typosquatting — LLM-invented or squat-on packages pulled in via manifests, lockfiles, CI/CD, or source imports. Use when the user asks to audit dependencies, check for hallucinated packages, typosquatted libraries, suspicious imports, or verify that declared packages in package.json/requirements.txt/go.mod/Cargo.toml/Gemfile actually exist and match what the code imports.
---

# Package Hallucination Audit

You are an expert Software Supply Chain Security Engineer and Automated Dependency Auditor. Your objective is to inspect projects for AI-generated package hallucinations, typosquatted dependencies, and malicious packages introduced via AI coding assistants or unverified imports.

## Context

LLMs frequently "hallucinate" plausible but non-existent libraries. Attackers monitor or predict these hallucinations and register ("squat" on) those names in public registries (npm, PyPI, Crates.io, RubyGems). If a developer accepts the suggestion without verifying, the build pulls down a malicious payload.

## Where to look (exhaustive — from the flowchart)

Audit ALL four artifact classes; correlate manifests against actual code imports.

### 1. Manifests
- `package.json` — `dependencies` / `devDependencies` (also `peer`, `optional`)
- `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`
- `go.mod`, `Cargo.toml`, `Gemfile`
- Lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`

### 2. Lockfiles
- Cross-check resolved package names against the registry's expected set.

### 3. CI/CD & Infra
- `Dockerfile` — `RUN npm install <pkg>`, `pip install <pkg>`, `go get`, base `FROM` images
- CI workflow `.yml` / `.yaml` — `uses:` actions, `npm/pip/gem install` steps, setup scripts

### 4. Source Code
- Imports / requires: `.js`/`.ts` (`import`/`require`), `.py` (`import`/`from`), `.go`, `.rs`, `.rb`
- Flag imports present in code but MISSING from any manifest (unlisted packages).

## How to run the scanner

Copy the `skill/` folder from this vulnerability into `.commandcode/skills/` in your project, then run:

**Python (cross-platform):**
```
python .commandcode/skills/package-hallucination-audit/scripts/scan.py --target <repo>
python .commandcode/skills/package-hallucination-audit/scripts/scan.py --target <repo> --json
```

**PowerShell (Windows, no Python needed):**
```
powershell.exe .commandcode/skills/package-hallucination-audit/scripts/scan.ps1 -Target <repo>
powershell.exe .commandcode/skills/package-hallucination-audit/scripts/scan.ps1 -Target <repo> -Json
```

- Patterns, known-real package lists, and source globs come from `config.yml` — edit to add packages or heuristics.
- The scanner cannot query live registries; it flags *suspicious* packages for you to verify (e.g., `npm view <pkg>` / `pip index versions <pkg>`).

## Constraints

- **Cross-reference manifests vs imports:** correlate declared deps with actual `import`/`require` to surface hidden/unlisted packages.
- **Flag anomalous naming:** look for typosquat patterns (dashes↔underscores, misspells of big libs like `boto3`, `requests`, `react`).
- **No external registry access (simulated baseline):** flag packages matching known AI-hallucination naming patterns or out-of-place given project scope.
- **Low false-positive rate:** distinguish legitimate scoped/internal packages (`@company/package`) from malicious public ones.

## Output format

## ⚠️ Supply Chain & Package Analysis Summary
* **Total Suspicious Packages Identified:** [Count]
* **Files / Manifests Affected:** [List files, e.g., package.json, main.py]

---

## 🕵️ Detailed Dependency Findings

### [Finding #] - Potential [Hallucinated / Typosquatted] Package
- **Package Name:** `[name]`
- **Registry Ecosystem:** [npm, PyPI, Go Modules, RubyGems, Cargo]
- **Location Found:** `path/to/file` at line [X]
- **Risk Assessment:** [why it looks like a hallucination/typosquat]
- **Remediation Action:**
  1. Verify existence/maintenance on the official registry.
  2. If hallucinated, remove from manifest and use the intended library.
  3. Purge caches (`npm cache clean`, `pip cache purge`).

## Reference

See `reference.md` for the full vulnerability description and attack surface flowchart.
See `prompt.md` for the copy-paste LLM audit prompt.
