#!/usr/bin/env python3
"""
v2 - Package Hallucination scanner

Finds AI-hallucinated / typosquatted dependencies by:
  1. Extracting declared packages from manifests (package.json, requirements.txt,
     go.mod, Cargo.toml, Gemfile, lockfiles, Dockerfile, CI yml).
  2. Extracting imported packages from source files.
  3. Flagging packages that look like typosquats of known-real packages, or match
     common AI-hallucination name patterns (e.g. "python-string-utils").
  4. Cross-referencing imports vs declared deps so unlisted imports surface.

Driven by config.yml. No third-party dependencies.

Usage:
  python scan.py --target . [--json]
  python scan.py --target <repo> --json
"""
import argparse
import json
import os
import re
import sys

# --------------------------------------------------------------------------
# Minimal YAML reader (same subset as the v1 scanner)
# --------------------------------------------------------------------------

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    def strip_comment(s):
        out, q = "", None
        for ch in s:
            if q:
                out += ch
                if ch == q:
                    q = None
            elif ch in ("'", '"'):
                q = ch
                out += ch
            elif ch == "#" and out.strip() == "":
                break
            else:
                out += ch
        return out.rstrip()

    def parse_scalar(s):
        s = s.strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            return s[1:-1]
        if s.lower() == "true":
            return True
        if s.lower() == "false":
            return False
        return s

    tokens = []
    for raw in lines:
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        body = strip_comment(raw)
        if not body.strip():
            continue
        indent = len(body) - len(body.lstrip(" "))
        content = body.strip()
        if content.startswith("- "):
            tokens.append((indent, None, content[2:].strip()))
        elif content == "-":
            tokens.append((indent, None, ""))
        else:
            if ":" in content:
                k, v = content.split(":", 1)
                tokens.append((indent, k.strip(), v.strip()))
            else:
                tokens.append((indent, None, content))

    pos = [0]

    def parse_block(min_indent):
        result = None
        while pos[0] < len(tokens):
            indent, key, value = tokens[pos[0]]
            if indent < min_indent:
                break
            if key is None:
                if result is None:
                    result = []
                item_indent = indent
                if value == "":
                    pos[0] += 1
                    child = parse_block(item_indent + 1)
                    result.append(child)
                elif ":" in value and not (value.startswith('"') or value.startswith("'")):
                    inline_key, inline_val = value.split(":", 1)
                    pos[0] += 1
                    m = {inline_key.strip(): parse_inline_val(inline_val.strip())}
                    while pos[0] < len(tokens) and tokens[pos[0]][0] > item_indent:
                        k2, v2 = tokens[pos[0]][1], tokens[pos[0]][2]
                        pos[0] += 1
                        m[k2] = parse_inline_val(v2)
                    result.append(m)
                else:
                    pos[0] += 1
                    result.append(parse_inline_val(value))
            else:
                if result is None:
                    result = {}
                pos[0] += 1
                if value == "":
                    child = parse_block(indent + 1)
                    result[key] = child if child is not None else None
                else:
                    result[key] = parse_inline_val(value)
        return result if result is not None else {}

    def parse_inline_val(v):
        if v == "":
            return None
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        return v

    return parse_block(0)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def load_config(config_path):
    cfg = load_yaml(config_path)
    return cfg


def is_excluded(rel_path, exclude):
    parts = rel_path.replace("\\", "/").split("/")
    for pat in exclude:
        pat = pat.rstrip("/")
        if pat in parts:
            return True
        if pat.endswith("/*") and pat[:-2] in parts:
            return True
    return False


def levenshtein(a, b):
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def norm(name):
    # normalize dash/underscore for typosquat comparison
    return name.replace("_", "-").lower()


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def extract_manifest_packages(path, ecosystem):
    """Return list of package-name strings declared in a manifest file."""
    pkgs = []
    try:
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        return pkgs

    if ecosystem == "npm":
        if path.endswith("package.json"):
            for m in re.finditer(r'"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{([^}]*)\}', text):
                for pm in re.finditer(r'"([^"]+)"\s*:\s*"', m.group(1)):
                    pkgs.append(pm.group(1))
        elif path.endswith("package-lock.json") or path.endswith("yarn.lock") or path.endswith("pnpm-lock.yaml"):
            # top-level package names from lockfiles
            for pm in re.finditer(r'^\s*"([a-zA-Z0-9@/_.\-]+)"\s*:', text, re.M):
                name = pm.group(1)
                if name not in ("name", "version", "lockfileVersion", "requires", "dependencies", "packages"):
                    pkgs.append(name)
    elif ecosystem == "pypi":
        if path.endswith("requirements.txt"):
            for line in text.splitlines():
                line = line.split("#")[0].strip()
                m = re.match(r'^([A-Za-z0-9_.\-]+)', line)
                if m and line and not line.startswith("-"):
                    pkgs.append(m.group(1))
        elif path.endswith("pyproject.toml"):
            for m in re.finditer(r'^\s*([A-Za-z0-9_.\-]+)\s*[=<>\~!]', text, re.M):
                pkgs.append(m.group(1))
        elif path.endswith("Pipfile") or path.endswith("poetry.lock"):
            for m in re.finditer(r'^([A-Za-z0-9_.\-]+)\s*=', text, re.M):
                pkgs.append(m.group(1))
    elif ecosystem == "go":
        for m in re.finditer(r'^\s*([A-Za-z0-9_./\-]+)\s+[v0-9]', text, re.M):
            pkgs.append(m.group(1))
    elif ecosystem == "cargo":
        for m in re.finditer(r'^([a-zA-Z0-9_\-]+)\s*=\s*"', text, re.M):
            pkgs.append(m.group(1))
    elif ecosystem == "rubygems":
        for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"]", text):
            pkgs.append(m.group(1))
    elif ecosystem == "docker":
        for m in re.finditer(r'(?:RUN|ARG|ENV)\s+[^#]*?\b(?:npm|pip|pip3|poetry|cargo|go get)\s+install\s+([A-Za-z0-9_@/.\-]+)', text):
            pkgs.append(m.group(1))
        for m in re.finditer(r'FROM\s+([a-zA-Z0-9_/.\-]+)', text):
            pkgs.append("image:" + m.group(1))
    elif ecosystem == "ci":
        # CI workflow: actions and package installs
        for m in re.finditer(r'uses:\s*([A-Za-z0-9_./\-@]+)', text):
            pkgs.append("action:" + m.group(1))
        for m in re.finditer(r'(?:npm|pip|pip3|poetry|cargo|go get|gem)\s+install\s+([A-Za-z0-9_@/.\-]+)', text):
            pkgs.append(m.group(1))
    return pkgs


def extract_imports(path, ecosystem):
    imps = set()
    try:
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        return imps
    if ecosystem == "npm":
        for m in re.finditer(r'require\(\s*[\'"]([^\'"]+)[\'"]\s*\)', text):
            imps.add(m.group(1).split("/")[0].lstrip("@"))
        for m in re.finditer(r'from\s+[\'"]([^\'"]+)[\'"]', text):
            name = m.group(1)
            if name.startswith(".") or name.startswith("/"):
                continue
            imps.add(name.split("/")[0].lstrip("@"))
    elif ecosystem == "pypi":
        for m in re.finditer(r'^\s*(?:import|from)\s+([A-Za-z0-9_]+)', text, re.M):
            imps.add(m.group(1))
    elif ecosystem == "go":
        for m in re.finditer(r'^\s*"\s*([A-Za-z0-9_./\-]+)"', text, re.M):
            imps.add(m.group(1).split("/")[0])
    elif ecosystem == "cargo":
        for m in re.finditer(r'use\s+([A-Za-z0-9_]+)::', text):
            imps.add(m.group(1).lower())
    elif ecosystem == "rubygems":
        for m in re.finditer(r'require\s+[\'"]([^\'"]+)[\'"]', text):
            imps.add(m.group(1).split("/")[0])
    return imps


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------

def scan(target, cfg):
    findings = []
    exclude = cfg.get("exclude_patterns") or []
    manifests = cfg.get("manifests") or []
    source_files = cfg.get("source_files") or {}
    known = cfg.get("known_packages") or {}
    ai_patterns = [p.lower() for p in (cfg.get("ai_hallucination_patterns") or [])]
    max_dist = int(cfg.get("typosquat_max_distance", 2))

    declared = {}  # name -> (file, ecosystem)
    declared_by_eco = {}

    # 1. walk manifests
    for root, dirs, files in os.walk(target):
        rel_root = os.path.relpath(root, target)
        if is_excluded(rel_root, exclude):
            dirs[:] = []
            continue
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, target)
            if is_excluded(rel, exclude):
                continue
            for man in manifests:
                if "|" in man:
                    mpath, eco = man.split("|", 1)
                else:
                    mpath = man.get("path")
                    eco = man.get("ecosystem")
                matched = (fn == mpath) or (mpath.startswith("*.") and fn.endswith(mpath[1:]))
                if not matched:
                    continue
                pkgs = extract_manifest_packages(full, eco)
                for p in pkgs:
                    base = p.split("/")[0].lstrip("@") if not p.startswith(("image:", "action:")) else p
                    declared.setdefault(base, []).append((rel, eco, p))
                    declared_by_eco.setdefault(eco, set()).add(base)

    # 2. walk source files -> imports
    imported_by_eco = {}
    for root, dirs, files in os.walk(target):
        rel_root = os.path.relpath(root, target)
        if is_excluded(rel_root, exclude):
            dirs[:] = []
            continue
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, target)
            if is_excluded(rel, exclude):
                continue
            for eco, globs in source_files.items():
                for g in globs:
                    if fn.endswith(g[1:]) or (g.startswith("*.") and fn.endswith(g[1:])):
                        imps = extract_imports(full, eco)
                        imported_by_eco.setdefault(eco, set()).update(imps)

    # 3. flag typosquats + AI-hallucination names
    for name, occ in declared.items():
        nname = norm(name)
        # AI-hallucination pattern match
        if nname in ai_patterns:
            for (rel, eco, raw) in occ:
                findings.append({
                    "package": raw, "file": rel, "ecosystem": eco,
                    "type": "AI-hallucination name", "severity": "high",
                    "detail": f"Matches common AI-fictionalized package name pattern '{name}'",
                })
            continue
        # typosquat against known packages
        for eco, known_list in known.items():
            for kp in known_list:
                if levenshtein(nname, norm(kp)) <= max_dist and nname != norm(kp):
                    for (rel, e2, raw) in occ:
                        findings.append({
                            "package": raw, "file": rel, "ecosystem": eco,
                            "type": "Typosquat candidate", "severity": "high",
                            "detail": f"Near-match to known package '{kp}' (distance {levenshtein(nname, norm(kp))})",
                        })
                    break

    # 4. cross-reference: imported packages not declared in manifest
    for eco, imps in imported_by_eco.items():
        declared_set = declared_by_eco.get(eco, set())
        # only meaningful when we actually saw a manifest for this ecosystem
        if eco not in declared_by_eco:
            continue
        for imp in imps:
            ibase = imp.split("/")[0].lstrip("@")
            if ibase not in declared_set and ibase not in ("image", "action"):
                findings.append({
                    "package": imp, "file": "(source import)", "ecosystem": eco,
                    "type": "Unlisted import", "severity": "medium",
                    "detail": f"Imported '{imp}' but not found in {eco} manifest",
                })

    return findings


def main():
    ap = argparse.ArgumentParser(description="AI Package Hallucination scanner")
    ap.add_argument("--target", default=".")
    ap.add_argument("--config", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    config_path = args.config or (os.path.join(here, "config.yml") if os.path.exists(os.path.join(here, "config.yml")) else os.path.join(here, "..", "config.yml"))
    cfg = load_config(config_path)
    findings = scan(args.target, cfg)

    if args.json:
        print(json.dumps({"count": len(findings), "findings": findings}, indent=2))
    else:
        print(f"\n=== AI Package Hallucination Scan :: {args.target} ===")
        print(f"Total suspicious packages identified: {len(findings)}\n")
        by_pkg = {}
        for f in findings:
            by_pkg.setdefault(f["package"], []).append(f)
        for pkg, items in sorted(by_pkg.items()):
            print(f"## {pkg}  ({len(items)} flag(s))")
            for it in items:
                print(f"  [{it['severity'].upper()}] {it['type']} [{it['ecosystem']}] @ {it['file']}")
                print(f"      {it['detail']}")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
