#!/usr/bin/env python3
"""
v8 - Flawed Object Authorization scanner

Scans backend source files for BOLA/IDOR, mass assignment, sequential ID
exposure, and tenant manipulation flaws:
  - ORM findById / raw SQL WHERE id = param with no ownership filter
  - GraphQL resolvers accepting id args without auth assertion
  - req.body spread directly into ORM update/save calls
  - Mongoose findByIdAndUpdate / Prisma update with raw req.body
  - Integer auto-increment PKs on public-facing routes/models
  - Tenant/org ID read from request body or query string instead of session

Driven entirely by config.yml. No third-party dependencies.

Usage:
  python scan.py --target <repo> [--config config.yml] [--json]
"""
import argparse
import json
import os
import re
import sys


# --------------------------------------------------------------------------
# Minimal YAML reader — same subset used across v1-v7
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
            elif ch == "#" and not out.strip():
                break
            else:
                out += ch
        return out.rstrip()

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
        elif ":" in content:
            k, v = content.split(":", 1)
            tokens.append((indent, k.strip(), v.strip()))
        else:
            tokens.append((indent, None, content))

    pos = [0]

    def parse_inline(v):
        v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        return v

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
                elif ":" in value and not value.startswith(("'", '"')):
                    inline_key, inline_val = value.split(":", 1)
                    pos[0] += 1
                    m = {inline_key.strip(): parse_inline(inline_val.strip())}
                    while pos[0] < len(tokens) and tokens[pos[0]][0] > item_indent:
                        k2, v2 = tokens[pos[0]][1], tokens[pos[0]][2]
                        pos[0] += 1
                        if k2:
                            m[k2] = parse_inline(v2)
                    result.append(m)
                else:
                    pos[0] += 1
                    result.append(parse_inline(value))
            else:
                if result is None:
                    result = {}
                pos[0] += 1
                if value == "":
                    child = parse_block(indent + 1)
                    result[key] = child if child is not None else None
                else:
                    result[key] = parse_inline(value)
        return result if result is not None else {}

    return parse_block(0)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def is_excluded(rel_path, exclude):
    parts = rel_path.replace("\\", "/").split("/")
    for pat in exclude:
        if pat.rstrip("/") in parts:
            return True
    return False


def load_config(config_path):
    cfg = load_yaml(config_path)
    patterns = []
    for p in (cfg.get("patterns") or []):
        try:
            rx = re.compile(p.get("regex", ""), re.IGNORECASE)
        except re.error as e:
            print(f"[warn] bad regex for '{p.get('name')}': {e}", file=sys.stderr)
            continue
        patterns.append({
            "name": p.get("name", ""),
            "regex": rx,
            "category": p.get("category", ""),
            "severity": p.get("severity", "medium"),
            "note": p.get("note", ""),
        })
    return cfg, patterns


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------

def scan(target, cfg, patterns):
    findings = []
    exclude = cfg.get("exclude_patterns") or []
    extensions = set(cfg.get("source_extensions") or [])

    for root, dirs, files in os.walk(target):
        rel_root = os.path.relpath(root, target)
        if is_excluded(rel_root, exclude):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not is_excluded(
            os.path.relpath(os.path.join(root, d), target), exclude)]

        for fn in files:
            _, ext = os.path.splitext(fn)
            if extensions and ext.lower() not in extensions:
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, target).replace("\\", "/")
            if is_excluded(rel, exclude):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        for p in patterns:
                            if p["regex"].search(line):
                                findings.append({
                                    "file": rel,
                                    "line": lineno,
                                    "name": p["name"],
                                    "category": p["category"],
                                    "severity": p["severity"],
                                    "note": p["note"],
                                    "evidence": line.rstrip(),
                                })
            except OSError:
                continue
    return findings


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="V8 Flawed Object Authorization scanner")
    ap.add_argument("--target", default=".", help="Path to scan")
    ap.add_argument("--config", default=None, help="Path to config.yml")
    ap.add_argument("--json", action="store_true", help="Emit JSON output")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    sibling = os.path.join(here, "..", "config.yml")
    config_path = args.config or (sibling if os.path.exists(sibling) else os.path.join(here, "config.yml"))

    if not os.path.exists(config_path):
        print(f"[error] config.yml not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    cfg, patterns = load_config(config_path)
    findings = scan(args.target, cfg, patterns)

    if args.json:
        print(json.dumps({"count": len(findings), "findings": findings}, indent=2))
    else:
        print(f"\n=== V8 Flawed Object Authorization Scan :: {args.target} ===")
        print(f"Total findings: {len(findings)}\n")
        by_file = {}
        for f in findings:
            by_file.setdefault(f["file"], []).append(f)
        for fpath, items in sorted(by_file.items()):
            print(f"## {fpath}  ({len(items)} hit(s))")
            for it in items:
                print(f"  [{it['severity'].upper()}] {it['name']} (L{it['line']}) [{it['category']}]")
                print(f"      {it['note']}")
                snippet = it["evidence"].strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                print(f"      > {snippet}")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
