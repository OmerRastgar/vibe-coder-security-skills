#!/usr/bin/env python3
"""
v6 - Baking Secrets into Source scanner

Scans source files (and optionally Git history) for hardcoded credentials:
  - API keys (OpenAI, Stripe, Google, etc.)
  - Generic secret/password/token variable assignments
  - Database URIs with embedded passwords
  - Default / weak passwords in config files
  - AWS keys, private key blocks, kubeconfig tokens
  - npm auth tokens, registry credentials
  - High-entropy strings assigned to credential-named variables

Driven entirely by config.yml. No third-party dependencies.

Usage:
  python scan.py --target <repo> [--history] [--config config.yml] [--json]

Options:
  --target   Path to scan (default: current directory)
  --history  Also scan full Git history (git log -p --all)
  --config   Path to config.yml (default: alongside this script's parent)
  --json     Emit results as JSON
"""
import argparse
import json
import os
import re
import subprocess
import sys


# --------------------------------------------------------------------------
# Minimal YAML reader — same subset used across v1-v5
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


def matches_sensitive_filename(name, sensitive):
    nl = name.lower()
    for s in sensitive:
        sl = s.lower()
        if sl.startswith("*."):
            if nl.endswith(sl[1:]):
                return True
        elif sl == nl:
            return True
    return False


def mask(value):
    v = value.strip().strip('"').strip("'")
    if len(v) <= 8:
        return v[:2] + "..." if len(v) > 2 else v
    return v[:4] + "..." + v[-4:]


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
# Scan filesystem
# --------------------------------------------------------------------------

def scan_files(target, cfg, patterns):
    findings = []
    exclude = cfg.get("exclude_patterns") or []
    extensions = set(cfg.get("source_extensions") or [])
    sensitive = cfg.get("sensitive_filenames") or []
    do_mask = cfg.get("mask_secret", True)

    for root, dirs, files in os.walk(target):
        rel_root = os.path.relpath(root, target)
        if is_excluded(rel_root, exclude):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not is_excluded(
            os.path.relpath(os.path.join(root, d), target), exclude)]

        for fn in files:
            _, ext = os.path.splitext(fn)
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, target).replace("\\", "/")
            if is_excluded(rel, exclude):
                continue

            if matches_sensitive_filename(fn, sensitive):
                findings.append({
                    "file": rel, "line": 0, "name": "Sensitive filename",
                    "category": "Dev Boilerplate", "severity": "high",
                    "note": "This file type should not be committed with real values.",
                    "evidence": fn, "source": "filesystem",
                })

            if extensions and ext.lower() not in extensions:
                continue

            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        for p in patterns:
                            if p["regex"].search(line):
                                m = p["regex"].search(line)
                                evidence = (mask(m.group(0)) if do_mask else m.group(0))
                                findings.append({
                                    "file": rel, "line": lineno,
                                    "name": p["name"], "category": p["category"],
                                    "severity": p["severity"], "note": p["note"],
                                    "evidence": evidence, "source": "filesystem",
                                })
            except OSError:
                continue
    return findings


# --------------------------------------------------------------------------
# Scan Git history
# --------------------------------------------------------------------------

def scan_history(target, cfg, patterns):
    findings = []
    do_mask = cfg.get("mask_secret", True)
    try:
        result = subprocess.run(
            ["git", "-C", target, "log", "-p", "--all", "--pretty=format:COMMIT:%H"],
            capture_output=True, text=True, errors="ignore", timeout=300,
        )
        out = result.stdout
    except Exception as e:
        print(f"[warn] git history scan failed: {e}", file=sys.stderr)
        return findings

    commit = "unknown"
    for i, line in enumerate(out.splitlines(), 1):
        if line.startswith("COMMIT:"):
            commit = line[7:].strip()
            continue
        for p in patterns:
            if p["regex"].search(line):
                m = p["regex"].search(line)
                evidence = (mask(m.group(0)) if do_mask else m.group(0))
                findings.append({
                    "file": f"commit:{commit}", "line": i,
                    "name": p["name"], "category": p["category"],
                    "severity": p["severity"], "note": p["note"],
                    "evidence": evidence, "source": "git-history",
                })
    return findings


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="V6 Baking Secrets into Source scanner")
    ap.add_argument("--target", default=".", help="Path to scan")
    ap.add_argument("--history", action="store_true", help="Also scan Git history")
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
    findings = scan_files(args.target, cfg, patterns)
    if args.history:
        findings += scan_history(args.target, cfg, patterns)

    if args.json:
        print(json.dumps({"count": len(findings), "findings": findings}, indent=2))
    else:
        print(f"\n=== V6 Baking Secrets Scan :: {args.target} ===")
        print(f"Total findings: {len(findings)}\n")
        by_file = {}
        for f in findings:
            by_file.setdefault(f["file"], []).append(f)
        for fpath, items in sorted(by_file.items()):
            print(f"## {fpath}  ({len(items)} hit(s))")
            for it in items:
                loc = f"L{it['line']}" if it["line"] else ""
                print(f"  [{it['severity'].upper()}] {it['name']} {loc} [{it['category']}]")
                print(f"      {it['note']}")
                print(f"      > {it['evidence']}")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
