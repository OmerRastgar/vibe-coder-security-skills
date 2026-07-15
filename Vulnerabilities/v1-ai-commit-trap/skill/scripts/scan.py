#!/usr/bin/env python3
"""
ai-commit-trap-audit :: scanner

Scans a target directory and its Git history for leaked secrets / credentials.
Driven entirely by config.yml (no third-party dependencies).

Usage:
  python scan.py --target . [--history] [--config config.yml] [--json]

Options:
  --target   Path to scan (default: current directory)
  --history  Also scan full Git history (git log -p --all)
  --config   Path to config.yml (default: alongside this script)
  --json     Emit results as JSON instead of human-readable text
"""
import argparse
import os
import re
import sys
import subprocess
from datetime import datetime

# --------------------------------------------------------------------------
# Minimal YAML reader (no PyYAML dependency)
# Supports the subset used by config.yml: nested maps, lists of scalars,
# lists of maps, inline scalars, and quoted strings.
# --------------------------------------------------------------------------

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    def strip_comment(s):
        # remove trailing # comments that are not inside quotes
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

    # Build a token stream of (indent, key_or_None, value)
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
        # Returns dict or list depending on first token
        result = None
        while pos[0] < len(tokens):
            indent, key, value = tokens[pos[0]]
            if indent < min_indent:
                break
            if key is None:
                # list item
                if result is None:
                    result = []
                item_indent = indent
                if value == "":
                    pos[0] += 1
                    child = parse_block(item_indent + 1)
                    result.append(child)
                elif ":" in value and not (value.startswith('"') or value.startswith("'")):
                    # inline map start on same line: e.g. "- name: X"
                    inline_key, inline_val = value.split(":", 1)
                    pos[0] += 1
                    m = {inline_key.strip(): parse_inline_val(inline_val.strip())}
                    # absorb deeper keys belonging to this map
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
# Scanning logic
# --------------------------------------------------------------------------

def mask(value):
    v = value.strip().strip('"').strip("'")
    if len(v) <= 8:
        return v[0:2] + "..." if len(v) > 2 else v
    return v[:4] + "..." + v[-4:]


def load_config(config_path):
    cfg = load_yaml(config_path)
    patterns = []
    for p in (cfg.get("patterns") or []):
        patterns.append({
            "name": p.get("name"),
            "regex": re.compile(p.get("regex")),
            "severity": p.get("severity", "medium"),
        })
    return cfg, patterns


def is_excluded(rel_path, exclude):
    parts = rel_path.replace("\\", "/").split("/")
    for pat in exclude:
        pat = pat.rstrip("/")
        if pat in parts:
            return True
        if pat.endswith("/*"):
            if pat[:-2] in parts:
                return True
    return False


def matches_sensitive_filename(name, sensitive):
    name_l = name.lower()
    for s in sensitive:
        s_l = s.lower()
        if s_l.startswith("*."):
            if name_l.endswith(s_l[1:]):
                return True
        elif s_l == name_l:
            return True
    return False


def _scan_one_file(full, rel, cfg, patterns, sensitive, findings):
    fn = os.path.basename(full)
    if matches_sensitive_filename(fn, sensitive):
        findings.append({
            "file": rel, "line": 0, "type": "Sensitive filename",
            "severity": "high", "evidence": fn, "source": "filesystem",
        })
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh, 1):
                for p in patterns:
                    for m in p["regex"].finditer(line):
                        secret = m.group(0)
                        evidence = secret if not cfg.get("mask_secret") else mask(secret)
                        findings.append({
                            "file": rel, "line": i, "type": p["name"],
                            "severity": p["severity"], "evidence": evidence,
                            "source": "filesystem",
                        })
    except (OSError, UnicodeError):
        pass


def scan_files(target, cfg, patterns):
    findings = []
    exclude = cfg.get("exclude_patterns") or []
    sensitive = cfg.get("sensitive_filenames") or []
    if os.path.isfile(target):
        _scan_one_file(target, target, cfg, patterns, sensitive, findings)
        return findings
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
            _scan_one_file(full, rel, cfg, patterns, sensitive, findings)
    return findings


def scan_history(target, cfg, patterns):
    findings = []
    try:
        out = subprocess.run(
            ["git", "-C", target, "log", "-p", "--all", "--pretty=format:COMMIT:%H"],
            capture_output=True, text=True, errors="ignore", timeout=300,
        ).stdout
    except Exception as e:
        print(f"[warn] git history scan failed: {e}", file=sys.stderr)
        return findings
    commit = "unknown"
    for i, line in enumerate(out.splitlines(), 1):
        if line.startswith("COMMIT:"):
            commit = line[7:].strip()
            continue
        for p in patterns:
            for m in p["regex"].finditer(line):
                secret = m.group(0)
                evidence = secret if not cfg.get("mask_secret") else mask(secret)
                findings.append({
                    "file": f"commit:{commit}", "line": i, "type": p["name"],
                    "severity": p["severity"], "evidence": evidence, "source": "git-history",
                })
    return findings


def main():
    ap = argparse.ArgumentParser(description="AI Commit Trap scanner")
    ap.add_argument("--target", default=".")
    ap.add_argument("--history", action="store_true")
    ap.add_argument("--config", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    if args.config:
        config_path = args.config
    else:
        sibling = os.path.join(here, "config.yml")
        config_path = sibling if os.path.exists(sibling) else os.path.join(here, "..", "config.yml")
    cfg, patterns = load_config(config_path)

    findings = scan_files(args.target, cfg, patterns)
    if args.history:
        findings += scan_history(args.target, cfg, patterns)

    if args.json:
        import json
        print(json.dumps({"count": len(findings), "findings": findings}, indent=2))
    else:
        print(f"\n=== AI Commit Trap Scan :: {args.target} ===")
        print(f"Total high-risk exposures found: {len(findings)}\n")
        by_file = {}
        for f in findings:
            by_file.setdefault(f["file"], []).append(f)
        for fpath, items in sorted(by_file.items()):
            print(f"## {fpath}  ({len(items)} hit(s))")
            for it in items:
                loc = f"L{it['line']}" if it["line"] else ""
                print(f"  [{it['severity'].upper()}] {it['type']} {loc} -> {it['evidence']}")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
