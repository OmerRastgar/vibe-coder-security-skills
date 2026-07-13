#!/usr/bin/env python3
"""
build_readme.py

Generates the top-level Readme.md from the per-vulnerability source files so the
vulnerability folders are the single source of truth — no duplicated text lives
in Readme.md.

For each folder under vulnerabilities/vN-...:
  - README.md     -> the "Detail" prose + Attack Surface Flowchart (any
                     "[<-- Back to full guide ...]" footer line is dropped)
  - prompt.md     -> appended under a "### Prompt to do an Audit" heading

The intro + index table come from Readme.template.md so they stay editable
without regenerating them from code.

Usage:
  python scripts/build_readme.py [--check]

  --check  : exit non-zero if Readme.md is out of date (used by CI).
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_DIR = os.path.join(ROOT, "vulnerabilities")
TEMPLATE = os.path.join(ROOT, "Readme.template.md")
OUTPUT = os.path.join(ROOT, "Readme.md")

# Subheadings used inside reference.md that we do NOT want duplicated as a
# generated section header (they already live in the source file).
BACKLINK_RE = re.compile(r"\[<--\s+Back to full guide.*?\]\(.*?\)\s*$")


def vuln_folders():
    dirs = [
        d for d in os.listdir(VULN_DIR)
        if os.path.isdir(os.path.join(VULN_DIR, d)) and d.startswith("v")
    ]
    # sort by the numeric prefix so V1, V2, ... V11 stay in order
    def key(d):
        m = re.match(r"v(\d+)", d)
        return int(m.group(1)) if m else 999
    return sorted(dirs, key=key)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def clean_reference(text):
    """Drop the leading H1 title and the trailing back-link footer."""
    lines = text.splitlines()
    # drop the leading "# VN — Title" line; the generated section heading
    # already supplies the vulnerability title.
    if lines and re.match(r"#\s*V\d+\s*[—-]", lines[0]):
        lines = lines[1:]
    # drop a blank line / '---' separator right after the stripped title
    while lines and lines[0].strip() in ("", "---"):
        lines.pop(0)
    # drop trailing back-link footer line(s)
    while lines and BACKLINK_RE.match(lines[-1].strip()):
        lines.pop()
    while lines and lines[-1].strip() in ("", "---"):
        lines.pop()
    return "\n".join(lines).strip() + "\n"


def title_from_reference(text):
    first = text.splitlines()[0] if text.splitlines() else ""
    # "# V3 — Client-Side Security Misplacements" -> "Client-Side Security Misplacements"
    m = re.match(r"#\s*V\d+\s*[—-]\s*(.*)$", first)
    return m.group(1).strip() if m else first.lstrip("# ").strip()


def primary_targets(folder):
    """Pull the 'Targets:'/'Pathways:' line from README.md for the index table."""
    text = read_source(folder)
    m = re.search(r"(?im)^\s*(?:targets|pathways)\s*[:\-]\s*(.+)$", text)
    return m.group(1).strip() if m else ""


def read_source(folder):
    """Read the per-vulnerability source doc, preferring README.md.

    Falls back to reference.md so the build still works before/after the
    reference.md -> README.md rename.
    """
    for name in ("README.md", "reference.md"):
        path = os.path.join(VULN_DIR, folder, name)
        if os.path.isfile(path):
            return read(path)
    return ""


def number(folder):
    m = re.match(r"v(\d+)", folder)
    return int(m.group(1)) if m else 0


def build():
    if not os.path.isfile(TEMPLATE):
        print(f"ERROR: template not found at {TEMPLATE}", file=sys.stderr)
        sys.exit(1)

    template = read(TEMPLATE).rstrip() + "\n"

    parts = [template]

    if not template.endswith("\n"):
        parts.append("\n")

    index_rows = []
    sections = []

    for folder in vuln_folders():
        ref_path = os.path.join(VULN_DIR, folder, "README.md")
        prompt_path = os.path.join(VULN_DIR, folder, "prompt.md")
        if not os.path.isfile(ref_path) or not os.path.isfile(prompt_path):
            # fall back to legacy reference.md name
            alt = os.path.join(VULN_DIR, folder, "reference.md")
            if not os.path.isfile(alt) or not os.path.isfile(prompt_path):
                print(f"SKIP {folder} (missing README.md/reference.md or prompt.md)")
                continue
            ref_path = alt

        raw = read(ref_path)
        prompt = read(prompt_path).strip()
        title = title_from_reference(raw)
        ref = clean_reference(raw)
        num = number(folder)
        targets = primary_targets(folder)

        # section heading mirrors the legacy Readme style
        heading = f"## Vulnerability {num}: {title}"
        index_rows.append(
            f"| {num} | `{folder}` | {title} | {targets} |"
        )

        section = [heading, "", ref.rstrip(), "", "### Prompt to do an Audit", "",
                   "```", prompt, "```", ""]
        sections.append("\n".join(section))

    # Build the index table body (header + separator live in the template)
    index_md = "\n".join(index_rows) + "\n"

    generated = "\n".join(parts).rstrip() + "\n\n"
    generated += index_md + "\n"
    generated += "\n\n".join(sections) + "\n"

    # ensure final newline
    if not generated.endswith("\n"):
        generated += "\n"
    return generated


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if Readme.md is out of date")
    args = ap.parse_args()

    generated = build()

    if args.check:
        existing = read(OUTPUT) if os.path.isfile(OUTPUT) else ""
        if existing != generated:
            print("Readme.md is out of date. Run: python scripts/build_readme.py")
            sys.exit(1)
        print("Readme.md is up to date.")
        return

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(generated)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
