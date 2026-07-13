#!/usr/bin/env python3
"""
rename_reference_to_readme.py

Renames every `reference.md` inside the vulnerability folders
(`vulnerabilities/vN-*/reference.md`) to `README.md`.

Using `git mv` preserves file history. Safe to re-run: folders that already have
a `README.md` (or no `reference.md`) are skipped.

Usage:
  python scripts/rename_reference_to_readme.py [--dry-run]
"""

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_DIR = os.path.join(ROOT, "vulnerabilities")


def vuln_folders():
    dirs = [
        d for d in os.listdir(VULN_DIR)
        if os.path.isdir(os.path.join(VULN_DIR, d)) and d.startswith("v")
    ]
    def key(d):
        m = re.match(r"v(\d+)", d)
        return int(m.group(1)) if m else 999
    return sorted(dirs, key=key)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="print actions without executing")
    args = ap.parse_args()

    renamed = 0
    for folder in vuln_folders():
        ref = os.path.join(VULN_DIR, folder, "reference.md")
        readme = os.path.join(VULN_DIR, folder, "README.md")
        if not os.path.isfile(ref):
            continue
        if os.path.exists(readme):
            print(f"SKIP {folder}: README.md already exists")
            continue
        if args.dry_run:
            print(f"WOULD RENAME {folder}/reference.md -> {folder}/README.md")
            renamed += 1
            continue
        subprocess.run(["git", "mv", ref, readme], check=True,
                       cwd=ROOT)
        print(f"RENAMED {folder}/reference.md -> {folder}/README.md")
        renamed += 1

    print(f"\nDone. {renamed} file(s) {'would be ' if args.dry_run else ''}renamed.")


if __name__ == "__main__":
    main()
