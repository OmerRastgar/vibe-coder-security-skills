#!/usr/bin/env python3
"""
restructure_vulnerabilities.py

For every vulnerability folder under `vulnerabilities/`:
  1. Merge detail.md + flowchart.md → reference.md  (skips if reference.md already exists)
  2. Delete detail.md and flowchart.md
  3. Move SKILL.md, config.yml, scripts/ → skill/SKILL.md, skill/config.yml, skill/scripts/
     (skips any file/folder that already exists in skill/)
  4. Delete the now-empty old locations (SKILL.md, config.yml, scripts/)

Safe to re-run — every step checks before acting.

Usage:
  python scripts/restructure_vulnerabilities.py [--dry-run]
"""

import argparse
import os
import shutil
import sys


VULN_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vulnerabilities")


def log(msg):
    print(msg)


def merge_reference(folder, dry_run):
    detail_path    = os.path.join(folder, "detail.md")
    flowchart_path = os.path.join(folder, "flowchart.md")
    reference_path = os.path.join(folder, "reference.md")

    has_detail    = os.path.isfile(detail_path)
    has_flowchart = os.path.isfile(flowchart_path)

    if not has_detail and not has_flowchart:
        return  # nothing to merge

    if not os.path.isfile(reference_path):
        detail_text    = open(detail_path,    encoding="utf-8").read().strip() if has_detail    else ""
        flowchart_text = open(flowchart_path, encoding="utf-8").read().strip() if has_flowchart else ""

        parts = []
        if detail_text:
            parts.append(detail_text)
        if flowchart_text:
            parts.append("---\n\n## Attack Surface Flowchart\n\n" + flowchart_text)

        content = "\n\n".join(parts) + "\n"
        log(f"  CREATE  reference.md")
        if not dry_run:
            with open(reference_path, "w", encoding="utf-8") as f:
                f.write(content)
    else:
        log(f"  SKIP    reference.md (already exists)")

    # delete detail.md and flowchart.md
    for path, name in [(detail_path, "detail.md"), (flowchart_path, "flowchart.md")]:
        if os.path.isfile(path):
            log(f"  DELETE  {name}")
            if not dry_run:
                os.remove(path)


def move_to_skill(folder, dry_run):
    skill_dir = os.path.join(folder, "skill")

    # files/dirs to move: (src_relative_to_folder, dest_relative_to_skill_dir)
    moves = [
        ("SKILL.md",   "SKILL.md"),
        ("config.yml", "config.yml"),
        ("scripts",    "scripts"),
    ]

    any_to_move = any(
        os.path.exists(os.path.join(folder, src))
        for src, _ in moves
    )
    if not any_to_move:
        return

    if not dry_run:
        os.makedirs(skill_dir, exist_ok=True)

    for src_name, dst_name in moves:
        src = os.path.join(folder, src_name)
        dst = os.path.join(skill_dir, dst_name)

        if not os.path.exists(src):
            continue

        if os.path.exists(dst):
            log(f"  SKIP    skill/{dst_name} (already exists)")
            # still delete the old location if it's a file
            if os.path.isfile(src):
                log(f"  DELETE  {src_name} (duplicate, skill/ version kept)")
                if not dry_run:
                    os.remove(src)
            continue

        log(f"  MOVE    {src_name} → skill/{dst_name}")
        if not dry_run:
            shutil.move(src, dst)


def process_folder(folder, dry_run):
    name = os.path.basename(folder)
    log(f"\n[{name}]")
    merge_reference(folder, dry_run)
    move_to_skill(folder, dry_run)


def main():
    parser = argparse.ArgumentParser(description="Restructure vulnerability folders")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing")
    args = parser.parse_args()

    if args.dry_run:
        log("=== DRY RUN — no files will be changed ===\n")

    if not os.path.isdir(VULN_ROOT):
        print(f"ERROR: vulnerabilities folder not found at {VULN_ROOT}", file=sys.stderr)
        sys.exit(1)

    folders = sorted([
        os.path.join(VULN_ROOT, d)
        for d in os.listdir(VULN_ROOT)
        if os.path.isdir(os.path.join(VULN_ROOT, d)) and d.startswith("v")
    ])

    for folder in folders:
        process_folder(folder, args.dry_run)

    log("\nDone.")


if __name__ == "__main__":
    main()
