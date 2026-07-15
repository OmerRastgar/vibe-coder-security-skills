"""Nuclei Scan Server — REST API for running Nuclei vulnerability scans.

POST /scan
    Body: {"url": "https://target.com", "vulnerabilities": ["v1","v3"]}
    Returns: JSON scan results

    vulnerabilities: list of v1-v11 identifiers, or null/omitted to scan ALL

GET /templates  — list available vulnerability categories and template counts
GET /health     — health check
"""

import json
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

TEMPLATES_DIR = Path("/opt/templates")
NUCLEI_DIR = Path("/opt/nuclei-templates")
RESULTS_DIR = Path("/app/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SCANS_DIR = Path("/tmp/scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

VULN_MAP = {
    "v1":  ("V1.txt",  "AI Commit Trap"),
    "v2":  ("v2.txt",  "Package Hallucination"),
    "v3":  ("v3.txt",  "Client-Side Security Misplacements"),
    "v4":  ("v4.txt",  "Disabled Data Isolation"),
    "v5":  ("v5.txt",  "Missing Input Validation"),
    "v6":  ("v6.txt",  "Baking Secrets into Source"),
    "v7":  ("v7.txt",  "AI Default Credentials"),
    "v8":  ("v8.txt",  "Flawed Object Authorization"),
    "v9":  ("v9.txt",  "Denial of Wallet & Rate-Limiting"),
    "v10": ("v10.txt", "CORS & IAM Perimeter Dissolution"),
    "v11": ("v11.txt", "Structural Type Enforcement"),
}


def validate_vulns(ids):
    if ids is None or len(ids) == 0:
        return list(VULN_MAP.keys())
    invalid = [v for v in ids if v not in VULN_MAP]
    if invalid:
        raise ValueError(f"Unknown vulnerability IDs: {invalid}. Valid: {sorted(VULN_MAP.keys())}")
    return ids


def collect_template_paths(vuln_ids):
    paths = []
    for vid in vuln_ids:
        tf = TEMPLATES_DIR / VULN_MAP[vid][0]
        if not tf.exists():
            raise FileNotFoundError(f"Template list file missing: {tf}")
        for line in tf.read_text().strip().splitlines():
            p = line.strip()
            if p:
                paths.append(p)
    return paths


def build_scan_workdir(template_paths):
    """
    Copy only the required templates from NUCLEI_DIR into a temp workdir,
    preserving their relative directory structure so nuclei can traverse them.
    Returns (workdir, copied_count).
    """
    workdir = SCANS_DIR / uuid.uuid4().hex[:12]
    workdir.mkdir(parents=True, exist_ok=True)
    count = 0
    for rel in template_paths:
        src = NUCLEI_DIR / rel
        if src.exists():
            dst = workdir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            count += 1
    return workdir, count


@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url is required"}), 400

        vuln_ids = validate_vulns(data.get("vulnerabilities"))
        template_paths = collect_template_paths(vuln_ids)

        if not template_paths:
            return jsonify({"error": "No templates resolved"}), 400

        scan_workdir, templates_copied = build_scan_workdir(template_paths)
        scan_id = uuid.uuid4().hex[:12]
        output_file = RESULTS_DIR / f"{scan_id}.jsonl"

        concurrency = int(data.get("concurrency") or 10)
        timeout_per = int(data.get("timeout") or 15)

        cmd = [
            "nuclei",
            "-u", url,
            "-templates", str(scan_workdir),
            "-jsonl",
            "-output", str(output_file),
            "-no-mhe",
            "-concurrency", str(concurrency),
            "-timeout", str(timeout_per),
            "-max-host-error", "5",
            "-retries", "1",
            "-silent",
        ]

        start = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        duration = round(time.time() - start, 2)

        shutil.rmtree(scan_workdir, ignore_errors=True)

        findings = []
        if output_file.exists():
            for line in output_file.read_text().strip().splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        findings.append({"raw": line})

        return jsonify({
            "scan_id": scan_id,
            "url": url,
            "vulnerabilities_scanned": [
                {"id": vid, "name": VULN_MAP[vid][1]} for vid in vuln_ids
            ],
            "templates_requested": len(template_paths),
            "templates_resolved": templates_copied,
            "findings": findings,
            "duration_sec": duration,
            "stats": format_stats(result.stderr),
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out after 300s"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def format_stats(stderr):
    lines = [l.strip() for l in stderr.splitlines() if l.strip()]
    return lines[-15:] if lines else []


@app.route("/templates", methods=["GET"])
def list_templates():
    result = {}
    for vid, (filename, name) in VULN_MAP.items():
        tf = TEMPLATES_DIR / filename
        count = 0
        if tf.exists():
            count = len([l for l in tf.read_text().strip().splitlines() if l.strip()])
        result[vid] = {"name": name, "file": filename, "template_count": count}
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "nuclei_version": get_nuclei_version(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def get_nuclei_version():
    try:
        r = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip().split("\n")[0]
    except Exception:
        return "unknown"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
