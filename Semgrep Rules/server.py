"""SAST Scan Server — routes vulnerabilities to the right code-scanning tool.

POST /scan
    Body: {"target": "/mnt/code", "vulnerabilities": ["v1","v6","v8"]}
    Returns: aggregated JSON findings from all applicable SAST tools

Tools per vulnerability:
    v1  → TruffleHog (secrets in source + git history)
    v2  → Custom Python scanner (package hallucination)
    v3  → Semgrep (client-side rules)
    v4  → Semgrep + Checkov (data isolation, IaC)
    v5  → Semgrep (input validation rules)
    v6  → TruffleHog + Custom regex scanner (hardcoded secrets)
    v7  → Semgrep + Checkov (default credentials, IaC misconfigs)
    v8  → Semgrep (object authorization / mass assignment)
    v9  → Semgrep (rate-limit config patterns)
    v10 → Checkov (IAM/cors policies) + Semgrep
    v11 → Semgrep (type enforcement rules)
"""

import json
import os
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

SCAN_TIMEOUT = 600

VULN_MAP = {
    "v1":  "AI Commit Trap",
    "v2":  "Package Hallucination",
    "v3":  "Client-Side Security Misplacements",
    "v4":  "Disabled Data Isolation",
    "v5":  "Missing Input Validation",
    "v6":  "Baking Secrets into Source",
    "v7":  "AI Default Credentials",
    "v8":  "Flawed Object Authorization",
    "v9":  "Denial of Wallet & Rate-Limiting",
    "v10": "CORS & IAM Perimeter Dissolution",
    "v11": "Structural Type Enforcement",
}

TOOL_PLAN = {
    "v1":  ["trufflehog"],
    "v2":  ["scanner_v2"],
    "v3":  ["semgrep_v3"],
    "v4":  ["checkov"],
    "v5":  ["semgrep_v5"],
    "v6":  ["trufflehog", "scanner_v6"],
    "v7":  ["checkov_credentials"],
    "v8":  ["semgrep_v8"],
    "v9":  ["semgrep_v9"],
    "v10": ["checkov_iam"],
    "v11": ["semgrep_v11"],
}

SEMGREP_COMMUNITY_RULES = {
    "v3": "auto",
    "v5": "auto",
    "v9": "auto",
}

RESULT_DIR = Path("/app/results")
RESULT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Tool runners — each returns a list of finding dicts
# ---------------------------------------------------------------------------

def run_trufflehog(target):
    findings = []
    scan_id = uuid.uuid4().hex[:8]
    outfile = RESULT_DIR / f"th_{scan_id}.json"

    cmd = [
        "trufflehog", "filesystem",
        "--directory", target,
        "--json",
        "--no-verification",
        "--fail",
        "--concurrency", "4",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        for line in result.stdout.strip().splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except subprocess.TimeoutExpired:
        findings.append({"error": "trufflehog timed out"})
    except Exception as e:
        findings.append({"error": f"trufflehog failed: {str(e)}"})

    return {"tool": "trufflehog", "findings": findings}


def run_scanner_v2(target):
    findings = []
    script = Path("/app/scanners/v2/scan.py")
    config = Path("/app/scanners/v2/config.yml")
    if not script.exists():
        return {"tool": "scanner_v2", "findings": [{"error": "scanner not found"}]}

    try:
        result = subprocess.run(
            ["python3", str(script), "--target", target, "--config", str(config), "--json"],
            capture_output=True, text=True, timeout=SCAN_TIMEOUT,
        )
        parsed = json.loads(result.stdout)
        findings = parsed.get("findings", [])
    except subprocess.TimeoutExpired:
        findings.append({"error": "v2 scanner timed out"})
    except Exception as e:
        findings.append({"error": f"v2 scanner failed: {str(e)}"})

    return {"tool": "scanner_v2", "findings": findings}


def run_scanner_v6(target):
    findings = []
    script = Path("/app/scanners/v6/scan.py")
    config = Path("/app/scanners/v6/config.yml")
    if not script.exists():
        return {"tool": "scanner_v6", "findings": [{"error": "scanner not found"}]}

    try:
        result = subprocess.run(
            ["python3", str(script), "--target", target, "--config", str(config), "--json"],
            capture_output=True, text=True, timeout=SCAN_TIMEOUT,
        )
        parsed = json.loads(result.stdout)
        findings = parsed.get("findings", [])
    except subprocess.TimeoutExpired:
        findings.append({"error": "v6 scanner timed out"})
    except Exception as e:
        findings.append({"error": f"v6 scanner failed: {str(e)}"})

    return {"tool": "scanner_v6", "findings": findings}


def run_semgrep(target, tag, rule_files=None):
    findings = []
    scan_id = uuid.uuid4().hex[:8]
    outfile = RESULT_DIR / f"sg_{tag}_{scan_id}.json"

    cmd = ["semgrep", "scan", "--json", "--output", str(outfile), "--quiet", "--no-git-ignore"]

    if rule_files:
        for rf in rule_files:
            if rf.exists():
                cmd += ["--config", str(rf)]

    if tag in SEMGREP_COMMUNITY_RULES:
        cmd += ["--config", SEMGREP_COMMUNITY_RULES[tag]]

    cmd.append(target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if outfile.exists():
            raw = json.loads(outfile.read_text())
            for r in raw.get("results", []):
                findings.append({
                    "check_id": r.get("check_id", ""),
                    "path": r.get("path", ""),
                    "start": r.get("start", {}),
                    "end": r.get("end", {}),
                    "extra": r.get("extra", {}),
                    "severity": r.get("extra", {}).get("severity", ""),
                })
    except subprocess.TimeoutExpired:
        findings.append({"error": f"semgrep {tag} timed out"})
    except Exception as e:
        findings.append({"error": f"semgrep {tag} failed: {str(e)}"})

    return {"tool": f"semgrep_{tag}", "findings": findings}


def run_checkov(target, framework=None):
    findings = []
    scan_id = uuid.uuid4().hex[:8]
    outfile = RESULT_DIR / f"ck_{scan_id}.json"

    cmd = ["checkov", "--directory", target, "--output", "json", "--output-file-path", str(RESULT_DIR), "--output-basename", f"ck_{scan_id}", "--quiet", "--skip-framework", "secrets"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        json_out = RESULT_DIR / f"ck_{scan_id}.json"
        if json_out.exists():
            raw = json.loads(json_out.read_text())
            for rec in raw.get("results", {}).get("failed_checks", []):
                findings.append({
                    "check_id": rec.get("check_id", ""),
                    "check_name": rec.get("check_name", ""),
                    "file_path": rec.get("file_path", ""),
                    "file_line_range": rec.get("file_line_range", []),
                    "resource": rec.get("resource", ""),
                    "guideline": rec.get("guideline", ""),
                    "severity": rec.get("severity", ""),
                })
    except subprocess.TimeoutExpired:
        findings.append({"error": "checkov timed out"})
    except Exception as e:
        findings.append({"error": f"checkov failed: {str(e)}"})

    return {"tool": "checkov", "findings": findings}


TOOL_RUNNERS = {
    "trufflehog": run_trufflehog,
    "scanner_v2": run_scanner_v2,
    "scanner_v6": run_scanner_v6,
    "semgrep_v3":  lambda t: run_semgrep(t, "v3", [Path("/app/rules/v3-client-side.yaml")]),
    "semgrep_v5":  lambda t: run_semgrep(t, "v5"),
    "semgrep_v8":  lambda t: run_semgrep(t, "v8", [Path("/app/rules/v8-object-authorization.yaml")]),
    "semgrep_v9":  lambda t: run_semgrep(t, "v9"),
    "semgrep_v11": lambda t: run_semgrep(t, "v11", [Path("/app/rules/v11-type-enforcement.yaml")]),
    "checkov": run_checkov,
    "checkov_credentials": run_checkov,
    "checkov_iam": run_checkov,
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()

    if not target:
        return jsonify({"error": "target path is required"}), 400
    if not os.path.isdir(target):
        return jsonify({"error": f"target directory not found: {target}"}), 400

    vuln_ids = data.get("vulnerabilities")
    if vuln_ids is None or len(vuln_ids) == 0:
        vuln_ids = list(VULN_MAP.keys())

    invalid = [v for v in vuln_ids if v not in VULN_MAP]
    if invalid:
        return jsonify({"error": f"Unknown vulnerability IDs: {invalid}. Valid: {sorted(VULN_MAP.keys())}"}), 400

    tools = set()
    for vid in vuln_ids:
        tools.update(TOOL_PLAN.get(vid, []))

    tool_results = {}
    start = time.time()

    with ThreadPoolExecutor(max_workers=min(len(tools), 6)) as executor:
        futures = {
            executor.submit(TOOL_RUNNERS[tool], target): tool
            for tool in tools
        }
        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                tool_results[tool_name] = future.result()
            except Exception as e:
                tool_results[tool_name] = {"tool": tool_name, "findings": [{"error": str(e)}]}

    duration = round(time.time() - start, 2)

    total_findings = sum(
        len(v.get("findings", [])) for v in tool_results.values()
        if isinstance(v, dict)
    )

    return jsonify({
        "scan_id": uuid.uuid4().hex[:12],
        "target": target,
        "vulnerabilities_scanned": [
            {"id": vid, "name": VULN_MAP[vid]} for vid in vuln_ids
        ],
        "tools_executed": sorted(tools),
        "tool_results": tool_results,
        "total_findings": total_findings,
        "duration_sec": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/templates", methods=["GET"])
def list_templates():
    tool_plan = {}
    for vid, tools in TOOL_PLAN.items():
        tool_plan[vid] = {
            "name": VULN_MAP[vid],
            "tools": tools,
        }
    return jsonify({
        "vulnerabilities": tool_plan,
        "semgrep_rules": [f.name for f in Path("/app/rules").glob("*.yaml")] if Path("/app/rules").exists() else [],
        "scanners": [d.name for d in Path("/app/scanners").iterdir() if d.is_dir()] if Path("/app/scanners").exists() else [],
    })


@app.route("/health", methods=["GET"])
def health():
    versions = {}
    for tool in ["semgrep", "trufflehog", "checkov"]:
        try:
            r = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=10)
            versions[tool] = r.stdout.strip().split("\n")[0]
        except Exception:
            versions[tool] = "not found"

    return jsonify({
        "status": "ok",
        "versions": versions,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
