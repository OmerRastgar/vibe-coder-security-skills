"""SAST Scan Server — async, zip-upload, zero-state code scanner.

POST /scan           → multipart/form-data: zip + fields
                       Returns 202 {scan_id, token}
GET  /scan/{id}      → header X-Scan-Token required
                       Returns {status, results}
GET  /health         → tool versions

Security:
  - Each scan gets a unique random token; only the submitter sees it.
  - Code is extracted to /tmp/{scan_id}/, scanned, and deleted immediately.
  - Cloud Run kills the container between requests; no disk persists.
"""

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200MB

TMP_ROOT = Path("/tmp")
SCAN_TIMEOUT = 600
MAX_CONCURRENT = 3
scan_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT)
scan_state = {}
state_lock = threading.Lock()

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_vulns(ids):
    if ids is None or len(ids) == 0:
        return list(VULN_MAP.keys())
    invalid = [v for v in ids if v not in VULN_MAP]
    if invalid:
        raise ValueError(f"Unknown vulnerability IDs: {invalid}. Valid: {sorted(VULN_MAP.keys())}")
    return ids


def parse_vuln_ids(raw):
    """Accept None, '["v1","v7"]', 'v1,v7', or just 'v7'."""
    if raw is None:
        return list(VULN_MAP.keys())
    if isinstance(raw, list):
        return validate_vulns(raw)
    s = str(raw).strip()
    if s.startswith("["):
        try:
            return validate_vulns(json.loads(s))
        except (json.JSONDecodeError, ValueError):
            raise ValueError(f"Could not parse vulnerabilities: {s}")
    ids = [v.strip() for v in s.split(",") if v.strip()]
    return validate_vulns(ids)


def run_trufflehog(target):
    findings = []
    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", "--directory", target, "--json",
             "--no-verification", "--fail", "--concurrency", "4"],
            capture_output=True, text=True, timeout=SCAN_TIMEOUT,
        )
        for line in result.stdout.strip().splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        findings.append({"error": f"trufflehog failed: {str(e)}"})
    return {"tool": "trufflehog", "findings": findings}


def run_scanner_v2(target):
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
        return {"tool": "scanner_v2", "findings": parsed.get("findings", [])}
    except Exception as e:
        return {"tool": "scanner_v2", "findings": [{"error": str(e)}]}


def run_scanner_v6(target):
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
        return {"tool": "scanner_v6", "findings": parsed.get("findings", [])}
    except Exception as e:
        return {"tool": "scanner_v6", "findings": [{"error": str(e)}]}


def run_semgrep(target, tag, rule_files=None):
    findings = []
    outfile = target + f"/.semgrep_{tag}_{uuid.uuid4().hex[:6]}.json"
    cmd = ["semgrep", "scan", "--json", "--output", outfile, "--quiet", "--no-git-ignore"]
    if rule_files:
        for rf in rule_files:
            if rf.exists():
                cmd += ["--config", str(rf)]
    cmd += ["--config", "auto"]
    cmd.append(target)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if os.path.exists(outfile):
            raw = json.loads(Path(outfile).read_text())
            for r in raw.get("results", []):
                findings.append({
                    "check_id": r.get("check_id", ""),
                    "path": r.get("path", ""),
                    "start": r.get("start", {}),
                    "extra": r.get("extra", {}),
                    "severity": r.get("extra", {}).get("severity", ""),
                })
    except Exception as e:
        findings.append({"error": f"semgrep {tag} failed: {str(e)}"})
    finally:
        if os.path.exists(outfile):
            os.remove(outfile)
    return {"tool": f"semgrep_{tag}", "findings": findings}


def run_checkov(target):
    findings = []
    outfile = target + f"/.checkov_{uuid.uuid4().hex[:6]}.json"
    cmd = ["checkov", "--directory", target, "--output", "json",
           "--output-file-path", target, "--output-basename",
           os.path.basename(outfile).replace(".json", ""),
           "--quiet", "--skip-framework", "secrets"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        real_out = Path(target) / (os.path.basename(outfile).replace(".json", "") + ".json")
        # checkov prefixes with results_
        for f in Path(target).glob("results_*.json"):
            real_out = f
            break
        if real_out.exists():
            raw = json.loads(real_out.read_text())
            for rec in raw.get("results", {}).get("failed_checks", []):
                findings.append({
                    "check_id": rec.get("check_id", ""),
                    "check_name": rec.get("check_name", ""),
                    "file_path": rec.get("file_path", ""),
                    "resource": rec.get("resource", ""),
                    "severity": rec.get("severity", ""),
                })
    except Exception as e:
        findings.append({"error": f"checkov failed: {str(e)}"})
    finally:
        for f in Path(target).glob("results_*.json"):
            try: os.remove(str(f))
            except: pass
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
# Background scan runner
# ---------------------------------------------------------------------------

def run_scan_background(scan_id, token, workdir, vuln_ids):
    try:
        with state_lock:
            scan_state[scan_id] = {"status": "running", "progress": 0, "token": token}

        tools = set()
        for vid in vuln_ids:
            tools.update(TOOL_PLAN.get(vid, []))

        tool_results = {}
        start = time.time()

        threads = []
        thread_lock = threading.Lock()

        def run_one(tool_name):
            try:
                result = TOOL_RUNNERS[tool_name](str(workdir))
            except Exception as e:
                result = {"tool": tool_name, "findings": [{"error": str(e)}]}
            with thread_lock:
                tool_results[tool_name] = result

        for tool in tools:
            t = threading.Thread(target=run_one, args=(tool,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=SCAN_TIMEOUT)

        duration = round(time.time() - start, 2)

        # Build breakdown
        vuln_breakdown = {}
        for vid in vuln_ids:
            vuln_breakdown[vid] = {
                "name": VULN_MAP[vid],
                "tools_used": TOOL_PLAN.get(vid, []),
            }

        # Aggregate findings per vN
        findings_by_vuln = defaultdict(list)
        for tool_name, tr in tool_results.items():
            # Rough mapping: semgrep_v3 -> v3
            for vid in vuln_ids:
                if tool_name.startswith(f"semgrep_{vid}") or \
                   (tool_name in TOOL_PLAN.get(vid, [])):
                    findings_by_vuln[vid].extend(tr.get("findings", []))

        for vid in vuln_breakdown:
            vuln_breakdown[vid]["findings_count"] = len(findings_by_vuln.get(vid, []))

        total_findings = sum(v["findings_count"] for v in vuln_breakdown.values())


        response_data = {
            "scan_id": scan_id,
            "vulnerabilities_scanned": list(vuln_ids),
            "breakdown": vuln_breakdown,
            "tool_results": tool_results,
            "findings_total": total_findings,
            "duration_sec": duration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Save results + token to disk
        (workdir / "results.json").write_text(json.dumps({
            "token": token,
            "results": response_data,
        }, indent=2))

        with state_lock:
            scan_state[scan_id] = {"status": "completed", "progress": 100, "token": token}

    except Exception as e:
        with state_lock:
            scan_state[scan_id] = {"status": "failed", "error": str(e)}
    finally:
        scan_semaphore.release()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():
    is_zip = "file" in request.files and request.files["file"].filename
    is_repo = False
    is_zip_url = False
    data = {}

    if not is_zip:
        data = request.get_json(silent=True) or {}
        repo_url = (data.get("repo_url") or data.get("repo") or "").strip()
        zip_url = (data.get("zip_url") or "").strip()
        if repo_url:
            is_repo = True
        elif zip_url:
            is_zip_url = True
        else:
            return jsonify({
                "error": "Send a zip file (multipart/form-data key 'file'), a repo URL (JSON 'repo_url'), or a zip URL (JSON 'zip_url')."
            }), 400

    try:
        vuln_ids_list = parse_vuln_ids(
            request.form.get("vulnerabilities") if is_zip else data.get("vulnerabilities")
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    acquired = scan_semaphore.acquire(blocking=False)
    if not acquired:
        return jsonify({
            "error": f"Server busy. Max {MAX_CONCURRENT} concurrent scans.",
            "retry_after_sec": 30,
        }), 503

    scan_id = uuid.uuid4().hex[:12]
    token = uuid.uuid4().hex[:16]
    workdir = TMP_ROOT / scan_id
    workdir.mkdir(parents=True, exist_ok=True)

    try:
        if is_zip:
            file = request.files["file"]
            file.save(str(workdir / "upload.zip"))
            with zipfile.ZipFile(str(workdir / "upload.zip"), "r") as zf:
                zf.extractall(str(workdir))
            os.remove(str(workdir / "upload.zip"))
        elif is_repo:
            workdir.rmdir()
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(workdir)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr.strip()}")
        elif is_zip_url:
            result = subprocess.run(
                ["curl", "-sSL", "-o", str(workdir / "upload.zip"), data.get("zip_url")],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                raise Exception(f"Failed to download zip: {result.stderr.strip()}")
            with zipfile.ZipFile(str(workdir / "upload.zip"), "r") as zf:
                zf.extractall(str(workdir))
            os.remove(str(workdir / "upload.zip"))
        shutil.rmtree(str(workdir), ignore_errors=True)
        scan_semaphore.release()
        return jsonify({"error": "Invalid zip file."}), 400
    except Exception as e:
        shutil.rmtree(str(workdir), ignore_errors=True)
        scan_semaphore.release()
        return jsonify({"error": str(e)}), 400

    with state_lock:
        scan_state[scan_id] = {"status": "queued", "token": token}

    thread = threading.Thread(
        target=run_scan_background,
        args=(scan_id, token, workdir, vuln_ids_list),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "token": token,
        "status": "accepted",
        "vulnerabilities": vuln_ids_list,
        "check_status": f"/scan/{scan_id}",
    }), 202


@app.route("/scan/<scan_id>", methods=["GET"])
def get_scan_status(scan_id):
    token = request.headers.get("X-Scan-Token") or request.args.get("token")

    with state_lock:
        state = scan_state.get(scan_id)

    if state is None:
        workdir = TMP_ROOT / scan_id
        results_file = workdir / "results.json"
        if results_file.exists():
            saved = json.loads(results_file.read_text())
            if token and saved.get("token") != token:
                return jsonify({"error": "invalid token"}), 403
            return jsonify({"status": "completed",
                           "results": saved.get("results", saved)})
        return jsonify({"error": "scan not found"}), 404

    if token and state.get("token") != token:
        return jsonify({"error": "invalid token"}), 403

    if state["status"] == "completed":
        workdir = TMP_ROOT / scan_id
        results_file = workdir / "results.json"
        if results_file.exists():
            saved = json.loads(results_file.read_text())
            results = saved.get("results", saved)
            shutil.rmtree(str(workdir), ignore_errors=True)
            return jsonify({"status": "completed", "results": results})

    if state["status"] == "failed":
        shutil.rmtree(str(TMP_ROOT / scan_id), ignore_errors=True)
        return jsonify({"status": "failed", "error": state.get("error")})

    return jsonify({"status": state["status"], "progress": state.get("progress", 0)})


@app.route("/health", methods=["GET"])
def health():
    versions = {}
    for tool_name, check_cmd in [
        ("semgrep", ["semgrep", "--version"]),
        ("trufflehog", ["trufflehog", "--version"]),
        ("checkov", ["checkov", "--version"]),
    ]:
        try:
            r = subprocess.run(check_cmd, capture_output=True, text=True, timeout=15)
            out = (r.stdout + r.stderr).strip()
            if out:
                versions[tool_name] = out.split("\n")[0] if "\n" in out else out[:120]
            else:
                versions[tool_name] = "installed (no output)"
        except FileNotFoundError:
            versions[tool_name] = "not installed"
        except Exception as e:
            versions[tool_name] = str(e)[:80]

    with state_lock:
        running = sum(1 for s in scan_state.values() if s["status"] in ("running", "copying", "queued"))
    return jsonify({
        "status": "ok",
        "versions": versions,
        "concurrent_scans": running,
        "max_concurrent": MAX_CONCURRENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/templates", methods=["GET"])
def list_templates():
    result = {}
    for vid, name in VULN_MAP.items():
        result[vid] = {"name": name, "tools": TOOL_PLAN.get(vid, [])}
    return jsonify(result)


@app.route("/process-report", methods=["POST"])
def process_report():
    """Process raw scan results through AI analysis."""
    try:
        data = request.get_json(silent=True) or {}
        scan_type = data.get("scan_type", "code")
        scan_data = data.get("scan_data", {})

        if not scan_data:
            return jsonify({"error": "scan_data is required"}), 400

        # Import ai_processor dynamically (shared module)
        import importlib.util
        spec = importlib.util.spec_from_file_location("ai_processor", "/app/ai_processor.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        report = mod.process_report(scan_data, scan_type)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), threaded=True)
