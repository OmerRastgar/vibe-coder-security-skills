"""SAST Scan Server — synchronous, zero-state code scanner.

POST /scan           → multipart/form-data: zip + fields
                       Returns 200 {scan_id, status, report}
GET  /health         → tool versions
POST /process-report → reprocess raw scan data with AI

Security:
  - Code is extracted to /tmp/{scan_id}/, scanned, and deleted immediately.
  - No state persists between requests — container can scale to zero.
"""

import hashlib
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
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB

TMP_ROOT = Path("/tmp")
SCAN_TIMEOUT = 600
MAX_CONCURRENT = 3
scan_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT)

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


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------

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
# Synchronous scan runner
# ---------------------------------------------------------------------------

def run_scan(workdir, vuln_ids):
    """Run all tools, process with AI, return the final report dict."""
    scan_id = uuid.uuid4().hex[:12]
    tools = set()
    for vid in vuln_ids:
        tools.update(TOOL_PLAN.get(vid, []))

    tool_results = {}
    start = time.time()

    # Run tools in parallel
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
    total_tools_run = 0
    total_tools_failed = 0
    for vid in vuln_ids:
        tools_list = TOOL_PLAN.get(vid, [])
        vuln_breakdown[vid] = {"name": VULN_MAP[vid], "tools_used": tools_list}
        total_tools_run += len(tools_list)
        for tool_name in tools_list:
            if tool_name in tool_results and any(
                "error" in str(f) for f in tool_results[tool_name].get("findings", [])
            ):
                total_tools_failed += 1

    # Aggregate findings per vN
    findings_by_vuln = defaultdict(list)
    for tool_name, tr in tool_results.items():
        for vid in vuln_ids:
            if tool_name.startswith(f"semgrep_{vid}") or (tool_name in TOOL_PLAN.get(vid, [])):
                findings_by_vuln[vid].extend(tr.get("findings", []))

    for vid in vuln_breakdown:
        vuln_breakdown[vid]["findings_count"] = len(findings_by_vuln.get(vid, []))

    total_findings = sum(v["findings_count"] for v in vuln_breakdown.values())

    # Tag findings with vulnerability context
    for vid in vuln_ids:
        for f in findings_by_vuln.get(vid, []):
            f["vulnerability_id"] = vid
            f["vulnerability_name"] = VULN_MAP.get(vid, "")
            f["vulnerability_targets"] = ", ".join(TOOL_PLAN.get(vid, []))

    response_data = {
        "scan_id": scan_id,
        "vulnerabilities_scanned": list(vuln_ids),
        "breakdown": vuln_breakdown,
        "tool_results": tool_results,
        "findings_total": total_findings,
        "templates_executed": total_tools_run,
        "templates_failed": total_tools_failed,
        "duration_sec": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Process with AI
    processed = None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("ai_processor", "/app/ai_processor.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        processed = mod.process_report(response_data, "code")
    except Exception as e:
        app.logger.error(f"AI processing failed: {e}")

    # Fallback if AI processing failed
    if not processed or processed.get("score") is None:
        raw_findings_list = []
        for tool_name in ["trufflehog", "scanner_v2", "scanner_v6"]:
            raw_findings_list.extend(
                response_data.get("tool_results", {}).get(tool_name, {}).get("findings", [])
            )
        fallback_findings = []
        seen_findings = set()
        for f in raw_findings_list:
            if not isinstance(f, dict):
                continue
            has_title = bool(f.get("DetectorName") or f.get("name") or f.get("type") or f.get("check_id") or f.get("check_name"))
            has_evidence = bool(f.get("Raw") or f.get("evidence") or f.get("note") or f.get("detail") or f.get("description"))
            has_location = bool(f.get("file") or f.get("path") or f.get("file_path") or f.get("matched-at"))
            if not ((has_title and has_evidence) or (has_location and has_evidence)):
                continue
            ev = f.get("evidence") or f.get("Raw") or f.get("note") or f.get("detail") or ""
            ev_key = hashlib.md5(ev[:200].encode()).hexdigest()[:12] if ev else str(id(f))
            if ev_key in seen_findings:
                continue
            seen_findings.add(ev_key)
            t = (f.get("name") or f.get("type") or f.get("check_name") or f.get("DetectorName") or "Security Finding")
            imp = (f.get("note") or f.get("detail") or f.get("Raw") or "Security issue detected by scanner.")[:200]
            loc = ""
            if f.get("file"):
                line = f.get("line", "")
                loc = f"{f['file']}:{line}" if line else f['file']
            elif f.get("matched-at"):
                loc = f["matched-at"]
            detail_parts = []
            if loc:
                detail_parts.append(f"Location: {loc}")
            if f.get("note"):
                detail_parts.append(f"{f['note']}")
            if f.get("detail"):
                detail_parts.append(f"{f['detail']}")
            if ev:
                detail_parts.append(f"Evidence: {ev[:300]}")
            detail = "\n".join(detail_parts) if detail_parts else "No details available."
            fallback_findings.append({
                "severity": "Low",
                "title": t,
                "impact": imp,
                "fix": f"Remove the hardcoded secret from {loc or 'the source file'} and use environment variables or a secrets manager.",
                "detail": detail,
                "aiPrompt": (
                    f"I need help fixing a Low-severity security issue in my application.\n\n"
                    f"**Issue:** {t}\n\n"
                    f"**Evidence found:** {ev[:200]}\n\n"
                    f"**Location:** {loc}\n\n"
                    f"Please provide:\n"
                    f"1. An explanation of the vulnerability and its impact\n"
                    f"2. Step-by-step instructions to fix it\n"
                    f"3. Code examples showing the fix\n"
                    f"4. Any additional security best practices to prevent similar issues"
                ),
                "template_id": f.get("type") or f.get("category") or "",
            })
        processed = {
            "score": 100 - min(total_findings * 5, 100),
            "duration_sec": duration,
            "summary": f"Scan complete. {total_findings} issue(s) found.",
            "severityCounts": {"Critical": 0, "High": 0, "Medium": 0, "Low": total_findings},
            "findings": fallback_findings,
            "templatesExecuted": total_tools_run,
            "templatesFailed": total_tools_failed,
            "totalFindings": total_findings,
        }

    return {"scan_id": scan_id, "status": "completed", "report": processed}


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
                "error": "No valid input provided.",
                "hint": "Send: (1) a zip file via multipart/form-data with key 'file', (2) a JSON body with 'repo_url', or (3) a JSON body with 'zip_url'.",
                "received_keys": list(data.keys()) if data else (list(request.form.keys()) if request.form else []),
            }), 400

    try:
        vuln_ids = parse_vuln_ids(
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
            clone_url = repo_url
            github_token = os.environ.get("GITHUB_TOKEN", "")
            if github_token and "github.com" in repo_url:
                clone_url = repo_url.replace("https://github.com/", f"https://{github_token}@github.com/")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(workdir)],
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
    except zipfile.BadZipFile:
        saved_size = 0
        try:
            saved_size = os.path.getsize(str(workdir / "upload.zip"))
        except:
            pass
        shutil.rmtree(str(workdir), ignore_errors=True)
        scan_semaphore.release()
        return jsonify({"error": f"Invalid zip file ({saved_size} bytes). File is corrupted or not a zip."}), 400
    except Exception as e:
        shutil.rmtree(str(workdir), ignore_errors=True)
        scan_semaphore.release()
        return jsonify({"error": str(e)}), 400

    # Run scan synchronously — container stays alive until done
    try:
        result = run_scan(workdir, vuln_ids)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"}), 500
    finally:
        shutil.rmtree(str(workdir), ignore_errors=True)
        scan_semaphore.release()


@app.route("/health", methods=["GET"])
def health():
    versions = {}
    for tool_name, check_cmd in [
        ("semgrep", ["semgrep", "--version"]),
        ("trufflehog", ["trufflehog", "--version"]),
        ("checkov", ["pip", "show", "checkov"]),
    ]:
        try:
            r = subprocess.run(check_cmd, capture_output=True, text=True, timeout=60)
            out = (r.stdout + r.stderr).strip()
            if tool_name == "checkov" and "Version:" in out:
                for line in out.splitlines():
                    if line.startswith("Version:"):
                        versions[tool_name] = f"checkov {line.split(':',1)[1].strip()}"
                        break
            elif out:
                versions[tool_name] = out.split("\n")[0][:120]
            else:
                versions[tool_name] = "installed"
        except Exception as e:
            versions[tool_name] = "not found"

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    ai_status = "configured" if gemini_key else "not configured"
    return jsonify({
        "status": "ok",
        "versions": versions,
        "ai_status": ai_status,
        "max_concurrent": MAX_CONCURRENT,
        "github_auth": bool(os.environ.get("GITHUB_TOKEN")),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/process-report", methods=["POST"])
def process_report_route():
    """Process raw scan results through AI analysis."""
    try:
        data = request.get_json(silent=True) or {}
        scan_type = data.get("scan_type", "code")
        scan_data = data.get("scan_data", {})
        if not scan_data and data.get("results"):
            scan_data = data["results"]
        if not scan_data and data.get("findings") is not None:
            scan_data = data
        if not scan_data:
            return jsonify({"error": "scan_data is required."}), 400

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
#  
#  
