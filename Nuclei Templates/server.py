"""Nuclei Scan Server — async REST API for running Nuclei vulnerability scans.

POST /scan           → 202 {scan_id, status: "accepted"}  (runs nuclei in background)
GET  /scan/{id}      → 200 {status: "running|completed|failed", data: ...}
GET  /scans          → list all past scans
GET  /templates      → list available vulnerability categories
GET  /health         → health check
GET  /log/{id}       → raw nuclei output
GET  /report/{id}    → raw JSONL results
"""

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

TEMPLATES_DIR = Path("/opt/templates")
NUCLEI_DIR = Path("/opt/nuclei-templates")
RESULTS_DIR = Path("/app/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SCANS_DIR = Path("/tmp/scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

# --- In-memory scan state ---
MAX_CONCURRENT = 5
scan_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT)
scan_state = {}
state_lock = threading.Lock()

# --- Rate limiter (simple token bucket) ---
rate_window = {}   # ip -> [timestamps]
RATE_WINDOW_SEC = 60
RATE_MAX_REQUESTS = 10  # max scan submissions per IP per minute

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


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

def check_rate_limit():
    ip = request.remote_addr or "unknown"
    now = time.time()
    with state_lock:
        bucket = rate_window.get(ip, [])
        bucket = [t for t in bucket if now - t < RATE_WINDOW_SEC]
        if len(bucket) >= RATE_MAX_REQUESTS:
            return False, f"Rate limit exceeded ({RATE_MAX_REQUESTS} scans per {RATE_WINDOW_SEC}s)"
        bucket.append(now)
        rate_window[ip] = bucket
    return True, None


# ---------------------------------------------------------------------------
# Validation & helpers
# ---------------------------------------------------------------------------

def validate_vulns(ids):
    if ids is None or len(ids) == 0:
        return list(VULN_MAP.keys())
    invalid = [v for v in ids if v not in VULN_MAP]
    if invalid:
        raise ValueError(f"Unknown vulnerability IDs: {invalid}. Valid: {sorted(VULN_MAP.keys())}")
    return ids


def collect_templates_per_vuln(vuln_ids):
    per_vuln = {}
    all_paths = []
    for vid in vuln_ids:
        tf = TEMPLATES_DIR / VULN_MAP[vid][0]
        if not tf.exists():
            raise FileNotFoundError(f"Template list file missing: {tf}")
        paths = [p.strip() for p in tf.read_text().strip().splitlines() if p.strip()]
        per_vuln[vid] = paths
        all_paths.extend(paths)
    return per_vuln, all_paths


def build_scan_workdir(template_paths):
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


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def run_scan_background(scan_id, url, vuln_ids, per_vuln, all_paths, concurrency, timeout_per):
    try:
        with state_lock:
            scan_state[scan_id] = {"status": "copying", "progress": 0}

        scan_workdir, templates_copied = build_scan_workdir(all_paths)
        output_file = RESULTS_DIR / f"{scan_id}.jsonl"

        with state_lock:
            scan_state[scan_id] = {"status": "running", "progress": 0}

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
            "-stats",
            "-stats-interval", "10",
            "-disable-update-check",
            "-v",
        ]

        log_file = RESULTS_DIR / f"{scan_id}_log.txt"
        start = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        duration = round(time.time() - start, 2)

        log_text = (result.stdout or "") + "\n" + (result.stderr or "")
        log_file.write_text(log_text)

        # Parse findings
        findings = []
        if output_file.exists():
            for line in output_file.read_text().strip().splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        findings.append({"raw": line})

        final_stats, stats_errors, template_errors = parse_nuclei_output(log_text, vuln_ids)

        vuln_breakdown = {}
        for vid in vuln_ids:
            requested = len(per_vuln.get(vid, []))
            vuln_breakdown[vid] = {
                "name": VULN_MAP[vid][1],
                "templates_requested": requested,
            }

        findings_by_vuln = defaultdict(list)
        for f in findings:
            tid = f.get("template-id") or ""
            vid = classify_finding_from_template_id(tid, vuln_ids)
            if vid:
                findings_by_vuln[vid].append(f)

        for vid in vuln_breakdown:
            f_list = findings_by_vuln.get(vid, [])
            vuln_breakdown[vid]["findings_count"] = len(f_list)
            vuln_breakdown[vid]["severity_counts"] = count_severities(f_list)
            te = template_errors.get(vid, {})
            vuln_breakdown[vid]["templates_failed"] = len(te.get("failed", []))
            vuln_breakdown[vid]["failed_template_ids"] = te.get("failed", [])

        unmapped = len([f for f in findings
            if not classify_finding_from_template_id(f.get("template-id") or "", vuln_ids)])

        # Tag findings with their vulnerability context
        for f in findings:
            vid = classify_finding_from_template_id(f.get("template-id", "") or "")
            if vid:
                f["vulnerability_id"] = vid
                f["vulnerability_name"] = VULN_MAP.get(vid, [None])[1] if vid in VULN_MAP else ""

        shutil.rmtree(scan_workdir, ignore_errors=True)

        response_data = {
            "scan_id": scan_id,
            "url": url,
            "vulnerabilities_scanned": list(vuln_ids),
            "breakdown": vuln_breakdown,
            "findings": findings,
            "findings_total": len(findings),
            "unmapped_findings": unmapped,
            "duration_sec": duration,
            "scan_output": {
                "summary": final_stats,
                "errors": stats_errors,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        (RESULTS_DIR / f"{scan_id}_summary.json").write_text(json.dumps(response_data, indent=2))

        # Auto-process the report with AI analysis
        try:
            from ai_processor import process_report as process
            processed = process(response_data, "url")
            (RESULTS_DIR / f"{scan_id}_report.json").write_text(json.dumps({
                "token": "not_used",
                "report": processed,
            }, indent=2))
        except Exception:
            pass

        with state_lock:
            scan_state[scan_id] = {"status": "completed", "progress": 100}

    except subprocess.TimeoutExpired:
        with state_lock:
            scan_state[scan_id] = {"status": "failed", "error": "Scan timed out after 300s"}
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
    allowed, rate_error = check_rate_limit()
    if not allowed:
        return jsonify({"error": rate_error}), 429

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    try:
        vuln_ids = validate_vulns(data.get("vulnerabilities"))
        per_vuln, all_paths = collect_templates_per_vuln(vuln_ids)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500

    if not all_paths:
        return jsonify({"error": "No templates resolved"}), 400

    # Check concurrency
    acquired = scan_semaphore.acquire(blocking=False)
    if not acquired:
        return jsonify({
            "error": f"Server busy. Max {MAX_CONCURRENT} concurrent scans. Try again shortly.",
            "retry_after_sec": 30,
        }), 503

    scan_id = uuid.uuid4().hex[:12]
    token = uuid.uuid4().hex[:16]
    concurrency = int(data.get("concurrency") or 10)
    timeout_per = int(data.get("timeout") or 15)

    with state_lock:
        scan_state[scan_id] = {"status": "queued", "progress": 0, "token": token}

    thread = threading.Thread(
        target=run_scan_background,
        args=(scan_id, url, vuln_ids, per_vuln, all_paths, concurrency, timeout_per),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "token": token,
        "status": "accepted",
        "vulnerabilities": list(vuln_ids),
        "check_status": f"/scan/{scan_id}",
    }), 202


@app.route("/scan/<scan_id>", methods=["GET"])
def get_scan_status(scan_id):
    token = request.headers.get("X-Scan-Token") or request.args.get("token")

    with state_lock:
        state = scan_state.get(scan_id)

    if state is None:
        summary_file = RESULTS_DIR / f"{scan_id}_summary.json"
        if summary_file.exists():
            return jsonify({"status": "completed", "results": json.loads(summary_file.read_text())})
        return jsonify({"error": "scan not found"}), 404

    if token and state.get("token") != token:
        return jsonify({"error": "invalid token"}), 403

    if state["status"] == "completed":
        # Return the AI-processed report if available
        report_file = RESULTS_DIR / f"{scan_id}_report.json"
        if report_file.exists():
            saved = json.loads(report_file.read_text())
            return jsonify({"status": "completed", "report": saved.get("report", {})})
        summary_file = RESULTS_DIR / f"{scan_id}_summary.json"
        if summary_file.exists():
            return jsonify({"status": "completed", "results": json.loads(summary_file.read_text())})
        return jsonify({"status": "completed", "error": "summary file missing"})

    if state["status"] == "failed":
        return jsonify({"status": "failed", "error": state.get("error")})

    return jsonify({"status": state["status"], "progress": state.get("progress", 0)})


@app.route("/health", methods=["GET"])
def health():
    with state_lock:
        running = sum(1 for s in scan_state.values() if s["status"] in ("running", "copying", "queued"))
    return jsonify({
        "status": "ok",
        "nuclei_version": get_nuclei_version(),
        "concurrent_scans": running,
        "max_concurrent": MAX_CONCURRENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/log/<scan_id>", methods=["GET"])
def get_log(scan_id):
    token = request.headers.get("X-Scan-Token") or request.args.get("token")
    with state_lock:
        state = scan_state.get(scan_id, {})
    if token and state.get("token") != token:
        return jsonify({"error": "invalid token"}), 403

    log_file = RESULTS_DIR / f"{scan_id}_log.txt"
    if not log_file.exists():
        return jsonify({"error": "log not found"}), 404
    raw = log_file.read_text()
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    return jsonify({
        "scan_id": scan_id,
        "size_bytes": len(raw),
        "lines": len(raw.splitlines()),
        "log": clean,
    })


@app.route("/report/<scan_id>", methods=["GET"])
def get_report(scan_id):
    token = request.headers.get("X-Scan-Token") or request.args.get("token")
    with state_lock:
        state = scan_state.get(scan_id, {})
    if token and state.get("token") != token:
        return jsonify({"error": "invalid token"}), 403

    jsonl_file = RESULTS_DIR / f"{scan_id}.jsonl"
    if not jsonl_file.exists():
        return jsonify({"error": "report not found"}), 404
    return jsonify({
        "scan_id": scan_id,
        "results": [json.loads(line) for line in jsonl_file.read_text().strip().splitlines() if line.strip()],
    })


@app.route("/scans", methods=["GET"])
def list_scans():
    """Return only scan IDs — no URLs or results exposed without token."""
    ids = []
    for f in sorted(RESULTS_DIR.glob("*_summary.json"), reverse=True):
        sid = f.stem.replace("_summary", "")
        ids.append(sid)
    return jsonify({"scan_count": len(ids), "scan_ids": ids})


@app.route("/process-report", methods=["POST"])
def process_report():
    """Process raw scan results through AI analysis. Auto-unwraps full scan responses."""
    try:
        data = request.get_json(silent=True) or {}
        scan_type = data.get("scan_type", "url")
        scan_data = data.get("scan_data", {})

        if not scan_data and data.get("results"):
            scan_data = data["results"]
        if not scan_data and data.get("findings") is not None:
            scan_data = data

        if not scan_data:
            return jsonify({"error": "scan_data is required. Send raw scan results or a full scan response."}), 400

        from ai_processor import process_report as process
        report = process(scan_data, scan_type)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Helpers (classify, parse, version)
# ---------------------------------------------------------------------------

def classify_finding_from_template_id(template_id, scanned_vulns=None):
    if not template_id:
        return None
    vulns_to_check = scanned_vulns or list(VULN_MAP.keys())
    for vid in vulns_to_check:
        tf = TEMPLATES_DIR / VULN_MAP[vid][0]
        if tf.exists():
            for line in tf.read_text().strip().splitlines():
                stripped = line.strip()
                if stripped and stripped.endswith(f"/{template_id}.yaml"):
                    return vid
    return None


def count_severities(findings):
    counts = defaultdict(int)
    for f in findings:
        sev = (f.get("info", {}).get("severity") or f.get("severity") or "unknown").lower()
        counts[sev] += 1
    return dict(counts)


def parse_nuclei_output(full_log, scanned_vulns=None):
    stats_lines = []
    errors = []
    final_stats = {}

    for line in full_log.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if "templates" in parsed and "hosts" in parsed:
                    stats_lines.append(parsed)
            except json.JSONDecodeError:
                pass
        clean = re.sub(r'\x1b\[[0-9;]*m', '', stripped)
        if any(kw in clean for kw in ["Could not", "ERR", "FTL"]):
            errors.append(clean)
        template_warn = re.match(r'\[[\d:\-]+\]\s*\[(?:WRN|ERR)\]\s*\[(\S+)\]\s*(.*)', clean)
        if template_warn:
            tid = template_warn.group(1)
            msg = template_warn.group(2)
            if "Scan results upload" not in msg and "Excluded" not in msg and "Could not read" not in msg:
                errors.append(f"[{tid}] {msg}")

    if stats_lines:
        final = stats_lines[-1]
        final_stats = {
            "templates_executed": int(final.get("templates", 0)),
            "hosts": int(final.get("hosts", 0)),
            "matched": int(final.get("matched", 0)),
            "errors": int(final.get("errors", 0)),
            "requests_sent": int(final.get("requests", 0)),
            "rps": int(float(final.get("rps", 0))),
            "total_templates_loaded": int(final.get("total", 0)),
        }

    template_errors_by_vuln = {}
    template_error_pattern = re.compile(r'\[(\S+)\].*(?:Could not|failed|unresolved)', re.IGNORECASE)
    for line in full_log.splitlines():
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line.strip())
        m = template_error_pattern.search(clean)
        if m:
            tid = m.group(1)
            vid = classify_finding_from_template_id(tid, scanned_vulns)
            if vid:
                template_errors_by_vuln.setdefault(vid, set()).add(tid)

    return final_stats, errors, {vid: {"failed": list(paths)} for vid, paths in template_errors_by_vuln.items()}


def get_nuclei_version():
    try:
        r = subprocess.run(
            ["nuclei", "-version", "-disable-update-check"],
            capture_output=True, text=True, timeout=10,
        )
        for line in (r.stderr + r.stdout).splitlines():
            if "Nuclei Engine" in line:
                return re.sub(r'\x1b\[[0-9;]*m', '', line.strip())
        return "unknown"
    except Exception:
        return "unknown"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
