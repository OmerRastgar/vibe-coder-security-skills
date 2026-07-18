"""
AI Report Processor — Gemini integration for scan result analysis.

POST /process-report
    Body: {"scan_type": "url|code", "scan_data": {...raw scan results...}}
    Returns: AIProcessedReport matching the SecureMyVibe frontend format.

Requires GEMINI_API_KEY environment variable. If not set, falls back
to local processing with basic AI prompts.
"""

import json
import os
import re
from datetime import datetime, timezone
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError

API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

SEVERITY_WEIGHTS = {
    "Critical": 20,
    "High": 10,
    "Medium": 5,
    "Low": 1,
}

MAX_SCORE = 100


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def process_report(raw_results, scan_type="url", debug_path=None):
    """
    Takes raw scan results dict and returns AIProcessedReport.
    If debug_path is given, saves Gemini prompt + raw findings there.
    """
    findings_raw, templates_exec, templates_failed = extract_findings(raw_results, scan_type)
    duration = raw_results.get("duration_sec", 0)

    # Filter out empty/phantom findings (e.g. TruffleHog results with no detector or raw data)
    findings_raw = [f for f in findings_raw if _has_meaningful_data(f)]

    # Deduplicate by title+location — same vulnerability at the same location appears once
    seen_keys = set()
    deduped = []
    for f in findings_raw:
        raw_title = extract_title(f)
        raw_loc = extract_location(f)
        raw_evidence = f.get("evidence") or f.get("Raw") or ""
        key = f"{raw_title}|||{raw_loc}|||{raw_evidence[:100]}"
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)
    findings_raw = deduped

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    normalized = []
    for f in findings_raw:
        sev = normalize_severity(f.get("severity", "unknown"))
        vname, vid = extract_vuln_context(f)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        normalized.append({
            "title": extract_title(f),
            "severity": sev,
            "template_id": extract_template_id(f),
            "location": extract_location(f),
            "description": extract_description(f),
            "evidence": extract_evidence(f),
            "vulnerability_name": vname,
            "vulnerability_id": vid,
            "_raw": {k: str(v)[:500] for k, v in f.items() if k not in ("_raw",)},
        })

    # Fallback — ensure all 4 keys exist
    severity_counts = {"Critical": severity_counts.get("Critical", 0),
                       "High": severity_counts.get("High", 0),
                       "Medium": severity_counts.get("Medium", 0),
                       "Low": severity_counts.get("Low", 0)}

    if API_KEY:
        summary, ai_results = call_gemini(normalized, scan_type)
        # Save Gemini debug info if debug_path provided
        if debug_path:
            _gemini_debug = {"gemini_called": True, "gemini_api_key_set": bool(API_KEY),
                             "gemini_input_count": len(normalized),
                             "gemini_output_count": len(ai_results),
                             "gemini_error": summary if not ai_results else None,
                             "raw_findings_sent": [{k: str(v)[:200] for k, v in f.items()} for f in normalized]}
            try:
                Path(debug_path).write_text(json.dumps(_gemini_debug, indent=2))
            except Exception:
                pass
        # If Gemini returned an error string (not a list), treat as error and fall through to fallback
        if isinstance(ai_results, str):
            gemini_error = ai_results
            ai_results = []
        else:
            gemini_error = None

        # If Gemini failed or returned no results, fall back to local processing
        if gemini_error or not ai_results:
            summary, ai_results = build_fallback(normalized)
        findings = []
        for nf, ar in zip(normalized, ai_results):
            findings.append({
                "severity": nf["severity"],
                "title": (ar.get("title") or nf.get("title", "Security Finding") or "Security Finding")[:100],
                "impact": (ar.get("impact") or nf.get("description", "") or "No impact description available.")[:200],
                "fix": (ar.get("fix") or "Review the detected location and apply the standard fix for this vulnerability class.")[:200],
                "detail": build_detail(nf),
                "aiPrompt": (ar.get("aiPrompt") or build_ai_prompt(nf))[:4000],
                "template_id": nf.get("template_id", ""),
            })
    else:
        summary, ai_results = build_fallback(normalized)
        findings = []
        for nf, ar in zip(normalized, ai_results):
            findings.append({
                "severity": nf["severity"],
                "title": (ar.get("title") or nf.get("title", "Security Finding") or "Security Finding")[:100],
                "impact": (ar.get("impact") or nf.get("description", "") or "No impact description available.")[:200],
                "fix": (ar.get("fix") or "Review the detected location and apply the standard fix for this vulnerability class.")[:200],
                "detail": build_detail(nf),
                "aiPrompt": (ar.get("aiPrompt") or build_ai_prompt(nf))[:4000],
                "template_id": nf.get("template_id", ""),
            })

    return {
        "score": score,
        "duration_sec": duration,
        "summary": summary or "Scan complete.",
        "severityCounts": severity_counts,
        "findings": findings if findings is not None else [],
        "templatesExecuted": templates_exec or 0,
        "templatesFailed": templates_failed or 0,
        "totalFindings": len(findings) if findings else 0,
        "processedBy": "gemini" if API_KEY else "local",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _has_meaningful_data(f):
    """Filter out empty/phantom findings with no detector, no evidence, and no location."""
    if not isinstance(f, dict):
        return False
    # At least one of these must have real content
    has_title = bool(f.get("DetectorName") or f.get("name") or f.get("type") or f.get("check_id") or f.get("check_name"))
    has_evidence = bool(f.get("Raw") or f.get("evidence") or f.get("note") or f.get("detail") or f.get("description"))
    has_location = bool(f.get("file") or f.get("path") or f.get("file_path") or f.get("matched-at"))
    return (has_title and has_evidence) or (has_location and has_evidence)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_findings(raw, scan_type):
    """Pull findings, templates_executed, templates_failed from raw scan data."""
    findings = []
    templates = 0
    failed = 0

    # SAST format — check first since SAST has empty findings[] but real results in tool_results
    tr = raw.get("tool_results") or {}
    if tr:
        for tool, tres in tr.items():
            findings.extend(tres.get("findings", []))
        # Count tools from the raw response if available
        templates = raw.get("templates_executed", 0)
        failed = raw.get("templates_failed", 0)
        return findings, templates, failed

    # Nuclei format — findings directly under raw
    raw_findings = raw.get("findings", [])
    if raw_findings:
        findings = raw_findings
        so = raw.get("scan_output", {})
        sm = so.get("summary", {})
        templates = sm.get("templates_executed", 0)
        failed = 0
        for e in so.get("errors", []):
            if any(kw in e for kw in ("Could not", "failed", "i/o timeout")):
                failed += 1
        return findings, templates, failed

    # Fallback: breakdown-based (processed report)
    bd = raw.get("breakdown", {})
    if bd:
        findings = raw.get("findings", [])
        if findings:
            return findings, 0, 0

    return findings, templates, failed


def extract_title(finding):
    # Nuclei format
    if isinstance(finding.get("info"), dict):
        return finding["info"].get("name", "")
    # v6 custom scanner — name + category
    if finding.get("name") and finding.get("category"):
        return f"[{finding['category']}] {finding['name']}"
    # v2 scanner type field
    if finding.get("type") and finding.get("package"):
        return f"{finding['type']}: {finding.get('package', finding.get('file', ''))}"
    if finding.get("type"):
        return finding["type"]
    # Semgrep check_name
    if finding.get("check_name"):
        return finding["check_name"]
    # Trufflehog detector name
    if finding.get("DetectorName"):
        return f"{finding.get('DetectorName', '')}: {finding.get('Raw', '')[:60]}"
    # Fallback
    if finding.get("name"):
        return finding["name"]
    if finding.get("title"):
        return finding["title"]
    return "Unknown finding"


def extract_template_id(finding):
    tid = finding.get("template-id") or finding.get("check_id") or ""
    if tid:
        return tid
    # v2 scanner
    if finding.get("type"):
        return f"{finding['type']}: {finding.get('package', finding.get('file', ''))}"
    # v6 custom scanner
    if finding.get("name") and finding.get("category"):
        return f"{finding['category']}: {finding['name']}"
    # Trufflehog detector
    if finding.get("DetectorName"):
        return finding["DetectorName"]
    return ""


def extract_location(finding):
    # Nuclei
    if finding.get("matched-at"):
        return finding["matched-at"]
    # v6 scanner — file + line
    if finding.get("file"):
        line = finding.get("line", "")
        if line:
            return f"{finding['file']}:{line}"
        return finding["file"]
    # Checkov
    if finding.get("file_path"):
        line_range = finding.get("file_line_range", [])
        if line_range:
            return f"{finding['file_path']}:{line_range[0]}"
        return finding["file_path"]
    # Semgrep
    if finding.get("path"):
        s = finding.get("start", {})
        return f"{finding['path']}:{s.get('line', '?')}"
    # v2 scanner — package context
    if finding.get("package") and finding.get("ecosystem"):
        return f"{finding.get('ecosystem', '')}:{finding.get('package', '')}"
    # Evidence only
    if finding.get("evidence"):
        return finding["evidence"]
    return "unknown"


def extract_description(finding):
    # Nuclei
    if isinstance(finding.get("info"), dict):
        return finding["info"].get("description", "")
    # v6 scanner
    if finding.get("note"):
        return finding["note"]
    if finding.get("detail"):
        return finding["detail"]
    # Trufflehog
    if finding.get("Raw"):
        return finding["Raw"][:500]
    # Checkov
    if finding.get("guideline"):
        return finding["guideline"]
    # Semgrep message
    if isinstance(finding.get("extra"), dict) and finding["extra"].get("message"):
        return finding["extra"]["message"]
    return ""


def extract_evidence(finding):
    """Extract a snippet of evidence for the technical detail section."""
    # v6 scanner evidence
    if finding.get("evidence"):
        return finding["evidence"]
    # Nuclei request/response
    if finding.get("request"):
        return finding["request"][:500]
    # Trufflehog raw
    if finding.get("Raw"):
        return finding["Raw"][:500]
    # v2 scanner note/detail
    if finding.get("note"):
        return finding["note"]
    if finding.get("detail"):
        return finding["detail"]
    return ""


def extract_request(finding):
    req = finding.get("request") or finding.get("curl-command") or ""
    return req[:500] if req else ""


def extract_response(finding):
    resp = finding.get("response") or ""
    return resp[:500] if resp else ""


def build_detail(finding):
    parts = []
    if finding["description"]:
        parts.append(finding["description"])
    vname, vid = extract_vuln_context(finding)
    if vname:
        parts.append(f"Vulnerability Category: {vname} ({vid})")
    if finding["request"]:
        parts.append(f"Evidence Snippet:\n```\n{finding['request'][:500]}\n```")
    parts.append(f"Scanner Template: {finding['template_id']}")
    parts.append(f"Location: {finding['location']}")
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def normalize_severity(raw):
    s = str(raw).lower().strip()
    if s in ("critical", "crit"):
        return "Critical"
    if s in ("high", "error", "err"):
        return "High"
    if s in ("medium", "med", "warning", "warn"):
        return "Medium"
    return "Low"  # info/note/unknown all map to Low


def calculate_score(counts):
    penalty = 0
    for sev, weight in SEVERITY_WEIGHTS.items():
        penalty += counts.get(sev, 0) * weight
    return max(0, MAX_SCORE - penalty)


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

def call_gemini(findings, scan_type):
    if not findings:
        return "Scan completed successfully. No security issues were detected.", []

    if not API_KEY:
        return _gemini_error("GEMINI_API_KEY is not set. Set it as an environment variable on the Cloud Run service.")

    prompt = build_gemini_prompt(findings, scan_type)
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
    }).encode("utf-8")

    try:
        req = urlrequest.Request(f"{GEMINI_URL}?key={API_KEY}", data=body,
                                 headers={"Content-Type": "application/json"})
        with urlrequest.urlopen(req, timeout=60) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return _gemini_error(f"Gemini API HTTP error {e.code}: {error_body}")
    except URLError as e:
        return _gemini_error(f"Gemini API connection error: {e.reason}")
    except json.JSONDecodeError as e:
        return _gemini_error(f"Gemini returned invalid JSON: {e}")
    except OSError as e:
        return _gemini_error(f"Gemini request failed: {e}")

    # Parse candidates
    text = ""
    for candidate in raw.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            text += part.get("text", "")

    if not text:
        return _gemini_error(f"Gemini returned empty response. Raw keys: {list(raw.keys())}")

    return parse_gemini_response(text, findings)


def _gemini_error(msg):
    """Return a structured error with clear messaging — NOT silent fallback."""
    return msg, []


def build_gemini_prompt(findings, scan_type):
    ctx = "URL-based web application scan" if scan_type == "url" else "source code static analysis"
    flist = []
    for i, f in enumerate(findings, 1):
        raw_str = json.dumps(f.get("_raw", {}), indent=2)[:800]
        flist.append(
            f"FINDING #{i}:\n"
            f"  severity: {f['severity']}\n"
            f"  scanner_template: {f['template_id']}\n"
            f"  file_or_url: {f['location']}\n"
            f"  description: {f['description'][:300]}\n"
            f"  evidence_found: {f.get('evidence', '')[:200]}\n"
            f"  vulnerability_category: {f.get('vulnerability_name', 'unknown')} ({f.get('vulnerability_id', '')})\n"
            f"  raw_scanner_output: {raw_str}"
        )
    block = "\n\n---\n\n".join(flist)

    return f"""You are a senior application security engineer. You are given raw scanner findings and must produce a clean, structured security report for a developer dashboard.

Each finding below is the ACTUAL raw data from security scanners (Nuclei, Semgrep, TruffleHog, Checkov, or custom scanners). Your job is to interpret this raw data and generate human-readable, actionable information.

**Critically important:** The raw_scanner_output field contains the COMPLETE raw scanner finding — including file paths, line numbers, connection strings, API keys, URLs, HTTP response snippets, and package names. Use this data to write SPECIFIC titles, impacts, and fixes — not generic placeholders.

Example of what NOT to do:
  ❌ title: "Unknown"
  ❌ impact: "Detected by ."
  ❌ fix: "Review the detected location."

Example of what TO do:
  ✅ title: "Hardcoded Postgres credentials in docker-compose.yml line 5"
  ✅ impact: "The database password is committed in plain text. Anyone with access to the git repository can connect to the production database and steal or destroy user data."
  ✅ fix: "Replace the hardcoded username and password with environment variables. Add POSTGRES_USER and POSTGRES_PASSWORD to a .env file, add .env to .gitignore, and reference them in docker-compose.yml using ${POSTGRES_USER}:${POSTGRES_PASSWORD}."

For aiPrompt, write a COMPLETE self-contained markdown prompt that a developer can copy-paste into any AI coding assistant to get a detailed fix. Include:
- The vulnerability category and what it means
- The exact file and line where the issue was found
- The evidence snippet (mask sensitive parts with xxxx)
- 3-5 numbered, specific remediation steps
- A code example showing the correct implementation
- Prevention tips

RETURN ONLY VALID JSON — no markdown blocks, no explanatory text, just this object:

{{
  "score": <integer 0-100>,
  "summary": "<2-3 sentence summary including count and severity breakdown>",
  "findings": [
    {{
      "severity": "<Critical|High|Medium|Low>",
      "title": "<specific human-readable title, max 100 chars>",
      "impact": "<1-2 sentences on real-world attacker impact>",
      "fix": "<1-2 specific actionable sentences>",
      "aiPrompt": "<complete self-contained markdown prompt>"
    }}
  ]
}}

Score: Critical=-20, High=-10, Medium=-5, Low=-1. 100 = no issues.

FINDINGS:
{block}"""


def parse_gemini_response(text, original_findings):
    def extract_json(t):
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', t, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass
        return None

    data = extract_json(text)
    if not data:
        return build_fallback(original_findings)

    summary = data.get("summary", "Scan complete.")
    ai_findings = data.get("findings", [])

    result = []
    for i, orig in enumerate(original_findings):
        if i < len(ai_findings):
            result.append({
                "title": ai_findings[i].get("title", orig["title"]),
                "impact": ai_findings[i].get("impact", orig["description"][:200]),
                "fix": ai_findings[i].get("fix", "Review and fix."),
                "aiPrompt": ai_findings[i].get("aiPrompt", build_ai_prompt(orig)),
            })
        else:
            result.append({
                "title": orig["title"],
                "impact": orig["description"][:200],
                "fix": "Review the finding and apply appropriate remediation.",
                "aiPrompt": build_ai_prompt(orig),
            })

    return summary, result


# ---------------------------------------------------------------------------
# Fallback (no API key)
# ---------------------------------------------------------------------------

def build_fallback(findings):
    if not findings:
        return "Scan completed successfully. No security issues were detected.", []

    sc = {}
    for f in findings:
        sc[f["severity"]] = sc.get(f["severity"], 0) + 1
    parts = [f"{sc.get(s,0)} {s}" for s in ["Critical", "High", "Medium", "Low"] if sc.get(s, 0)]
    summary = f"{len(findings)} security issue(s) found: {', '.join(parts)}. Review each finding and use the AI fix prompts to resolve them quickly."

    results = []
    for f in findings:
        desc = f["description"][:200] or ""
        vname, vid = extract_vuln_context(f)
        impact_text = desc or (f"Detected by {f['template_id']}" if f["template_id"] else f"Security issue detected.")
        fix_text = f"Remove the hardcoded secret from {f['location'] or 'the source file'} and use environment variables or a secrets manager." if vname else "Review the detected location and apply the standard fix for this vulnerability class."
        results.append({
            "title": f["title"],
            "impact": impact_text,
            "fix": fix_text,
            "aiPrompt": build_ai_prompt(f),
        })
    return summary, results


def extract_vuln_context(finding):
    """Pull vulnerability name and ID if tagged."""
    if finding.get("vulnerability_name"):
        return finding["vulnerability_name"], finding.get("vulnerability_id", "")
    return "", ""


def build_ai_prompt(finding):
    sev = finding["severity"].upper()
    title = finding["title"]
    desc = finding["description"][:300] or "No description available."
    evidence = finding["evidence"][:300] or ""
    loc = finding["location"] or "unknown"
    vname, vid = extract_vuln_context(finding)
    template = finding["template_id"] or ""

    vuln_context = ""
    if vname and vid:
        vuln_context = (
            f"\n\n**Vulnerability Category:** {vname} ({vid})\n"
            f"This vulnerability falls under '{vname}' — credentials or secrets hardcoded in source code, "
            f"config files, or environment stubs that should be moved to environment variables or a secrets manager.\n"
        )

    evidence_block = ""
    if evidence:
        evidence_block = f"\n\n**Evidence found:**\n```\n{evidence}\n```\n"

    return (
        f"I need help fixing a {sev}-severity security issue in my application.\n\n"
        f"**Issue:** {title}\n"
        f"{vuln_context}"
        f"**Location:** {loc}\n"
        f"{evidence_block}"
        f"**Description:** {desc}\n\n"
        f"Please provide:\n"
        f"1. An explanation of the vulnerability and its impact\n"
        f"2. Step-by-step instructions to fix it\n"
        f"3. Code examples showing the fix\n"
        f"4. Any additional security best practices to prevent similar issues"
    )
    desc = finding["description"] or "No description available."
    loc = finding["location"]
    tid = finding["template_id"]
    vname, vid = extract_vuln_context(finding)

    vuln_line = ""
    if vname:
        vuln_line = f"**Vulnerability Category:** {vname} ({vid})\n\n"
        if "Baking Secrets" in vname:
            vuln_line += (
                "This vulnerability falls under 'Baking Secrets into Source' — "
                "credentials or secrets hardcoded in source code, config files, or environment stubs "
                "that should be moved to environment variables or a secrets manager.\n\n"
            )
        elif "Package Hallucination" in vname:
            vuln_line += (
                "This vulnerability falls under 'Package Hallucination' — "
                "a dependency that appears to be AI-generated or typosquatted, "
                "which may not actually exist in the official registry.\n\n"
            )
        elif "Client-Side" in vname:
            vuln_line += (
                "This vulnerability falls under 'Client-Side Security Misplacements' — "
                "security logic enforced only in the browser that must be moved to the server side.\n\n"
            )

    return (
        f"I need help fixing a {sev}-severity security issue in my application.\n\n"
        f"{vuln_line}"
        f"**Issue:** {title}\n\n"
        f"**Detected by:** {tid}\n\n"
        f"**Location:** {loc}\n\n"
        f"**Description:** {desc}\n\n"
        f"Please provide:\n"
        f"1. An explanation of the vulnerability and its impact\n"
        f"2. Step-by-step instructions to fix it\n"
        f"3. Code examples showing the fix\n"
        f"4. Any additional security best practices to prevent similar issues"
    )
