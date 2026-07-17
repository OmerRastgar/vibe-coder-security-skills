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
from urllib.error import URLError

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

def process_report(raw_results, scan_type="url"):
    """
    Takes raw scan results dict and returns AIProcessedReport.
    """
    findings_raw, templates_exec, templates_failed = extract_findings(raw_results, scan_type)
    duration = raw_results.get("duration_sec", 0)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    normalized = []
    for f in findings_raw:
        sev = normalize_severity(f.get("severity", "unknown"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        normalized.append({
            "title": extract_title(f),
            "severity": sev,
            "template_id": extract_template_id(f),
            "location": extract_location(f),
            "description": extract_description(f),
            "request": extract_request(f),
            "response": extract_response(f),
        })

    score = calculate_score(severity_counts)

    if API_KEY:
        summary, ai_results = call_gemini(normalized, scan_type)
    else:
        summary, ai_results = build_fallback(normalized)

    findings = []
    for nf, ar in zip(normalized, ai_results):
        findings.append({
            "severity": nf["severity"],
            "title": ar.get("title", nf["title"]),
            "impact": ar.get("impact", nf["description"][:200]),
            "fix": ar.get("fix", "Review the detected location and apply the appropriate fix."),
            "detail": build_detail(nf),
            "aiPrompt": ar.get("aiPrompt", build_ai_prompt(nf)),
            "template_id": nf["template_id"],
        })

    return {
        "score": score,
        "duration_sec": duration,
        "summary": summary,
        "severityCounts": severity_counts,
        "findings": findings,
        "templatesExecuted": templates_exec,
        "templatesFailed": templates_failed,
        "totalFindings": len(findings),
        "processedBy": "gemini" if API_KEY else "local",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


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
        return findings, 0, 0

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
    # SAST - semgrep check_name
    if finding.get("check_name"):
        return finding["check_name"]
    # SAST - v2 scanner type field
    if finding.get("type"):
        return f"{finding['type']}: {finding.get('package', finding.get('file', ''))}"
    # SAST - trufflehog
    if finding.get("DetectorName"):
        return f"{finding.get('DetectorName', '')}: {finding.get('Raw', '')[:60]}"
    return finding.get("name") or finding.get("template-id", "") or finding.get("title", "") or "Unknown finding"


def extract_template_id(finding):
    return finding.get("template-id") or finding.get("check_id") or finding.get("type", "")


def extract_location(finding):
    # Nuclei
    if finding.get("matched-at"):
        return finding["matched-at"]
    # SAST file-based
    if finding.get("file"):
        line = finding.get("line", "")
        return f"{finding['file']}:{line}" if line else finding["file"]
    if finding.get("file_path"):
        return finding["file_path"]
    if finding.get("path"):
        s = finding.get("start", {})
        return f"{finding['path']}:{s.get('line', '?')}"
    # SAST package-based
    if finding.get("package") and finding.get("ecosystem"):
        return f"{finding.get('ecosystem', '')}:{finding.get('package', '')}"
    return "unknown"


def extract_description(finding):
    # Nuclei
    if isinstance(finding.get("info"), dict):
        return finding["info"].get("description", "")
    # SAST detail/note
    if finding.get("detail"):
        return finding["detail"]
    if finding.get("note"):
        return finding["note"]
    if finding.get("Raw"):
        return finding["Raw"][:300]
    # Checkov
    if finding.get("guideline"):
        return finding["guideline"]
    # Semgrep message
    if isinstance(finding.get("extra"), dict) and finding["extra"].get("message"):
        return finding["extra"]["message"]
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
    if finding["request"]:
        parts.append(f"Request:\n```\n{finding['request']}\n```")
    if finding["response"]:
        parts.append(f"Response:\n```\n{finding['response']}\n```")
    parts.append(f"Template: {finding['template_id']}")
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
    if s in ("low", "info", "note"):
        return "Low"
    return "Low"


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

    prompt = build_gemini_prompt(findings, scan_type)
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
    }).encode("utf-8")

    try:
        req = urlrequest.Request(f"{GEMINI_URL}?key={API_KEY}", data=body,
                                 headers={"Content-Type": "application/json"})
        with urlrequest.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError, OSError):
        return build_fallback(findings)

    text = ""
    for candidate in raw.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            text += part.get("text", "")

    return parse_gemini_response(text, findings)


def build_gemini_prompt(findings, scan_type):
    ctx = "URL-based web application scan" if scan_type == "url" else "source code static analysis"
    flist = []
    for i, f in enumerate(findings, 1):
        flist.append(
            f"{i}. [{f['severity'].upper()}] {f['title']}\n"
            f"   Template: {f['template_id']}\n"
            f"   Location: {f['location']}\n"
            f"   Description: {f['description'][:300]}"
        )
    block = "\n\n".join(flist)

    return f"""You are a senior application security engineer. Analyze the following {ctx} findings and produce a structured report.

Return ONLY valid JSON with this exact shape:
{{
  "score": <0-100>,
  "summary": "<2-sentence executive summary>",
  "findings": [
    {{
      "title": "<human readable title, max 60 chars>",
      "impact": "<1-2 sentences on what an attacker could do>",
      "fix": "<1-2 sentences on how to fix it>",
      "aiPrompt": "<detailed markdown remediation prompt for an AI coding assistant>"
    }}
  ]
}}

The aiPrompt must be a self-contained markdown block the user can copy to any AI tool:
- Start with "I need help fixing a {severity}-severity security issue in my application."
- Include the template ID, affected URL/file, and what the scanner detected.
- Ask for: explanation of the risk, step-by-step fix instructions, code examples, and prevention tips.

Score formula: 100 minus (Critical * 20) minus (High * 10) minus (Medium * 5) minus (Low * 1).

Findings:
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
        results.append({
            "title": f["title"],
            "impact": f["description"][:200] or f"Detected by {f['template_id']}.",
            "fix": "Review the detected location and apply the standard fix for this vulnerability class.",
            "aiPrompt": build_ai_prompt(f),
        })
    return summary, results


def build_ai_prompt(finding):
    sev = finding["severity"].upper()
    title = finding["title"]
    desc = finding["description"] or "No description available."
    loc = finding["location"]
    tid = finding["template_id"]

    return (
        f"I need help fixing a {sev}-severity security issue in my application.\n\n"
        f"**Issue:** {title}\n\n"
        f"**Detected by:** {tid}\n\n"
        f"**Location:** {loc}\n\n"
        f"**Description:** {desc}\n\n"
        f"Please provide:\n"
        f"1. An explanation of the vulnerability and its impact\n"
        f"2. Step-by-step instructions to fix it\n"
        f"3. Code examples showing the fix\n"
        f"4. Any additional security best practices to prevent similar issues\n\n"
        f"**Technical detail:**\n"
        f"```\n{finding.get('request', finding.get('location', ''))}\n```"
    )
