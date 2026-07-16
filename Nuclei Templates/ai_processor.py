"""
AI Report Processor — Gemini integration for scan result analysis.

POST /process-report
    Body: raw scan results (from nuclei or SAST)
    Returns: AIProcessedReport with score, summary, findings with aiPrompt

Requires GEMINI_API_KEY environment variable. If not set, returns
a best-effort non-AI processed report with basic severity normalization.
"""

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib import request as urlrequest
from urllib.error import URLError

API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 30,
    "medium": 10,
    "low": 3,
    "info": 1,
    "unknown": 0,
}

MAX_SCORE = 100


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def process_report(raw_results, scan_type="url"):
    """
    Takes raw scan results dict and returns AIProcessedReport.
    Falls back to non-AI processing if no API key is set.
    """
    findings, total_templates, templates_failed = extract_findings(raw_results, scan_type)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    normalized = []
    for f in findings:
        sev = normalize_severity(f.get("severity", "unknown"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        normalized.append({
            "title": extract_title(f),
            "severity": sev,
            "template_id": extract_template_id(f),
            "location": extract_location(f),
            "description": extract_description(f),
            "raw": f,
        })

    score = calculate_score(severity_counts)

    if API_KEY:
        summary, ai_prompts = call_gemini(normalized, scan_type)
    else:
        summary = build_fallback_summary(severity_counts, len(findings))
        ai_prompts = build_fallback_prompts(normalized)

    processed_findings = []
    for nf, prompt in zip(normalized, ai_prompts):
        processed_findings.append({
            "title": nf["title"],
            "severity": nf["severity"],
            "templateId": nf["template_id"],
            "location": nf["location"],
            "description": nf["description"],
            "aiPrompt": prompt,
        })

    return {
        "score": score,
        "summary": summary,
        "severityCounts": severity_counts,
        "findings": processed_findings,
        "templatesExecuted": total_templates,
        "templatesFailed": templates_failed,
        "totalFindings": len(findings),
        "processedBy": "gemini" if API_KEY else "local",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_findings(raw, scan_type):
    """Pull findings from different scanner response formats."""
    findings = []
    templates = 0
    failed = 0

    # Nuclei format
    findings_list = raw.get("findings") or []
    scan_output = raw.get("scan_output", {})

    # SAST format
    tool_results = raw.get("tool_results") or {}
    breakdown = raw.get("breakdown") or {}

    if scan_type == "url" or findings_list:
        findings = findings_list
        summary = scan_output.get("summary", {})
        templates = summary.get("templates_executed", 0)
        failed = 0
        # Count failed from errors
        for e in scan_output.get("errors", []):
            if "Could not" in e or "failed" in e:
                failed += 1

    elif tool_results:
        for tool_name, tr in tool_results.items():
            for f in tr.get("findings", []):
                if isinstance(f, dict):
                    findings.append(f)
        # SAST doesn't track template counts the same way
        templates = 0
        failed = 0

    elif breakdown:
        all_findings = []
        for vid, vdata in breakdown.items():
            all_findings.extend(raw.get("findings", []))
        findings = all_findings
        templates = 0
        failed = 0

    return findings, templates, failed


def extract_title(finding):
    if isinstance(finding.get("info"), dict):
        return finding["info"].get("name", "")
    if finding.get("check_name"):
        return finding["check_name"]
    if finding.get("name"):
        return finding["name"]
    return finding.get("template-id", "") or finding.get("type", "") or "Unknown"


def extract_template_id(finding):
    return (
        finding.get("template-id")
        or finding.get("templateID")
        or finding.get("check_id")
        or ""
    )


def extract_location(finding):
    if finding.get("matched-at"):
        return finding["matched-at"]
    if finding.get("file_path"):
        return f"{finding['file_path']}:{finding.get('file_line_range', [''])[0] if finding.get('file_line_range') else ''}"
    if finding.get("path"):
        start = finding.get("start", {})
        return f"{finding['path']}:{start.get('line', '?')}"
    if finding.get("file"):
        return f"{finding['file']}:{finding.get('line', '?')}"
    return "unknown"


def extract_description(finding):
    if isinstance(finding.get("info"), dict):
        return finding["info"].get("description", "")
    if finding.get("detail"):
        return finding["detail"]
    if finding.get("note"):
        return finding["note"]
    return finding.get("extra", {}).get("message", "") if isinstance(finding.get("extra"), dict) else ""


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def normalize_severity(raw):
    s = str(raw).lower().strip()
    if s in ("critical", "crit"):
        return "critical"
    if s in ("high", "error", "err"):
        return "high"
    if s in ("medium", "med", "warning", "warn"):
        return "medium"
    if s in ("low", "info", "note"):
        return "low"
    return "low"


def calculate_score(counts):
    penalty = 0
    for sev, weight in SEVERITY_WEIGHTS.items():
        penalty += counts.get(sev, 0) * weight
    return max(0, MAX_SCORE - penalty)


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

def call_gemini(findings, scan_type):
    """Send findings to Gemini, return (summary, ai_prompts_list)."""
    if not findings:
        return "No vulnerabilities found. The scan completed successfully with zero findings.", []

    prompt = build_gemini_prompt(findings, scan_type)

    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
    }).encode("utf-8")

    try:
        req = urlrequest.Request(
            f"{GEMINI_URL}?key={API_KEY}",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urlrequest.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError, OSError) as e:
        return build_fallback_summary(
            {f["severity"]: 0 for f in findings}, len(findings)
        ), build_fallback_prompts(findings)

    text = ""
    for candidate in raw.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            text += part.get("text", "")

    return parse_gemini_response(text, findings)


def build_gemini_prompt(findings, scan_type):
    ctx = "URL-based DAST scan" if scan_type == "url" else "Source code SAST analysis"
    findings_text = []
    for i, f in enumerate(findings, 1):
        findings_text.append(
            f"{i}. [{f['severity'].upper()}] {f['title']}\n"
            f"   Template: {f['template_id']}\n"
            f"   Location: {f['location']}\n"
            f"   Description: {f['description'][:500]}"
        )
    findings_block = "\n\n".join(findings_text)

    return f"""You are a senior security engineer analyzing results from a {ctx}.

Below are the findings. For each one, generate a structured remediation prompt that a developer can copy and give to their AI coding assistant to fix the issue. Each prompt must include:
1. A clear description of the vulnerability
2. Where exactly in the code/website the issue was detected
3. Specific step-by-step remediation instructions that an AI agent can follow

Also provide an overall security score from 0-100 (lower = more vulnerable) and a concise executive summary.

Return ONLY valid JSON with this exact structure:
{{
  "score": <int>,
  "summary": "<markdown summary paragraph>",
  "findings": [
    {{
      "aiPrompt": "### Vulnerability: <title>\\n\\n**Description:** ...\\n\\n**Location:** ...\\n\\n**Remediation Steps:**\\n1. ...\\n2. ...\\n\\n**Copy this prompt and paste it to your AI coding assistant to fix this issue.**"
    }}
  ]
}}

Findings:
{findings_block}"""


def parse_gemini_response(text, original_findings):
    try:
        data = json.loads(text)
        summary = data.get("summary", "Scan completed.")
        score = data.get("score", 0)
        ai_prompts = [f.get("aiPrompt", "") for f in data.get("findings", [])]
        # Pad if Gemini returned fewer prompts than findings
        while len(ai_prompts) < len(original_findings):
            ai_prompts.append(build_single_fallback_prompt(original_findings[len(ai_prompts)]))
        return summary, ai_prompts
    except (json.JSONDecodeError, KeyError):
        # Try to extract JSON from markdown
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                summary = data.get("summary", "Scan completed.")
                ai_prompts = [f.get("aiPrompt", "") for f in data.get("findings", [])]
                while len(ai_prompts) < len(original_findings):
                    ai_prompts.append(build_single_fallback_prompt(original_findings[len(ai_prompts)]))
                return summary, ai_prompts
            except (json.JSONDecodeError, KeyError):
                pass

    return build_fallback_summary(
        {f["severity"]: 0 for f in original_findings}, len(original_findings)
    ), build_fallback_prompts(original_findings)


# ---------------------------------------------------------------------------
# Fallback (no API key / Gemini fails)
# ---------------------------------------------------------------------------

def build_fallback_summary(severity_counts, total):
    if total == 0:
        return "Scan completed successfully with zero findings. No vulnerabilities were detected."
    parts = [f"{severity_counts[s]} {s}" for s in ["critical", "high", "medium", "low"] if severity_counts.get(s, 0)]
    return f"Scan completed. Detected {total} finding(s): {', '.join(parts)}."


def build_fallback_prompts(findings):
    return [build_single_fallback_prompt(f) for f in findings]


def build_single_fallback_prompt(finding):
    sev = finding["severity"].upper()
    title = finding["title"]
    loc = finding["location"]
    desc = finding["description"] or "No description available."
    tid = finding["template_id"]

    return (
        f"### {sev}: {title}\n\n"
        f"**Description:** {desc}\n\n"
        f"**Detected at:** {loc}\n"
        f"**Template:** {tid}\n\n"
        f"**Remediation:**\n"
        f"1. Review the detected location and understand the vulnerability context.\n"
        f"2. Apply the appropriate fix based on the vulnerability type.\n"
        f"3. Re-scan to verify the fix.\n\n"
        f"**Copy this prompt and share it with your AI coding assistant for detailed remediation guidance.**"
    )
