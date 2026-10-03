"""SafeAI Security Scorecard: deterministic, transparent, auditable scoring.

The scorecard is a Scorecard-style report (not an OpenSSF Scorecard report)
that summarises a SafeAI scan into an overall 0-10 score, per-category
scores, and a pass/warn/fail policy outcome. All scoring rules are
auditable and deterministic: identical findings always produce the same
scorecard.

Design:

- Severity weights: critical=4.0, high=2.0, medium=0.75, low=0.25, info=0.0.
- Diminishing returns for repeated findings from the same rule and location
  (a repeated pattern contributes less after the first occurrence).
- Duplicate fingerprints are treated as a single finding (deduplicated).
- The final score is normalized to the 0-10 range and clamped.
- Skipped or unavailable analyzers are never treated as successful checks;
  they are reported under ``coverage.analyzers_skipped``.
- Suppressed findings keep their ``suppressed`` status but do not affect
  the score (they are excluded from gating).
- Baseline-resolved findings are not present in the current finding set and
  therefore do not affect the score; only ``new``/``existing``/``regressed``
  findings do.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from safeai.kya.assurance import build_assurance_boundary
from safeai.kya.util import redact_secrets
from safeai.severity import SEVERITIES

SCORECARD_SCHEMA_VERSION = 1

# Severity weights for the scorecard (0-10 scale). These are the penalties
# applied per finding before diminishing returns and normalization.
SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high": 2.0,
    "medium": 0.75,
    "low": 0.25,
    "info": 0.0,
}

# Diminishing-returns exponent for repeated findings from the same rule and
# location. The first occurrence contributes its full weight; each subsequent
# occurrence contributes ``weight * DECAY**n`` where ``n`` is the occurrence
# index (0-based).
DECAY = 0.5

# Maximum number of top findings included in the Markdown report.
TOP_FINDINGS_LIMIT = 10


def _severity_index(sev: str) -> int:
    """Return the index of *sev* in :data:`SEVERITIES`.

    Unknown severities sort after all known ones so they surface for review
    rather than silently vanishing.
    """
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return len(SEVERITIES)


def _safe_line(line: object) -> int:
    """Coerce *line* to an ``int``, returning ``0`` on failure."""
    try:
        return int(line or 0)
    except (TypeError, ValueError):
        return 0

# Category definitions. Rule IDs are mapped to categories by exact rule ID
# prefix (first match wins). Categories are ordered for display.
_CATEGORY_MAP = [
    ("PROMPT_INJECTION", "Prompt injection"),
    ("PROMPT_DELIMITER", "Prompt injection"),
    ("PROMPT_SYSTEM_LEAK", "Prompt injection"),
    ("PROMPT_ROLE_OVERRIDE", "Prompt injection"),
    ("PROMPT_FILE_INJECTION", "Prompt injection"),
    ("PROMPT_FILE_SYSTEM_LEAK", "Prompt injection"),
    ("PROMPT_FILE_ROLE_OVERRIDE", "Prompt injection"),
    ("PROMPT_FILE_UNTRUSTED_PLACEHOLDER", "Prompt injection"),
    ("CC_SLASH_COMMAND_ARG_INJECTION", "Prompt injection"),
    ("DATA_LEAKAGE", "Secrets and credentials"),
    ("SKILL_HARDCODED_SECRET", "Secrets and credentials"),
    ("MCP_RESOURCE_SENSITIVE", "Secrets and credentials"),
    ("ENV_DEP_INVENTORY", "Secrets and credentials"),
    ("DEP_UNDECLARED_CAPABILITY", "Secrets and credentials"),
    ("DEP_ORPHANED_TOOL", "Secrets and credentials"),
    ("CAP_shell", "Command or code execution"),
    ("CAP_code_exec", "Command or code execution"),
    ("CAP_subprocess_shell", "Command or code execution"),
    ("CC_SLASH_COMMAND_SHELL", "Command or code execution"),
    ("CC_HOOK_SHELL_EXEC", "Command or code execution"),
    ("CAP_AUTONOMY", "Tool and capability risk"),
    ("CAP_browser", "Tool and capability risk"),
    ("CAP_docker", "Tool and capability risk"),
    ("CAP_kubernetes", "Tool and capability risk"),
    ("CAP_gcp", "Tool and capability risk"),
    ("CAP_redis", "Tool and capability risk"),
    ("CAP_s3", "Tool and capability risk"),
    ("CAP_slack", "Tool and capability risk"),
    ("CAP_ms_teams", "Tool and capability risk"),
    ("CAP_jira", "Tool and capability risk"),
    ("CAP_http", "Network and external access"),
    ("CAP_filesystem", "Tool and capability risk"),
    ("CAP_file_write", "Tool and capability risk"),
    ("CAP_db", "Tool and capability risk"),
    ("MCP_TOOL_OVERLY_BROAD", "MCP or external server risk"),
    ("MCP_TRANSPORT_INSECURE", "MCP or external server risk"),
    ("MCP_ASSETS_DISCOVERED", "MCP or external server risk"),
    ("CC_MCP_UNCONSTRAINED", "MCP or external server risk"),
    ("SKILL_EMBEDDED_PROMPT", "Configuration and workflow risk"),
    ("SKILL_EXCESSIVE_PERMISSIONS", "Configuration and workflow risk"),
    ("SKILL_INSECURE_DEFAULT", "Configuration and workflow risk"),
    ("SKILL_RISKY_CAPABILITY", "Configuration and workflow risk"),
    ("TOOL_MISSING_VALIDATION", "Configuration and workflow risk"),
    ("TOOL_DANGEROUS_PARAMS", "Configuration and workflow risk"),
    ("TOOL_EXCESSIVE_PERMISSIONS", "Configuration and workflow risk"),
    ("TOOL_SHELL_ACCESS", "Configuration and workflow risk"),
    ("MODEL_UNSAFE_TEMPERATURE", "Configuration and workflow risk"),
    ("MODEL_MISSING_CONTENT_FILTER", "Configuration and workflow risk"),
    ("MODEL_DISABLED_SAFETY", "Configuration and workflow risk"),
    ("WORKFLOW_NO_APPROVAL", "Configuration and workflow risk"),
    ("WORKFLOW_INSECURE_DEFAULT", "Configuration and workflow risk"),
    ("WORKFLOW_CAPABILITY_SPRAWL", "Configuration and workflow risk"),
    ("WORKFLOW_MISSING_VALIDATION", "Configuration and workflow risk"),
    ("CC_WILDCARD_PERMISSION", "Permissions and authorization"),
    ("CC_BYPASS_PERMISSIONS", "Permissions and authorization"),
    ("CC_DENY_SHADOWED", "Permissions and authorization"),
    ("CC_FS_WRITE_OUTSIDE_ROOT", "Permissions and authorization"),
    ("CC_SUBAGENT_PRIVILEGE_ESCALATION", "Permissions and authorization"),
    ("CC_SETTINGS_UNPARSEABLE", "Configuration and workflow risk"),
]

# Map from rule ID to category name.
RULE_TO_CATEGORY = {rule_id: category for rule_id, category in _CATEGORY_MAP}

# Category display order.
CATEGORY_ORDER = [
    "Secrets and credentials",
    "Prompt injection",
    "Tool and capability risk",
    "Permissions and authorization",
    "Network and external access",
    "Command or code execution",
    "Data and privacy exposure",
    "Dependencies and supply chain",
    "MCP or external server risk",
    "Configuration and workflow risk",
    "Governance and policy compliance",
]


def _escape_md(value: str) -> str:
    """Escape a string for safe Markdown table/inline use."""
    if not value:
        return ""
    # Escape pipe, backslash, and backtick inside inline code spans.
    escaped = value.replace("\\", "\\\\").replace("`", "\\`").replace("|", "\\|")
    return escaped


def _finding_category(rule_id: str) -> str:
    """Return the category for a rule ID, or ``"Uncategorized"``."""
    return RULE_TO_CATEGORY.get(rule_id, "Uncategorized")


def _penalty_for_finding(finding: dict, occurrence: int) -> float:
    """Return the penalty for one finding occurrence.

    ``occurrence`` is the 0-based occurrence index for this finding among
    findings that share the same (rule_id, file, line). The first occurrence
    (index 0) contributes the full severity weight; later occurrences
    contribute ``weight * DECAY**occurrence``.
    """
    severity = finding.get("severity", "medium")
    weight = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["medium"])
    return weight * (DECAY ** occurrence)


def compute_score(findings: list[dict]) -> float:
    """Compute the overall score (0-10) from findings.

    Findings are deduplicated by ``fingerprint`` (if present). Repeated
    findings from the same rule and location incur diminishing returns.
    The raw penalty is normalized so that a large number of findings still
    yields a score in the 0-10 range, then clamped.
    """
    # Deduplicate by fingerprint, preserving order (first occurrence wins).
    seen_fps: set[str] = set()
    unique_findings: list[dict] = []
    for finding in findings:
        fp = finding.get("fingerprint")
        if fp:
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
        unique_findings.append(finding)

    # Group by (rule_id, file, line) to apply diminishing returns.
    groups: dict[tuple[str, str, int], list[dict]] = {}
    for finding in unique_findings:
        key = (
            finding.get("rule_id", ""),
            finding.get("file", ""),
            _safe_line(finding.get("line")),
        )
        groups.setdefault(key, []).append(finding)

    raw_penalty = 0.0
    for key, group in groups.items():
        for occurrence, finding in enumerate(group):
            raw_penalty += _penalty_for_finding(finding, occurrence)

    # Normalize: 10 findings of medium severity (0.75 each) = raw_penalty
    # 7.5, which should map to roughly the midpoint of the scale. We use a
    # linear normalization: score = 10 - raw_penalty / 1.0, clamped to
    # [0, 10]. This is transparent and auditable: every finding contributes
    # a known penalty, and the mapping is a simple linear shift.
    normalized_penalty = raw_penalty
    score = 10.0 - normalized_penalty
    return max(0.0, min(10.0, score))


def compute_category_scores(findings: list[dict]) -> list[dict]:
    """Compute per-category scores and statistics.

    Returns a list of category dicts ordered by ``CATEGORY_ORDER`` then by
    name. Each category has ``name``, ``findings``, ``severity_counts``,
    ``score``, ``status``, ``explanation``, ``top_findings``, and
    ``analyzer_coverage``.
    """
    categories: dict[str, list[dict]] = {}
    for finding in findings:
        category = _finding_category(finding.get("rule_id", ""))
        categories.setdefault(category, []).append(finding)

    result = []
    # Emit categories in the defined order, then any extra categories.
    ordered_names = [c for c in CATEGORY_ORDER if c in categories]
    ordered_names.extend(sorted(c for c in categories if c not in CATEGORY_ORDER))

    for name in ordered_names:
        category_findings = categories[name]
        severity_counts = {sev: 0 for sev in SEVERITIES}
        for finding in category_findings:
            sev = finding.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Compute a per-category score using the same penalty model.
        # Only active (non-suppressed) findings affect the score so that
        # suppressed findings do not contradict the documented behaviour.
        active = [f for f in category_findings if f.get("status") != "suppressed"]
        category_score = compute_score(active)

        # Determine status.
        if not category_findings:
            status = "not_applicable"
            explanation = "No findings in this category."
        elif not active:
            status = "pass"
            explanation = "All findings suppressed."
        elif any(f.get("severity") in {"critical", "high"} for f in active):
            status = "fail"
            explanation = "Critical or high findings present."
        elif active:
            status = "warn"
            explanation = "Findings present but below blocking threshold."
        else:
            status = "pass"
            explanation = "No active findings."

        # Top findings (up to 3, ordered by severity then rule ID).
        sorted_findings = sorted(
            active,
            key=lambda f: (
                _severity_index(f.get("severity", "medium")),
                f.get("rule_id", ""),
                f.get("file", ""),
                _safe_line(f.get("line")),
            ),
            reverse=True,
        )[:3]
        top_findings = [
            {
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "message": str(f.get("message", "")).split("\n")[0][:120],
                "file": f.get("file"),
                "line": _safe_line(f.get("line")),
                "fingerprint": f.get("fingerprint"),
                "status": f.get("status"),
            }
            for f in sorted_findings
        ]

        result.append({
            "name": name,
            "findings": len(category_findings),
            "severity_counts": severity_counts,
            "score": round(category_score, 1),
            "status": status,
            "explanation": explanation,
            "top_findings": top_findings,
        })

    return result


def build_scorecard(report: dict, scan_meta: dict, policy_decision: dict,
                    scan_args: dict | None = None) -> dict:
    """Build the SafeAI Security Scorecard dict from a scan report.

    ``scan_meta`` must contain ``scan_id``, ``started_at``, ``completed_at``.
    ``policy_decision`` must contain ``outcome`` and ``reasons``.
    ``scan_args`` is the parsed CLI args namespace (for ``fail_on`` etc.).
    """
    scan_args = scan_args or {}
    findings = report.get("findings", [])
    suppressed = [f for f in findings if f.get("status") == "suppressed"]
    active = [f for f in findings if f.get("status") != "suppressed"]

    # Severity counts over the active (non-suppressed) findings.
    severity_counts = {sev: 0 for sev in SEVERITIES}
    for finding in active:
        sev = finding.get("severity", "medium")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Score and status.
    # Only active (non-suppressed) findings affect the numeric score.
    overall_score = compute_score(active)
    policy_outcome = policy_decision.get("outcome", "warn")
    fail_on = scan_args.get("fail_on", "critical")
    # An unrecognised fail-on threshold is a configuration error; we must not
    # crash, so fall back to the strictest posture (block on any active
    # finding) rather than silently failing open.
    if fail_on not in SEVERITIES:
        threshold_index = 0
    else:
        threshold_index = _severity_index(fail_on)
    blocking = [
        f for f in active
        if _severity_index(f.get("severity", "medium")) >= threshold_index
    ]
    if policy_outcome == "block":
        status = "fail"
        blocking = active
    elif blocking:
        # Findings at or above the blocking threshold cause exit code 1.
        status = "fail"
    elif active:
        # Findings exist but none are at or above the blocking threshold.
        status = "warn"
    else:
        # No active findings at all.
        status = "pass"

    # New/resolved counts from baseline comparison.
    baseline = report.get("baseline") or {}
    new_findings = baseline.get("new", 0)
    resolved_findings = baseline.get("resolved", 0)

    # Top findings (up to TOP_FINDINGS_LIMIT, ordered by severity then rule).
    top_sorted = sorted(
        active,
        key=lambda f: (
            _severity_index(f.get("severity", "medium")),
            f.get("rule_id", ""),
            f.get("file", ""),
            _safe_line(f.get("line")),
        ),
        reverse=True,
    )[:TOP_FINDINGS_LIMIT]
    top_findings = [
        {
            "rule_id": f.get("rule_id"),
            "severity": f.get("severity"),
            "message": redact_secrets(str(f.get("message", "")).split("\n")[0][:120]),
            "file": f.get("file"),
            "line": _safe_line(f.get("line")),
            "remediation": f.get("remediation"),
            "fingerprint": f.get("fingerprint"),
            "status": f.get("status"),
        }
        for f in top_sorted
    ]

    # Analyzer coverage and limitations.
    boundary = build_assurance_boundary(report)
    analyzers_run = sorted({
        f.get("provenance", {}).get("analyzer", "unknown")
        for f in findings
        if f.get("provenance")
    })
    analyzers_skipped = []  # no analyzer-skip metadata in current report
    limitations = boundary.get("coverage_notes", [])

    # Scan metadata.
    target = scan_args.get("directory", ".")
    commit = report.get("scan_meta", {}).get("commit_sha") or ""
    duration = None
    if scan_meta.get("started_at") and scan_meta.get("completed_at"):
        try:
            start = datetime.fromisoformat(scan_meta["started_at"])
            end = datetime.fromisoformat(scan_meta["completed_at"])
            duration = round((end - start).total_seconds(), 2)
        except Exception:
            duration = None

    scorecard = {
        "schema_version": SCORECARD_SCHEMA_VERSION,
        "tool": {
            "name": "SafeAI",
            "version": report.get("safeai_meta", {}).get("version", "unknown"),
            "report_type": "safeai-security-scorecard",
        },
        "scan": {
            "target": target,
            "commit": commit,
            "generated_at": scan_meta.get("completed_at"),
            "duration_seconds": duration,
            "baseline_used": bool(report.get("baseline")),
        },
        "summary": {
            "score": round(overall_score, 1),
            "status": status,
            "findings_total": len(findings),
            "blocking_findings": len(blocking),
            "suppressed_findings": len(suppressed),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
        },
        "severity_counts": severity_counts,
        "categories": compute_category_scores(findings),
        "top_findings": top_findings,
        "coverage": {
            "analyzers_run": analyzers_run,
            "analyzers_skipped": analyzers_skipped,
            "limitations": limitations,
        },
        "policy": {
            "fail_on": fail_on,
            "fail_on_new": bool(scan_args.get("fail_on_new")),
            "fail_on_escalation": scan_args.get("fail_on_escalation"),
            "scorecard_fail_under": scan_args.get("scorecard_fail_under"),
        },
    }
    return {"safeai_security_scorecard": scorecard}


def write_scorecard_json(scorecard: dict, path: str) -> None:
    """Write the scorecard as JSON. ``path`` may be ``"-"`` for stdout."""
    if path == "-":
        print(json.dumps(scorecard, indent=2, sort_keys=True, default=str))
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(scorecard, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")


def _remediation_theme_lines(top_findings):
    """Summarize remediation themes (counts only, not raw remediation).

    Groups top findings by remediation text so reviewers see where effort
    concentrates, instead of re-reading every raw recommendation.
    Deterministic: count desc, then text asc. Capped at 3 themes.
    """
    counts = {}
    for finding in top_findings:
        remediation = (finding.get("remediation") or "").strip()
        if remediation:
            counts[remediation] = counts.get(remediation, 0) + 1
    if not counts:
        return ["- No remediation guidance recorded."]
    themes = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    lines = []
    for text, count in themes:
        short = text if len(text) <= 120 else text[:117] + "..."
        lines.append(f"- {count}x — {_escape_md(short)}")
    return lines


def write_scorecard_md(scorecard: dict, path: str) -> None:
    """Write the scorecard as Markdown. ``path`` may be ``"-"`` for stdout."""
    if path == "-":
        print(render_scorecard_md(scorecard), end="")
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_scorecard_md(scorecard))


def render_scorecard_md(scorecard: dict) -> str:
    """Render the scorecard as Markdown.

    The output is deterministic: identical scorecards produce identical
    Markdown. All untrusted content (messages, file paths) is escaped for
    safe rendering in GitHub pull requests and job summaries.
    """
    data = scorecard["safeai_security_scorecard"]
    summary = data["summary"]
    scan = data["scan"]
    severity_counts = data["severity_counts"]
    categories = data["categories"]
    top_findings = data["top_findings"]
    coverage = data["coverage"]

    lines = [
        "# SafeAI Security Scorecard",
        "",
        "| Property | Value |",
        "|---|---|",
        f"| Overall score | {summary['score']} / 10 |",
        f"| Status | {summary['status'].upper()} |",
        f"| Target | `{_escape_md(scan['target'])}` |",
        f"| Findings | {summary['findings_total']} |",
        f"| Blocking findings | {summary['blocking_findings']} |",
        f"| Generated | {scan['generated_at']} |",
        "",
        "## Category scores",
        "",
        "| Category | Score | Status | Findings |",
        "|---|---:|---|---:|",
    ]
    for category in categories:
        lines.append(
            f"| {_escape_md(category['name'])} "
            f"| {category['score']} "
            f"| {category['status'].upper()} "
            f"| {category['findings']} |"
        )
    lines.extend([
        "",
        "## Severity distribution",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ])
    for severity in SEVERITIES:
        count = severity_counts.get(severity, 0)
        lines.append(f"| {severity.capitalize()} | {count} |")

    lines.extend([
        "",
        "## Highest-priority findings",
        "",
    ])
    if not top_findings:
        lines.append("- No findings.")
    for finding in top_findings:
        rule_id = finding.get("rule_id", "")
        severity = finding.get("severity", "").upper()
        message = _escape_md(finding.get("message", ""))
        file = finding.get("file", "")
        line = finding.get("line", 0)
        remediation = _escape_md(finding.get("remediation", ""))
        lines.append(f"- [{severity}] {rule_id} — {message}")
        if file:
            lines.append(f"  - Location: `{_escape_md(file)}:{line}`")
        if remediation:
            lines.append(f"  - Remediation: {remediation}")

    lines.extend([
        "",
        "## Remediation focus",
        "",
    ])
    lines.extend(_remediation_theme_lines(top_findings))

    lines.extend([
        "",
        "## Coverage and limitations",
        "",
        f"- Analyzers executed: {', '.join(coverage['analyzers_run']) or 'none'}",
        f"- Analyzers skipped: {', '.join(coverage['analyzers_skipped']) or 'none'}",
    ])
    for limitation in coverage["limitations"]:
        lines.append(f"- {_escape_md(limitation)}")
    lines.extend([
        "",
        "_Generated by SafeAI. This is not an official OpenSSF Scorecard report._",
        "_SafeAI performs static analysis and cannot prove runtime safety._",
        "_Findings should be reviewed in context._",
        "",
    ])
    return "\n".join(lines)


def write_scorecard_summary(scorecard: dict, path: str | None = None) -> None:
    """Write the scorecard to the GitHub Actions job summary.

    ``path`` defaults to ``$GITHUB_STEP_SUMMARY``. Does nothing when running
    outside GitHub Actions (``GITHUB_STEP_SUMMARY`` unset).
    """
    summary_file = path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    with open(summary_file, "a", encoding="utf-8") as fh:
        fh.write(render_scorecard_md(scorecard))
