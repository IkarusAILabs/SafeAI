"""Pull-request comment renderer.

A reviewer has seconds, not minutes. This renderer exists to answer one
question at a glance: **did a named tool or MCP server acquire new
authority in this change?** Everything that does not serve that question
is left out — no inventory tables, no severity legends, no "0 findings"
banners, no unchanged surface.

Design constraints, all enforced by tests:

* The stable marker ``<!-- safeai:pr-comment:v1 -->`` is always the first
  line, so CI can update one comment in place instead of posting a new
  one on every push.
* Blocks are grouped **by tool**, ordered by severity. Rules are detail,
  tools are the subject.
* A typical change renders in under 20 lines; the hard cap is 60, after
  which the body is truncated with a pointer to the full report.
* Deterministic: no timestamps, no run IDs, no durations, no elapsed
  times. Two runs on the same report are byte-identical.
* Nothing is posted anywhere. This module returns a string.
"""

import re
import sys

from safeai.analysis.tool_identity import display_name
from safeai.kya.assurance import BOUNDARY_SENTENCE
from safeai.severity import ESCALATION_SEVERITIES

#: Mentions that would notify a user or team if left raw in a PR comment.
_AT_HANDLE = re.compile(
    r"@([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38}[A-Za-z0-9])?)?)"
)

#: Markdown inline links in attacker-controlled paths/messages.
_MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")


def sanitize_pr_text(value):
    """Neutralize markdown that could break or weaponize a PR comment.

    Finding messages, file paths, data-flow evidence, and remediation
    text all originate in the scanned diff. A crafted branch can put
    backticks, fences, HTML comments, ``@mentions``, or ``[x](url)``
    links into those fields. This helper:

    * collapses newlines so injection cannot inflate the 60-line cap
    * replaces backticks (so fences and inline-code breakouts die)
    * breaks HTML comment delimiters
    * strips the leading ``@`` from GitHub-style handles
    * renders markdown links as plain ``label (url)`` text
    * drops C0 control characters (terminal escapes, null bytes)
    """
    text = str(value or "")
    text = "".join(ch for ch in text
                   if ch in (chr(10), chr(13))
                   or (32 <= ord(ch) != 127))
    text = text.replace(chr(13) + chr(10), chr(10)).replace(chr(13), chr(10))
    text = " ".join(part.strip() for part in text.split(chr(10)))
    text = text.replace("`", "'")
    text = text.replace("<!--", "< !--").replace("-->", "-- >")
    text = _AT_HANDLE.sub(r"\1", text)
    text = _MD_LINK.sub(r"\1 (\2)", text)
    return text


#: CI keys on this to find its own previous comment.
MARKER = "<!-- safeai:pr-comment:v1 -->"

#: Hard ceiling on rendered lines, including marker and footer.
MAX_LINES = 60

#: Target for a typical change. Not enforced, but the layout is tuned
#: so that a two-escalation report lands well inside it.
TARGET_LINES = 20

_SEVERITY_ORDER = {sev: i for i, sev in enumerate(reversed(ESCALATION_SEVERITIES))}

#: Severity marks. Text, not colour: PR comments render on many themes.
_SEVERITY_MARK = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

_FOOTER = f"_{BOUNDARY_SENTENCE}_"

#: Escalations below this severity are not worth a reviewer's attention
#: in the summary block; they remain in the full report.
_MIN_SEVERITY = "medium"


def _severity_rank(severity):
    return _SEVERITY_ORDER.get(str(severity or "low").lower(), 99)


def _plural(count, singular, plural=None):
    return singular if count == 1 else (plural or singular + "s")


def _evidence_label(evidence):
    """Render the first evidence location as ``path:line``.

    Only a path and a line number are emitted — never source text.
    """
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        path = sanitize_pr_text(item.get("path"))
        if not path:
            continue
        line = item.get("line")
        return f"`{path}:{line}`" if line else f"`{path}`"
    return None


def _tool_blocks(diff):
    """Return one renderable block per tool that escalated, worst first."""
    blocks = []
    entries = list(diff.get("tools") or [])
    unattributed = diff.get("unattributed")
    if isinstance(unattributed, dict) and unattributed.get("escalations"):
        entries.append(unattributed)

    for entry in entries:
        escalations = [
            e for e in (entry.get("escalations") or [])
            if _severity_rank(e.get("severity")) <= _severity_rank(_MIN_SEVERITY)
        ]
        if not escalations:
            continue
        escalations = sorted(
            escalations,
            key=lambda e: (_severity_rank(e.get("severity")), str(e.get("id"))),
        )
        worst = escalations[0]
        blocks.append({
            "tool_key": entry.get("tool_key"),
            "label": display_name(entry.get("tool") or {}) or entry.get("tool_key"),
            "status": entry.get("status"),
            "access": entry.get("access_summary") or {},
            "access_changes": entry.get("access_mode_changes") or [],
            "severity": worst.get("severity"),
            "escalations": escalations,
        })

    return sorted(
        blocks,
        key=lambda b: (_severity_rank(b["severity"]), str(b["tool_key"])),
    )


def _access_phrase(block):
    """Short 'read → mutate' or 'new' phrase for the block heading.

    The tool-wide summary is the *maximum* mode across every capability,
    so it can stay flat while a specific capability escalates — an MCP
    server that already spawned a process still reads at ``execute``
    after its tools go from read-only to mutating. When that happens the
    capability-level change is the honest thing to show.
    """
    access = block["access"]
    before = access.get("before") if isinstance(access, dict) else None
    after = access.get("after") if isinstance(access, dict) else None
    if before and after and before != after:
        return f"{before} → {after}"
    if before and after and before == after:
        for change in block.get("access_changes") or []:
            change_before = change.get("before")
            change_after = change.get("after")
            if change_before and change_after and change_before != change_after:
                return f"{change.get('capability')}: {change_before} → {change_after}"
    if block["status"] == "new" and after:
        return f"new · {after}"
    if after:
        return str(after)
    return str(block["status"] or "changed")


def _recommended_action(escalation):
    """One concise action for critical/high escalations (else None).

    Tolerates escalations without remediation (old reports, hand-built
    fixtures): those render exactly as before.
    """
    if str(escalation.get("severity", "")).lower() not in ("critical", "high"):
        return None
    remediation = escalation.get("remediation") or {}
    actions = remediation.get("recommended_actions") or []
    if not actions:
        summary = sanitize_pr_text(remediation.get("summary") or "").strip()
        return summary or None
    return sanitize_pr_text(actions[0]).strip() or None


def _render_block(block):
    """Two lines per tool: what it is, then why it matters."""
    mark = _SEVERITY_MARK.get(block["severity"], block["severity"])
    lines = [f"**`{sanitize_pr_text(block['tool_key'])}`** — {_access_phrase(block)}  ⚠️ {mark}"]
    primary = block["escalations"][0]
    detail = sanitize_pr_text(primary.get("summary") or primary.get("id") or "").strip()
    evidence = _evidence_label(primary.get("evidence"))
    extra = len(block["escalations"]) - 1
    parts = [detail] if detail else []
    if evidence:
        parts.append(evidence)
    if extra > 0:
        parts.append(f"+{extra} more {_plural(extra, 'escalation')}")
    if parts:
        lines.append("  " + " · ".join(parts))
    action = _recommended_action(primary)
    if action:
        lines.append(f"  → {action}")
    lines.append("")
    return lines


def _first_scan_summary(report):
    """Rendered when there is no baseline: state facts, never a fake diff."""
    surface = report.get("tool_surface") or []
    agents = report.get("kya_agents") or report.get("agent_models") or []
    capabilities = []
    for entry in surface:
        for capability in entry.get("capabilities") or []:
            mode = capability.get("access_mode")
            if mode in {"execute", "mutate", "write"}:
                capabilities.append((capability.get("name"), mode, entry.get("tool_key")))
    capabilities = sorted(set(capabilities))[:3]

    scope = (
        f"{len(agents)} {_plural(len(agents), 'agent')} · "
        f"{len(surface)} {_plural(len(surface), 'tool')} in scope. "
        "No prior baseline, so no capability change can be shown yet."
    )
    lines = ["### SafeAI — first scan, establishing a baseline", "", scope]
    if capabilities:
        lines.append("")
        lines.append("Highest-authority capabilities found:")
        for name, mode, tool_key in capabilities:
            lines.append(
                f"- `{sanitize_pr_text(tool_key)}` — {sanitize_pr_text(name)} ({mode})"
            )
    return lines


def _dataflow_paths(report, budget=7):
    """Newly reachable source→sink paths as compact Markdown lines.

    Only new/regressed ``DATAFLOW_*`` findings (baseline mode) surface
    here, alongside escalations. Paths are single-file heuristics — the
    heading says so. Returns at most ``budget`` lines including the
    heading and a ``+N more`` overflow line.
    """
    ranked = []
    for finding in report.get("findings") or []:
        rule_id = str(finding.get("rule_id") or "")
        if not rule_id.startswith("DATAFLOW_"):
            continue
        if finding.get("status") not in ("new", "regressed"):
            continue
        sink = rule_id[len("DATAFLOW_"):]
        evidence = sanitize_pr_text(finding.get("evidence") or "")
        source = ""
        if "->" in evidence:
            source = evidence.split("->")[0].replace("source:", "").strip()
        label = sanitize_pr_text(f"{source} → {sink}" if source else sink)
        where = sanitize_pr_text(f"{finding.get('file')}:{finding.get('line')}")
        ranked.append((_severity_rank(finding.get("severity")), label, where))

    if not ranked:
        return []
    ranked.sort(key=lambda item: (item[0], item[1], item[2]))

    lines = ["**New data-flow paths** (heuristic, single-file — not verified):", ""]
    shown = ranked[: max(0, budget - 3)]
    for _, label, where in shown:
        lines.append(f"- `{label}` in `{where}`")
    hidden = len(ranked) - len(shown)
    if hidden > 0:
        lines.append(f"- +{hidden} more {_plural(hidden, 'path')}")
    return lines[:budget]


def _iac_authority(report, budget=9):
    """IaC authority correlation verdicts as concise review-only lines.

    Lane B by construction (ADR-0008): verdicts inform human review and
    never gate. Only raw IaC evidence refs are shown — never arbitrary
    IaC content — and every interpolated value passes through
    ``sanitize_pr_text``. Returns at most ``budget`` lines including the
    heading and overflow line. Empty when the scan carries no verdicts.
    """
    iac = report.get("iac_correlations") or {}
    verdicts = [v for v in iac.get("verdicts") or [] if isinstance(v, dict)]
    if not verdicts:
        return []
    order = {"EXCESS_AUTHORITY": 0, "AUTHORITY_MISMATCH": 1,
             "UNVERIFIED_LINK": 2, "MATCH": 3, "UNKNOWN": 4}
    grants = iac.get("grants") or []
    ranked = sorted(
        verdicts,
        key=lambda v: (order.get(str(v.get("verdict")), 5),
                       str(v.get("domain") or "")),
    )
    lines = [("**Infrastructure authority** (Lane B / review-only — "
              "IaC evidence, never a gate):"), ""]
    shown = ranked[: max(0, (budget - 3) // 3)]
    for item in shown:
        label = sanitize_pr_text(str(item.get("verdict") or "UNKNOWN"))
        domain = sanitize_pr_text(str(item.get("domain") or "unknown"))
        identity = item.get("identity_ref") or {}
        who = sanitize_pr_text(str(identity.get("name") or "repository"))
        lines.append(f"{label}   {domain} — {who}")
        detail = _iac_verdict_detail(item, grants)
        if detail:
            lines.append(f"  {detail}")
        refs = item.get("grant_evidence_refs") or []
        where = sanitize_pr_text(refs[0]) if refs else "repo IaC"
        lines.append(f"  Evidence: `{where}`")
    hidden = len(ranked) - len(shown)
    if hidden > 0:
        lines.append(f"- +{hidden} more {_plural(hidden, 'verdict')}")
    return lines[:budget]


def _iac_verdict_detail(item, grants):
    """One-line authority substance for a verdict (sanitized)."""
    refs = set(item.get("grant_evidence_refs") or [])
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        ref = f"{grant.get('source_file')}:{grant.get('line', 0)}"
        if ref not in refs:
            continue
        actions = grant.get("actions") or {}
        resources = grant.get("resources") or {}
        first_action = (actions.get("values") or ["?"])[0]
        first_resource = (resources.get("values") or ["?"])[0]
        return sanitize_pr_text(f"{first_action} -> {first_resource}")
    reason = str(item.get("reason") or "")
    return sanitize_pr_text(reason.split(".")[0]) if reason else ""


def _review_questions(report, budget=7):
    """Lane-B policy matches as reviewer questions (never CI gates).

    Returns at most ``budget`` lines including the heading and overflow
    line. Empty when no Lane-B matches exist.
    """
    seen = []
    decision = report.get("policy_decision") or {}
    for match in decision.get("matches") or []:
        if match.get("lane") != "B":
            continue
        seen.append((sanitize_pr_text(match.get("policy_id") or "review"),
                     sanitize_pr_text(match.get("message") or "requires human review")))
    if not seen:
        return []
    lines = ["**Human review** (questions for a reviewer — not CI gates):", ""]
    for policy_id, message in seen[: max(0, budget - 3)]:
        lines.append(f"- ? [{policy_id}] {message}")
    hidden = len(seen) - len(lines) + 2
    if hidden > 0:
        lines.append(f"- +{hidden} more {_plural(hidden, 'question')}")
    return lines[:budget]


def _details_line(report, diff, shown):
    """One collapsed line of context. Never expands the reviewer's work."""
    counts = diff.get("counts") or {}
    bits = []
    policy = report.get("policy_decision") or {}
    outcome = policy.get("outcome")
    if outcome:
        bits.append(f"Policy: {outcome}")
    unchanged = counts.get("tools_unchanged")
    if unchanged:
        bits.append(f"{unchanged} unchanged {_plural(unchanged, 'tool')}")
    removed = counts.get("tools_removed")
    if removed:
        bits.append(f"{removed} removed {_plural(removed, 'tool')}")
    if not diff.get("baseline_tool_attribution", True):
        bits.append("baseline predates tool attribution")
    if not bits:
        return []
    return [f"<sub>{' · '.join(bits)} · {shown} shown</sub>", ""]


def _footer(report):
    """One-line assurance boundary, with the scan's real inference count.

    The generic sentence alone is easy to skim past. Naming how many
    values in *this* scan were inferred keeps the caveat specific.
    """
    boundary = report.get("assurance_boundary") or {}
    sentence = str(boundary.get("summary") or BOUNDARY_SENTENCE)
    inferred = boundary.get("inferred_value_count") or 0
    if inferred:
        sentence += (
            f" {inferred} access mode{'' if inferred == 1 else 's'} in this scan "
            "were inferred rather than declared."
        )
    return f"_{sentence}_"


def _truncate(lines, total_blocks, shown_blocks):
    """Enforce the hard line cap, leaving room for the notice and footer."""
    remaining = total_blocks - shown_blocks
    if len(lines) + 2 <= MAX_LINES and remaining <= 0:
        return lines
    # Budget accounts for everything appended afterwards: the truncation
    # notice + blank line here, plus the caller's blank line + footer.
    budget = MAX_LINES - 4
    trimmed = lines[:budget]
    while trimmed and trimmed[-1] == "":
        trimmed.pop()
    if remaining > 0 or len(trimmed) < len(lines):
        hidden = max(remaining, 1)
        trimmed.append("")
        trimmed.append(f"_{hidden} more — see full report_")
    return trimmed


def render_pr_comment(report, ci_context=None):
    """Render the Markdown PR comment for ``report``.

    ``ci_context`` is accepted for provenance in the collapsed detail
    line and may be ``None``. The output is deterministic and contains no
    source text, secret values, or timestamps.
    """
    report = report or {}
    diff = report.get("capability_diff") or {}
    lines = [MARKER, ""]

    if not diff or not diff.get("baseline_available", False):
        lines.extend(_first_scan_summary(report))
        lines.extend(["", _footer(report)])
        return "\n".join(lines) + "\n"

    blocks = _tool_blocks(diff)
    if not blocks:
        lines.append("### SafeAI — no capability escalations in this change")
        lines.extend(["", _footer(report)])
        return "\n".join(lines) + "\n"

    total = sum(len(block["escalations"]) for block in blocks)
    heading = (
        f"### SafeAI — {total} capability "
        f"{_plural(total, 'escalation')} across "
        f"{len(blocks)} {_plural(len(blocks), 'tool')}"
    )
    lines.extend([heading, ""])

    body = []
    shown = 0
    for block in blocks:
        candidate = body + _render_block(block)
        # Reserve space for the detail line, footer, and blank separators.
        if len(lines) + len(candidate) > MAX_LINES - 4 and shown:
            break
        body = candidate
        shown += 1

    lines.extend(body)
    # Newly reachable data-flow paths ride alongside escalations inside the
    # same line budget (details line + footer need 4 reserved lines;
    # _truncate below still enforces the hard cap).
    remaining = MAX_LINES - 4 - len(lines) - 2
    if remaining > 3:
        sections = _dataflow_paths(report, budget=remaining)
        questions = _review_questions(
            report, budget=max(0, remaining - len(sections)))
        iac_lines = _iac_authority(
            report, budget=max(0, remaining - len(sections) - len(questions)))
        if sections and (questions or iac_lines):
            sections.append("")
        sections.extend(questions)
        if questions and iac_lines:
            sections.append("")
        sections.extend(iac_lines)
        if sections:
            lines.extend(sections)
            lines.append("")
    lines.extend(_details_line(report, diff, shown))
    lines = _truncate(lines, len(blocks), shown)

    while lines and lines[-1] == "":
        lines.pop()
    lines.extend(["", _footer(report)])
    return "\n".join(lines) + "\n"


def write_pr_comment(report, path, ci_context=None):
    """Write the rendered comment to ``path`` and return the text."""
    text = render_pr_comment(report, ci_context=ci_context)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return text


def post_pr_comment(report, ci_context=None, token=None):
    """Post or update the PR comment on GitHub.

    Uses the GitHub API to find an existing comment with the MARKER and
    update it, or create a new comment if none exists. Returns the comment
    URL on success, None on failure.

    Requires:
    - ci_context with ``pr_number`` and ``repository``
    - A GitHub token with ``pull_requests: write`` permission
    """
    import os

    if ci_context is None:
        ci_context = {}
    pr_number = ci_context.get("pr_number")
    repository = ci_context.get("repository")
    if not pr_number or not repository:
        return None

    token = token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return None

    text = render_pr_comment(report, ci_context=ci_context)
    api_base = f"https://api.github.com/repos/{repository}"

    # Explicit integration boundary: the scanner is offline by default;
    # this is the one path that makes a network request, and it says so.
    sys.stderr.write(
        "Integration mode enabled: SafeAI is making an explicit GitHub API "
        "request to post/update a PR comment.\n"
    )

    # Find existing comment with our marker
    comment_id = _find_existing_comment(api_base, pr_number, token)
    if comment_id:
        # Update existing comment
        return _update_comment(api_base, comment_id, text, token)
    else:
        # Create new comment
        return _create_comment(api_base, pr_number, text, token)


def _find_existing_comment(api_base, pr_number, token):
    """Find an existing SafeAI PR comment by marker."""
    import json
    import urllib.error
    import urllib.request

    url = f"{api_base}/issues/{pr_number}/comments?per_page=100"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            comments = json.loads(resp.read())
            for comment in comments:
                if MARKER in comment.get("body", ""):
                    return comment["id"]
    except (urllib.error.URLError, json.JSONDecodeError):
        pass
    return None


def _create_comment(api_base, pr_number, text, token):
    """Create a new PR comment."""
    import json
    import urllib.error
    import urllib.request

    url = f"{api_base}/issues/{pr_number}/comments"
    data = json.dumps({"body": text}).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            return result.get("html_url")
    except (urllib.error.URLError, json.JSONDecodeError):
        return None


def _update_comment(api_base, comment_id, text, token):
    """Update an existing PR comment."""
    import json
    import urllib.error
    import urllib.request

    url = f"{api_base}/issues/comments/{comment_id}"
    data = json.dumps({"body": text}).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    })
    req.get_method = lambda: "PATCH"
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            return result.get("html_url")
    except (urllib.error.URLError, json.JSONDecodeError):
        return None
