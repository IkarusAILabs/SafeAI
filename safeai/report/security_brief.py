"""Security brief: scan report -> decision-support model.

Pure deterministic transformation consumed by HTML, Markdown/PR, and
future reporting formats. Never executes scans, never touches the
network, never invents conclusions: every statement, action, and
uncertainty cites report evidence, and unknown stays unknown.

Brief shape (all lists deterministically ordered, no timestamps —
identical input yields identical brief)::

    {
      "schema_version": 1,
      "posture": {risk_score, risk_band, finding_counts,
                  agent_count, tool_count, capability_count},
      "evidence": {detected, declared, inferred, repo-iac-observed,
                   unknown},          # findings by provenance_class
      "changes": {available, summary, escalations},
      "authority": {available, match, excess, mismatch,
                    unverified_link, unknown},
      "actions": [{reference, priority, title, reason, evidence_refs,
                   remediation, confidence, limitations}],
      "uncertainty": [{kind, detail, evidence_ref}],
      "coverage": [...],
      "value": {agents_discovered, capabilities_inventoried, ...},
    }

Risk bands reuse the documented HTML gauge bands
(docs/architecture/RISK_MODEL.md); no new scoring is introduced.
"""


SCHEMA_VERSION = 1

MAX_ACTIONS = 7
MAX_UNCERTAINTY = 10
MAX_HIGHLIGHTS = 6

_SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

_PROVENANCE_ORDER = (
    "detected", "declared", "inferred", "repo-iac-observed", "unknown",
)

_VERDICT_KEYS = (
    ("MATCH", "match"),
    ("EXCESS_AUTHORITY", "excess"),
    ("AUTHORITY_MISMATCH", "mismatch"),
    ("UNVERIFIED_LINK", "unverified_link"),
    ("UNKNOWN", "unknown"),
)


def _severity_of(item):
    return str(item.get("severity") or "info").lower()


def _rank(severity):
    return _SEVERITY_RANK.get(str(severity or "").lower(), 5)


def _risk_band(score):
    """Gauge bands from docs/architecture/RISK_MODEL.md (reused, not invented)."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if value >= 80:
        return "very-high"
    if value >= 50:
        return "high"
    if value >= 25:
        return "moderate"
    return "low"


def _ref(finding):
    """Stable reference: fingerprint when present, else rule@file:line."""
    fingerprint = finding.get("fingerprint") or finding.get("finding_id")
    if fingerprint:
        return str(fingerprint)
    return "{}@{}:{}".format(
        finding.get("rule_id", "UNKNOWN"),
        finding.get("file", "?"),
        finding.get("line", 0),
    )


def _location(finding):
    if finding.get("file"):
        return "{}:{}".format(finding.get("file"), finding.get("line", 0))
    return ""


def _priority_for(severity, lane=None, provenance=None):
    if _rank(severity) <= 1:
        return "high"
    if lane == "B":
        return "medium"
    if str(provenance or "") == "unknown" and _rank(severity) <= 1:
        return "high"
    if _rank(severity) == 2:
        return "medium"
    return "low"


def build_posture(report):
    """Risk signal + inventory counts (descriptive, never a verdict)."""
    trust = report.get("trust_score") or {}
    score = trust.get("overall_ai_risk_score")
    counts = {}
    for severity, count in (report.get("counts") or {}).items():
        try:
            counts[str(severity)] = int(count)
        except (TypeError, ValueError):
            continue
    agents = report.get("kya_agents") or report.get("agents") or []
    tools = report.get("tool_surface") or []
    capabilities = report.get("normalized_capabilities") or []
    return {
        "risk_score": score,
        "risk_band": _risk_band(score),
        "finding_counts": dict(sorted(counts.items())),
        "agent_count": len(agents),
        "tool_count": len(tools),
        "capability_count": len(capabilities),
    }


def build_evidence(report):
    """Findings bucketed by provenance class (unknown stays unknown)."""
    buckets = {key: 0 for key in _PROVENANCE_ORDER}
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        provenance = str(finding.get("provenance_class") or "unknown")
        if provenance not in buckets:
            provenance = "unknown"
        buckets[provenance] += 1
    return buckets


def _change_summary(diff):
    """Human lines describing a capability diff (evidence-backed only)."""
    counts = diff.get("counts") or {}
    lines = []
    added = counts.get("added", 0)
    removed = counts.get("removed", 0)
    changed = counts.get("changed", 0)
    escalations = counts.get("escalations", 0)
    if added:
        lines.append("{} new tool{} detected since the approved baseline.".format(
            added, "" if added == 1 else "s"))
    if removed:
        lines.append("{} tool{} removed since the approved baseline.".format(
            removed, "" if removed == 1 else "s"))
    if changed:
        lines.append("{} tool{} changed authority since the approved baseline.".format(
            changed, "" if changed == 1 else "s"))
    if escalations:
        lines.append("{} capability escalation{} recorded.".format(
            escalations, "" if escalations == 1 else "s"))
    if diff.get("baseline_tool_attribution") is False:
        lines.append("Baseline predates per-tool attribution; only combination rules were evaluated.")
    return lines


def _escalation_entries(diff):
    """Compact per-escalation records, deterministically ordered."""
    entries = []
    for tool in diff.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        for escalation in tool.get("escalations") or []:
            if not isinstance(escalation, dict):
                continue
            entries.append({
                "reference": "escalation:{}:{}".format(
                    tool.get("tool_key", "?"), escalation.get("id", "?")),
                "tool_key": str(tool.get("tool_key", "")),
                "id": str(escalation.get("id", "")),
                "severity": str(escalation.get("severity", "info")),
                "summary": str(escalation.get("summary", "")),
                "inferred": bool(escalation.get("inferred")),
                "confidence": str(escalation.get("confidence", "")),
                "remediation": escalation.get("remediation") or {},
            })
    entries.sort(key=lambda e: (_rank(e["severity"]), e["tool_key"], e["id"]))
    return entries


def build_changes(report):
    """Capability-change evidence (empty when no baseline diff exists)."""
    diff = report.get("capability_diff")
    if not isinstance(diff, dict) or not diff:
        return {"available": False, "summary": [], "escalations": []}
    return {
        "available": True,
        "summary": _change_summary(diff),
        "escalations": _escalation_entries(diff),
    }


def build_authority(report):
    """IaC verdict counts (static evidence; never runtime proof)."""
    iac = report.get("iac_correlations")
    if not isinstance(iac, dict) or not (iac.get("grants") or iac.get("verdicts")):
        return {"available": False, "match": 0, "excess": 0,
                "mismatch": 0, "unverified_link": 0, "unknown": 0}
    counts = {key: 0 for _, key in _VERDICT_KEYS}
    for item in iac.get("verdicts") or []:
        if not isinstance(item, dict):
            continue
        for verdict, key in _VERDICT_KEYS:
            if str(item.get("verdict")) == verdict:
                counts[key] += 1
                break
    return {"available": True, **counts}


def _action_from_escalation(entry):
    remediation = entry["remediation"] if isinstance(entry["remediation"], dict) else {}
    actions = remediation.get("recommended_actions") or []
    why = remediation.get("why_it_matters") or entry["summary"]
    questions = remediation.get("review_questions") or []
    limitations = remediation.get("limitations") or ["Static evidence only; confirm against the cited tool."]
    return {
        "reference": entry["reference"],
        "priority": _priority_for(entry["severity"]),
        "title": "{} on {}".format(entry["id"] or "Escalation", entry["tool_key"] or "unknown tool"),
        "reason": str(why or "Capability escalation recorded between scans."),
        "evidence_refs": [entry["tool_key"]] if entry["tool_key"] else [],
        "remediation": str(actions[0]) if actions else "Review whether the authority change is intentional; update the approved baseline if so.",
        "confidence": str(entry["confidence"] or ("low" if entry["inferred"] else "medium")),
        "limitations": [str(item) for item in limitations],
        "review_questions": [str(q) for q in questions],
    }


def _action_from_lane_match(match):
    policy_id = str(match.get("policy_id") or "review")
    message = str(match.get("message") or "requires human review")
    return {
        "reference": f"policy:{policy_id}",
        "priority": "medium",
        "title": f"Human review: {policy_id}",
        "reason": message,
        "evidence_refs": [policy_id],
        "remediation": "A reviewer must decide; CI cannot decide this automatically.",
        "confidence": "medium",
        "limitations": ["Requires human judgment; no deterministic verdict exists."],
        "review_questions": [message],
    }


_IAC_REMEDIATION = {
    "EXCESS_AUTHORITY": "Narrow the grant to the required operations, or declare and justify the wider capability.",
    "AUTHORITY_MISMATCH": "Add the missing grant, or confirm it is granted outside this repository and record that link.",
    "UNVERIFIED_LINK": "Confirm which runtime identity the agent assumes; without that link this stays review-only.",
}

_IAC_CONFIDENCE = {
    "EXCESS_AUTHORITY": "medium",
    "AUTHORITY_MISMATCH": "medium",
    "UNVERIFIED_LINK": "low",
}


def _action_from_verdict(item):
    name = str(item.get("verdict") or "UNKNOWN")
    domain = str(item.get("domain") or "unknown")
    identity = item.get("identity_ref") or {}
    who = str(identity.get("name") or "repository")
    refs = list(item.get("grant_evidence_refs") or []) + list(item.get("link_evidence_refs") or [])
    return {
        "reference": f"iac:{domain}:{name}",
        "priority": "high" if name == "EXCESS_AUTHORITY" else "medium",
        "title": "{}: {} ({})".format(name.replace("_", " ").title(), domain, who),
        "reason": str(item.get("reason") or name),
        "evidence_refs": refs,
        "remediation": _IAC_REMEDIATION.get(name, "Review the verdict evidence."),
        "confidence": _IAC_CONFIDENCE.get(name, "low"),
        "limitations": ["Repository IaC is evidence of declared grants, never proof of deployed permission."],
        "review_questions": [],
    }


def _action_from_finding(finding):
    location = _location(finding)
    return {
        "reference": _ref(finding),
        "priority": _priority_for(finding.get("severity"),
                                 lane=finding.get("lane"),
                                 provenance=finding.get("provenance_class")),
        "title": "{} ({})".format(str(finding.get("message", finding.get("rule_id", "Finding")))[:120],
                                  location or str(finding.get("rule_id", ""))),
        "reason": str(finding.get("message") or finding.get("rule_id", "")),
        "evidence_refs": [location] if location else [],
        "remediation": str(finding.get("remediation") or "Review the flagged configuration."),
        "confidence": str(finding.get("confidence_label") or finding.get("confidence") or "medium"),
        "limitations": ["Static pattern evidence; verify in context before acting."],
        "review_questions": [],
    }


def build_actions(report, changes=None, authority=None):
    """Review actions from escalations, Lane-B matches, IaC verdicts,
    and critical/high findings — each mapped to evidence, none invented.
    Capped and deterministically ordered."""
    changes = changes if changes is not None else build_changes(report)
    actions = []
    for entry in (changes.get("escalations") or [])[:MAX_ACTIONS]:
        actions.append(_action_from_escalation(entry))
    decision = report.get("policy_decision") or {}
    for match in decision.get("matches") or []:
        if not isinstance(match, dict) or match.get("lane") != "B":
            continue
        actions.append(_action_from_lane_match(match))
    iac = report.get("iac_correlations") or {}
    if isinstance(iac, dict):
        for item in iac.get("verdicts") or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("verdict")) in ("MATCH", "UNKNOWN"):
                continue
            actions.append(_action_from_verdict(item))
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        severity = _severity_of(finding)
        gateability = str(finding.get("gateability") or "")
        if severity == "critical" or (severity == "high" and gateability == "review-only"):
            actions.append(_action_from_finding(finding))
    order = {"high": 0, "medium": 1, "low": 2}
    actions.sort(key=lambda a: (order.get(a["priority"], 3), a["title"], a["reference"]))
    return actions[:MAX_ACTIONS]


def build_uncertainty(report):
    """Open questions: inferred, unresolved, unknown, unlinked, static limits."""
    items = []

    def add(kind, detail, ref=""):
        items.append({"kind": kind, "detail": detail, "evidence_ref": ref})

    for tool in report.get("tool_surface") or []:
        if not isinstance(tool, dict):
            continue
        for cap in tool.get("capabilities") or []:
            if not isinstance(cap, dict) or not cap.get("access_mode_inferred"):
                continue
            evidence = cap.get("evidence") or []
            ref = ""
            if evidence and isinstance(evidence[0], dict):
                ref = "{}:{}".format(evidence[0].get("path", ""),
                                     evidence[0].get("line", 0))
            add("inferred-access-mode",
                "{} access mode on {} was inferred, not declared.".format(
                    cap.get("name", "capability"), tool.get("tool_key", "unknown tool")),
                ref)
    iac = report.get("iac_correlations") or {}
    if isinstance(iac, dict):
        for grant in iac.get("grants") or []:
            if not isinstance(grant, dict):
                continue
            fields = grant.get("actions") or {}
            resources = grant.get("resources") or {}
            if not isinstance(fields, dict):
                continue
            unresolved = (str(fields.get("resolution", "")) != "resolved"
                          or str(resources.get("resolution", "")) != "resolved")
            if unresolved:
                add("unresolved-iac-reference",
                    "IaC grant '{}' has unresolved values; conclusions about it stay unknown.".format(
                        (grant.get("identity") or {}).get("name", "?")),
                    "{}:{}".format(grant.get("source_file", ""), grant.get("line", 0)))
        for item in iac.get("verdicts") or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("verdict")) == "UNVERIFIED_LINK":
                refs = item.get("grant_evidence_refs") or []
                add("missing-identity-link",
                    "No static Agent-to-Identity link for {}.".format(item.get("domain", "?")),
                    refs[0] if refs else "")
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("provenance_class") or "") == "unknown":
            add("unknown-evidence",
                "{} reported with unknown provenance.".format(
                    finding.get("rule_id", "A finding")),
                _location(finding))
    items.sort(key=lambda i: (i["kind"], i["detail"], i["evidence_ref"]))
    return items[:MAX_UNCERTAINTY]


def build_coverage(report):
    """What the scan inspected (factual strings, deterministic order)."""
    lines = ["Files scanned: {}".format(report.get("files_scanned", 0))]
    frameworks = sorted(report.get("detected_frameworks") or [])
    lines.append("Frameworks: {}".format(", ".join(frameworks) if frameworks else "none detected"))
    iac = report.get("iac_correlations") or {}
    if isinstance(iac, dict):
        files = iac.get("files") or {}
        inspected = sorted(set(files.get("terraform") or []) | set(files.get("kubernetes_rbac") or []))
        if inspected or (iac.get("grants") or iac.get("verdicts")):
            lines.append(f"IaC files inspected: {len(inspected)}")
        unparsed = sorted(set(files.get("unparsed") or []))
        if unparsed:
            lines.append(f"IaC files skipped (unparseable): {len(unparsed)}")
    boundary = report.get("assurance_boundary") or {}
    inferred = boundary.get("inferred_value_count") or 0
    lines.append(f"Inferred values in this scan: {inferred}")
    return lines


def build_value(report, brief=None):
    """Descriptive product-value indicators derived from evidence."""
    brief = brief if brief is not None else {}
    changes = brief.get("changes") or {}
    authority = brief.get("authority") or {}
    escalations = changes.get("escalations") or []
    iac = report.get("iac_correlations") or {}
    if not isinstance(iac, dict):
        iac = {}
    verdicts = iac.get("verdicts") or []
    unknown_verdicts = sum(1 for v in verdicts
                           if isinstance(v, dict) and str(v.get("verdict")) == "UNKNOWN")
    unknown_findings = sum(1 for f in report.get("findings") or []
                           if isinstance(f, dict)
                           and str(f.get("provenance_class") or "") == "unknown")
    unknown_changes = sum(1 for t in ((report.get("capability_diff") or {}).get("tools") or [])
                          if isinstance(t, dict) and str(t.get("change_class")) == "UNKNOWN")
    grants = iac.get("grants") or []
    bindings = iac.get("grant_bindings") or []
    actions = brief.get("actions") or []
    return {
        "agents_discovered": (brief.get("posture") or {}).get("agent_count", 0),
        "capabilities_inventoried": (brief.get("posture") or {}).get("capability_count", 0),
        "capability_changes_identified": len(changes.get("summary") or []),
        "escalations_identified": len(escalations),
        "authority_relationships_identified": len(grants) + len(bindings),
        "unresolved_identity_links": int(authority.get("unverified_link", 0)),
        "unknown_conclusions": unknown_verdicts + unknown_findings + unknown_changes,
        "actionable_review_items": len(actions),
    }


def build_highlights(report, limit=MAX_HIGHLIGHTS):
    """Concise human statements from tool-surface evidence (traced only)."""
    highlights = []
    for tool in report.get("tool_surface") or []:
        if not isinstance(tool, dict) or len(highlights) >= limit:
            continue
        key = str(tool.get("tool_key") or "unknown tool")
        for cap in tool.get("capabilities") or []:
            if not isinstance(cap, dict) or len(highlights) >= limit:
                continue
            name = str(cap.get("name") or "")
            mode = str(cap.get("access_mode") or "")
            if not name or mode in ("", "none"):
                continue
            evidence = cap.get("evidence") or []
            ref = ""
            if evidence and isinstance(evidence[0], dict):
                ref = "{}:{}".format(evidence[0].get("path", ""),
                                     evidence[0].get("line", 0))
            highlights.append({
                "text": "{} is available to {} ({} access).".format(
                    name.replace("_", " ").capitalize(), key, mode),
                "evidence_ref": ref,
            })
    highlights.sort(key=lambda h: (h["text"], h["evidence_ref"]))
    return highlights[:limit]


def build_security_brief(report):
    """Transform a scan report into the decision-support brief."""
    report = report if isinstance(report, dict) else {}
    posture = build_posture(report)
    evidence = build_evidence(report)
    changes = build_changes(report)
    authority = build_authority(report)
    actions = build_actions(report, changes=changes, authority=authority)
    brief = {
        "schema_version": SCHEMA_VERSION,
        "posture": posture,
        "evidence": evidence,
        "changes": changes,
        "authority": authority,
        "actions": actions,
        "uncertainty": build_uncertainty(report),
        "coverage": build_coverage(report),
    }
    brief["value"] = build_value(report, brief=brief)
    return brief
