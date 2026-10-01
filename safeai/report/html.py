"""Self-contained HTML report generator.

Produces a single-file HTML report with the shared SafeAI design system
(:mod:`safeai.report.html_kit`). Includes an executive summary with a
risk gauge, trust score breakdown, capability matrix, capability
escalations (v1.4), governance summary, the full findings table, KYA
agent records, per-tool capability surface, and the assurance boundary.
"""

from datetime import UTC, datetime
from html import escape

from safeai.report import html_kit
from safeai.report.security_brief import (
    build_actions,
    build_authority,
    build_changes,
    build_evidence,
    build_highlights,
    build_posture,
)


def _priority_badge(priority):
    colors = {"high": ("#dc2626", "#fef2f2"), "medium": ("#ea580c", "#fff7ed"),
              "low": ("#2563eb", "#eff6ff")}
    fg, bg = colors.get(str(priority or "").lower(), ("#6b7280", "#f9fafb"))
    return (
        f"<span class='badge' style='color:{fg};background:{bg};border-color:{fg}33'>"
        f"{escape(str(priority or 'low').upper())}</span>"
    )


def _verdict_badge(verdict):
    colors = {"MATCH": ("#16a34a", "#f0fdf4"),
              "EXCESS_AUTHORITY": ("#dc2626", "#fef2f2"),
              "AUTHORITY_MISMATCH": ("#ea580c", "#fff7ed"),
              "UNVERIFIED_LINK": ("#ca8a04", "#fefce8"),
              "UNKNOWN": ("#6b7280", "#f9fafb")}
    fg, bg = colors.get(str(verdict or "").upper(), ("#6b7280", "#f9fafb"))
    return (
        f"<span class='badge' style='color:{fg};background:{bg};border-color:{fg}33'>"
        f"{escape(str(verdict or 'UNKNOWN'))}</span>"
    )


def _brief_section(report):
    """Security Brief: 30-second risk signal, evidence confidence, scope."""
    posture = build_posture(report)
    evidence = build_evidence(report)
    brief_changes = build_changes(report)
    authority = build_authority(report)
    total_findings = sum(evidence.values())
    grounded = evidence.get("detected", 0) + evidence.get("declared", 0)
    confidence = (f"{100.0 * grounded / total_findings:.0f}% deterministic"
                  if total_findings else "n/a (no findings)")
    unknown = evidence.get("unknown", 0)
    escalations = len(brief_changes.get("escalations") or [])
    verdict_bits = []
    if authority.get("available"):
        for key in ("excess", "mismatch", "unverified_link", "unknown"):
            count = authority.get(key, 0)
            if count:
                verdict_bits.append("{} {}".format(count, key.replace("_", " ")))
    cards = "".join([
        html_kit.kpi("Risk signal",
                     "{} ({} band)".format(
                         "–" if posture["risk_score"] is None else posture["risk_score"],
                         posture["risk_band"]),
                     accent="#0f766e"),
        html_kit.kpi("Evidence confidence", escape(confidence), accent="#2563eb"),
        html_kit.kpi("Agents / Tools / Capabilities",
                     "{}/{}/{}".format(posture["agent_count"], posture["tool_count"],
                                       posture["capability_count"]),
                     accent="#7c3aed"),
        html_kit.kpi("Escalations", escalations, accent="#dc2626"),
        html_kit.kpi("Authority observations",
                     escape(", ".join(verdict_bits) if verdict_bits else "none"),
                     accent="#ea580c"),
        html_kit.kpi("Unresolved / unknown", unknown, accent="#6b7280"),
    ])
    baseline_line = ""
    for line in brief_changes.get("summary") or []:
        baseline_line = escape(line)
        break
    return f"""
    <h2>Security Brief</h2>
    <div class='hero'>{cards}</div>
    {("<p>" + baseline_line + "</p>") if baseline_line else ""}
    <p class='muted'>Risk and evidence confidence are different dimensions: a high
    risk signal with inferred evidence needs verification before action.</p>"""


def _found_section(report):
    """What SafeAI Found: traced human statements from tool-surface evidence."""
    highlights = build_highlights(report)
    if not highlights:
        return ""
    items = "".join(
        "<li>{} <span class='muted'>({})</span></li>".format(
            escape(h["text"]), escape(h["evidence_ref"] or "static evidence"))
        for h in highlights
    )
    return f"""
    <h2>What SafeAI Found</h2>
    <div class='card'><ul>{items}</ul>
    <p class='muted'>Each statement traces to cited evidence; nothing here is inferred beyond the reference.</p></div>"""


def _actions_section(report):
    """Recommended Review Actions: prioritized, evidence-mapped, capped."""
    actions = build_actions(report)
    if not actions:
        return """
    <h2>Recommended Review Actions</h2>
    <div class='card'><p class='muted'>No review actions: no escalations, policy questions, authority findings, or critical findings in this scan.</p></div>"""
    cards = []
    for action in actions:
        refs = "".join(f"<li><code>{escape(r)}</code></li>"
                       for r in action["evidence_refs"]) or "<li>—</li>"
        questions = "".join(f"<li>{escape(q)}</li>"
                            for q in action.get("review_questions") or [])
        limits = "".join(f"<li>{escape(item)}</li>"
                         for item in action["limitations"])
        cards.append(f"""
      <div class='card'>
        <h3>{_priority_badge(action['priority'])} {escape(action['title'])}</h3>
        <p><strong>Why:</strong> {escape(action['reason'])}</p>
        <p><strong>Evidence:</strong></p><ul>{refs}</ul>
        <p><strong>Recommended reviewer action:</strong> {escape(action['remediation'])}</p>
        <p class='muted'>Confidence: {escape(action['confidence'])}</p>
        {("<p><strong>Reviewer questions:</strong></p><ul>" + questions + "</ul>") if questions else ""}
        <p class='muted'>Limitations:</p><ul>{limits}</ul>
      </div>""")
    return f"""
    <h2>Recommended Review Actions</h2>
    <div class='grid-2'>{''.join(cards)}</div>"""


def _changes_section(report):
    """Capability Changes in human terms (drill-down table kept below)."""
    changes = build_changes(report)
    if not changes.get("available"):
        return """
    <h2>Capability Changes</h2>
    <div class='card'><p class='muted'>No baseline supplied: change comparison needs <code>--baseline</code> with a prior manifest or JSON report.</p></div>"""
    lines = "".join(f"<li>{escape(line)}</li>" for line in changes["summary"])
    return f"""
    <h2>Capability Changes</h2>
    <div class='card'><ul>{lines or "<li>No material changes.</li>"}</ul>
    <p class='muted'>Per-tool detail with escalation rules follows in Capability Escalations.</p></div>"""


def _authority_section(report):
    """Authority Review: IaC verdicts grouped with evidence and confidence."""
    iac = report.get("iac_correlations")
    if not isinstance(iac, dict) or not (iac.get("grants") or iac.get("verdicts")):
        return ""
    rows = []
    for item in iac.get("verdicts") or []:
        if not isinstance(item, dict):
            continue
        identity = item.get("identity_ref") or {}
        refs = list(item.get("grant_evidence_refs") or []) + list(item.get("link_evidence_refs") or [])
        rows.append([
            _verdict_badge(item.get("verdict")),
            escape(str(item.get("domain") or "")),
            escape(str(identity.get("name") or "repository")),
            escape(", ".join(refs) if refs else "—"),
            escape(str(item.get("resolution") or "")),
        ])
    rows.sort(key=lambda r: (r[0], r[1]))
    legend = ("MATCH: grant covers the linked requirement. EXCESS_AUTHORITY: grant "
              "exceeds need. AUTHORITY_MISMATCH: linked identity lacks a needed grant. "
              "UNVERIFIED_LINK: no static Agent-to-Identity link. UNKNOWN: insufficient evidence.")
    return f"""
    <h2>Authority Review</h2>
    <div class='card'><p>{escape(legend)}</p>
    <p class='muted'>Repository IaC is evidence of declared grants, never proof of deployed runtime permission.</p></div>
    """ + html_kit.data_table(
        ["Verdict", "Domain", "Identity", "Evidence", "Resolution"],
        rows,
        empty="No authority verdicts.",
    )


def _worked_example(finding, gateability_label):
    """One Risk/Evidence/Gateability example line, fully escaped."""
    location = ""
    if finding.get("file"):
        location = " ({}:{})".format(finding.get("file", ""),
                                     finding.get("line", 0))
    return (
        "<p>Risk: {}<br>Evidence: {}<br>Gateability: {} ({}{})</p>".format(
            escape(str(finding.get("severity", "")).capitalize()),
            escape(str(finding.get("provenance_class", "unknown")).capitalize()),
            escape(gateability_label),
            escape(str(finding.get("rule_id", ""))),
            escape(location),
        )
    )


def _confidence_section(report):
    """Evidence Confidence legend with live counts and worked examples."""
    evidence = build_evidence(report)
    legend = [
        ["Detected", "Observed in code/config by SafeAI analysis", str(evidence.get("detected", 0))],
        ["Declared", "Stated by the agent's own configuration", str(evidence.get("declared", 0))],
        ["Inferred", "Heuristic conclusion; verify before acting", str(evidence.get("inferred", 0))],
        ["Repository IaC observed", "Granted in repo IaC; review-only, never runtime proof",
         str(evidence.get("repo-iac-observed", 0))],
        ["Unknown", "Could not be determined; never treated as safe", str(evidence.get("unknown", 0))],
    ]
    examples = ""
    deterministic = [f for f in report.get("findings") or []
                     if isinstance(f, dict) and str(f.get("gateability") or "") == "deterministic"]
    deterministic.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        str(f.get("severity") or "").lower(), 5), str(f.get("rule_id", ""))))
    review_only = [f for f in report.get("findings") or []
                   if isinstance(f, dict)
                   and (str(f.get("provenance_class") or "") in ("inferred", "unknown")
                        or str(f.get("gateability") or "") == "review-only")]
    if deterministic:
        examples += _worked_example(deterministic[0], "Deterministic")
    if review_only:
        examples += _worked_example(review_only[0], "Review-only")
    return """
    <h2>Evidence Confidence</h2>
    <div class='card'><p>Risk (how bad if exploited) and evidence confidence (how reliably
    SafeAI observed it) are different dimensions. A high-risk finding on inferred evidence
    needs verification; a medium-risk finding on repository IaC is review-only by design.</p></div>
    """ + html_kit.data_table(
        ["Evidence class", "Meaning", "Findings"],
        legend,
        empty="No evidence.",
        searchable=False,
    ) + (f"<div class='card'><h3>Worked examples from this scan</h3>{examples}</div>" if examples else "")


def _sev_badge(severity):
    return html_kit.sev_badge(severity)


def _escalation_remediation_html(escalation):
    """Collapsible remediation for one escalation (absent on old reports)."""
    remediation = escalation.get("remediation") or {}
    actions = remediation.get("recommended_actions") or []
    if not isinstance(actions, list):
        actions = [actions]
    why = remediation.get("why_it_matters") or ""
    questions = remediation.get("review_questions") or []
    limitations = remediation.get("limitations") or []
    if not (why or actions or questions):
        return ""
    body = ""
    if why:
        body += f"<p>{escape(str(why))}</p>"
    if actions:
        items = "".join(f"<li>{escape(str(a))}</li>" for a in actions)
        body += f"<p><strong>Recommended actions</strong></p><ul>{items}</ul>"
    if questions:
        items = "".join(f"<li>{escape(str(q))}</li>" for q in questions)
        body += f"<p><strong>Review questions</strong></p><ul>{items}</ul>"
    if limitations:
        items = "".join(f"<li>{escape(str(l))}</li>" for l in limitations)
        body += f"<p class='muted'>Limitations: {items}</p>"
    return f"<details><summary>Remediation</summary>{body}</details>"


def _escalation_section(report):
    """Render the capability escalation summary (v1.4 capability_diff)."""
    diff = report.get("capability_diff")
    if not diff:
        return ""
    counts = diff.get("counts") or {}
    highest = diff.get("highest_escalation")

    cards = "".join(
        html_kit.kpi(label, value, accent="#0f766e")
        for label, value in [
            ("Added", counts.get("added", 0)),
            ("Removed", counts.get("removed", 0)),
            ("Changed", counts.get("changed", 0)),
            ("Escalations", counts.get("escalations", 0)),
        ]
    )

    tool_rows = []
    for tool in diff.get("tools") or []:
        summary = tool.get("access_summary") or {}
        escalations = tool.get("escalations") or []
        esc_html = "".join(
            f"<div>{_sev_badge(e.get('severity', 'info'))} "
            f"<code>{escape(str(e.get('id', '')))}</code> "
            f"{escape(str(e.get('summary', '')))}{' <span class=muted>(inferred)</span>' if e.get('inferred') else ''}"
            f"{_escalation_remediation_html(e)}</div>"
            for e in escalations
        ) or "<span class='muted'>no per-rule escalation</span>"
        tool_rows.append(
            "<tr>"
            f"<td><code>{escape(str(tool.get('tool_key', '')))}</code></td>"
            f"<td>{escape(str(tool.get('status', '')))}</td>"
            f"<td>{escape(str(summary.get('before', '-')))} &rarr; {escape(str(summary.get('after', '-')))}</td>"
            f"<td>{esc_html}</td>"
            "</tr>"
        )
    tools_table = (
        f"<table><thead><tr><th>Tool</th><th>Status</th><th>Access (before -> after)</th>"
        f"<th>Escalation rules</th></tr></thead><tbody>{''.join(tool_rows) or '<tr><td colspan=4 class=muted center>No tool-level changes.</td></tr>'}</tbody></table>"
    )

    baseline_note = (
        "<div class='note'>Baseline predates per-tool attribution; only combination rules were "
        "evaluated (individual per-tool escalation rules suppressed).</div>"
        if diff.get("baseline_tool_attribution") is False
        else ""
    )

    return f"""
    <h2>Capability Escalations</h2>
    <div class='hero'>{cards}</div>
    {baseline_note}
    {tools_table}
    <p class='muted'>Highest escalation: {escape(str(highest or 'none'))}</p>"""


def _dependency_section(report):
    """Render the CE 1.5 dependency inventory + correlation summary."""
    inventory = report.get("dependency_inventory") or []
    correlation = report.get("dependency_correlation") or {}
    if not inventory and not correlation:
        return ""
    parts = []

    if inventory:
        rows = [
            [
                escape(str(e.get("name", ""))),
                "Yes" if e.get("secret") else "No",
                str(e.get("source_count", 0)),
                ", ".join(
                    f"{escape(str(s.get('file', '')))}:{s.get('line', '')}"
                    for s in (e.get("sources") or [])[:3]
                ) or "-",
            ]
            for e in inventory
        ]
        parts.append(html_kit.data_table(
            ["Name", "Secret-backed", "Refs", "Sources"],
            rows,
            empty="No external configuration/credential references detected.",
        ))

    counts = correlation.get("counts") or {}
    undeclared = counts.get("undeclared", 0)
    orphaned = counts.get("orphaned", 0)
    families = counts.get("families") or {}
    fam_rows = [
        [escape(str(fam)), str(info.get("referenced", 0)),
         "Yes" if info.get("declared") else "No"]
        for fam, info in sorted(families.items())
    ]
    parts.append(f"""
    <h3>Correlation</h3>
    <div class='hero'>
      {html_kit.kpi("Undeclared capability candidates", undeclared, accent='#b45309')}
      {html_kit.kpi("Orphaned declared tools", orphaned, accent='#6b7280')}
    </div>
    {html_kit.data_table(
        ["Family", "Referenced names", "Declared"],
        fam_rows,
        empty="No correlated families.",
        searchable=False,
    )}
    <p class='muted'>Name-family heuristic correlation from static references; not proof of runtime behaviour.</p>""")

    return f"""
    <h2>Dependency Inventory & Correlation</h2>
    {'<h3>Referenced configuration / credentials</h3><p class="muted">Names and source locations only — values are never read or stored.</p>' if inventory else ''}
    {''.join(parts)}"""


def _kya_section(report):
    """Render the Know Your Agent section: agents, policy, registry status."""
    agents = report.get("kya_agents")
    registry = report.get("registry") or {}
    policy = report.get("policy_decision") or {}
    policy_profile = report.get("policy_profile")
    if agents is None and not policy and not registry:
        return ""

    rows = []
    for agent in agents or []:
        caps = ", ".join(sorted({str(c.get("name", "")) for c in agent.get("capabilities") or [] if c.get("name")})) or "-"
        locations = ", ".join(
            f"{loc.get('path')}:{loc.get('line_start')}" for loc in (agent.get("source_locations") or [])
        ) or "-"
        rows.append(
            "<tr>"
            f"<td>{escape(str(agent.get('name', '')))}</td>"
            f"<td><code>{escape(str(agent.get('agent_id', '')))}</code></td>"
            f"<td>{escape(str(agent.get('framework', '')))}</td>"
            f"<td>{escape(str(agent.get('agent_type', '')))}</td>"
            f"<td>{escape(caps)}</td>"
            f"<td>{escape(locations)}</td>"
            f"<td>{escape(str(agent.get('confidence', '')))}</td>"
            "</tr>"
        )

    registry_html = ""
    if registry:
        registry_html = (
            f"<p class='muted'>Registry: {escape(str(registry.get('state', 'skipped')))}"
            + (f" - <code>{escape(str(registry.get('path')))}</code>" if registry.get("path") else "")
            + "</p>"
        )

    policy_html = ""
    if policy:
        profile_html = (
            f"<p><strong>Policy profile:</strong> {escape(str(policy_profile))}</p>"
            if policy_profile
            else ""
        )
        reasons = "".join(f"<li>{escape(str(r))}</li>" for r in (policy.get("reasons") or []))
        policy_html = (
            f"<p><strong>Policy outcome:</strong> {escape(str(policy.get('outcome', '')))}</p>"
            f"{profile_html}"
            f"<ul>{reasons}</ul>"
        )

    return f"""
    <h2>Know Your Agent (KYA)</h2>
    {registry_html}
    {policy_html}
    <table>
      <thead><tr><th>Agent</th><th>Agent ID</th><th>Framework</th><th>Type</th><th>Capabilities (static evidence)</th><th>Source</th><th>Confidence</th></tr></thead>
      <tbody>{''.join(rows) or "<tr><td colspan='7' class='muted center'>No agents/workflows detected in source/configuration.</td></tr>"}</tbody>
    </table>"""


def _tool_surface_section(report):
    """Render the per-tool capability surface (tool identity + access modes)."""
    surface = report.get("tool_surface")
    if not surface:
        return ""
    rows = []
    for tool in surface:
        tool_key = tool.get("tool_key") or tool.get("name") or "-"
        caps = tool.get("capabilities") or []
        caps_html = ", ".join(
            f"{escape(str(c.get('name', '')))} "
            f"<span class='muted'>({escape(str(c.get('access_mode', 'read')))})</span>"
            for c in caps
        ) or "-"
        inferred = sum(1 for c in caps if c.get("access_mode_inferred"))
        rows.append(
            "<tr>"
            f"<td><code>{escape(str(tool_key))}</code></td>"
            f"<td>{escape(str(tool.get('kind', '')))}</td>"
            f"<td>{escape(str(tool.get('framework', '')))}</td>"
            f"<td>{caps_html}</td>"
            f"<td>{escape(str(tool.get('access_summary', '')))}</td>"
            f"<td>{escape(str(inferred))}</td>"
            "</tr>"
        )
    return f"""
    <h2>Tool Capability Surface</h2>
    <p class='muted'>Per-tool authority: capabilities are attributed to the named tool (agent, MCP server, skill, tool, workflow node) with their access modes.</p>
    <table>
      <thead><tr><th>Tool</th><th>Kind</th><th>Framework</th><th>Capabilities (access mode)</th><th>Access summary</th><th>Inferred modes</th></tr></thead>
      <tbody>{''.join(rows) or "<tr><td colspan='6' class='muted center'>No tool surface captured.</td></tr>"}</tbody>
    </table>"""


def _assurance_section(report):
    """Render the assurance boundary: what this scan did and did not verify."""
    boundary = report.get("assurance_boundary")
    if not isinstance(boundary, dict) or not boundary:
        return ""

    def items(values):
        return "".join(f"<li>{escape(str(value))}</li>" for value in values or [])

    inferred = boundary.get("inferred_value_count") or 0
    return f"""
    <h2>Assurance boundary</h2>
    <p class='muted'>{escape(str(boundary.get("summary", "")))}</p>
    <div class='grid-2'>
      <div class='card'>
        <h3>Verified statically</h3>
        <ul>{items(boundary.get("verified_statically"))}</ul>
      </div>
      <div class='card'>
        <h3>Not verifiable statically</h3>
        <ul>{items(boundary.get("not_verifiable_statically"))}</ul>
      </div>
    </div>
    <h3>Coverage notes</h3>
    <ul>{items(boundary.get("coverage_notes"))}</ul>
    <p class='muted'>Inferred values in this scan: {escape(str(inferred))}</p>"""


# ── Architecture diagram ──────────────────────────────────────────────

import hashlib as _hashlib
import re as _re

_TYPE_SHAPES = {
    "agent": ("[", "]"),
    "tool": ("(", ")"),
    "mcp": ("{{", "}}"),
    "workflow": ("{", "}"),
    "prompt": ("[/", "/]"),
    "model": ("((", "))"),
}

_TYPE_STYLES = {
    "agent": "fill:#bfdbfe,stroke:#2563eb,stroke-width:2px",
    "tool": "fill:#bbf7d0,stroke:#16a34a,stroke-width:2px,rx:10,ry:10",
    "mcp": "fill:#fed7aa,stroke:#ea580c,stroke-width:2px",
    "workflow": "fill:#e9d5ff,stroke:#9333ea,stroke-width:2px",
    "prompt": "fill:#e5e7eb,stroke:#4b5563,stroke-width:2px",
    "model": "fill:#fecaca,stroke:#dc2626,stroke-width:2px",
}

_DEFAULT_STYLE = "fill:#f3f4f6,stroke:#9ca3af,stroke-width:2px"


def _mermaid_escape(text):
    """Escape *text* for safe interpolation inside Mermaid node labels.

    Handles both Mermaid-special characters (``"``, ``]``, ``}``) and
    HTML characters (``<``, ``>``, ``&``) since labels are rendered
    inside HTML ``<div class="mermaid">`` blocks.
    """
    s = escape(str(text))
    s = s.replace('"', "#quot;")
    s = s.replace("]", "#93;")
    s = s.replace("}", "#125;")
    return s


_ARCHIVE_NODE_ID_RE = _re.compile(r"[^A-Za-z0-9_]")


def _arch_node_id(raw_id, seen):
    """Return a Mermaid-safe node identifier, disambiguated via *seen* dict.

    Mermaid node IDs must match ``[A-Za-z_][A-Za-z0-9_]*``.  We strip
    non-alphanumeric characters and append a short hash when collisions
    occur.
    """
    clean = _ARCHIVE_NODE_ID_RE.sub("_", raw_id)
    if not clean or clean[0].isdigit():
        clean = "n_" + clean

    base = clean
    if clean not in seen:
        seen[clean] = 0
        return clean

    seen[clean] += 1
    suffix = _hashlib.sha1(raw_id.encode()).hexdigest()[:6]
    disambiguated = f"{base}_{suffix}"
    seen[disambiguated] = 0
    return disambiguated


def _architecture_table(graph_data):
    """Render a static HTML table of the component architecture.

    Always emitted — offline-safe, no external dependencies.
    """
    from safeai.analysis.component_graph import export_component_graph
    exported = export_component_graph(graph_data)
    if not exported or not exported.get("nodes"):
        return ""

    node_rows = []
    for n in exported["nodes"]:
        badge = "orphan" if n.get("is_orphan") else escape(n.get("type", "unknown"))
        node_rows.append([
            escape(n["label"]),
            f"<span class='badge'>{badge}</span>",
        ])

    edge_rows = []
    for e in exported["edges"]:
        edge_rows.append([
            escape(e["source"]),
            escape(e["label"]),
            escape(e["target"]),
        ])

    return (
        "<h2>Architecture</h2>"
        "<div class='card'>"
        "<h3>Components</h3>"
        + html_kit.data_table(["Component", "Type"], node_rows, empty="No components found.")
        + "<h3>Relationships</h3>"
        + html_kit.data_table(["Source", "Relationship", "Target"], edge_rows, empty="No relationships found.")
        + "</div>"
    )


def _architecture_mermaid(graph_data):
    """Render a Mermaid diagram of the component architecture.

    Only emitted when ``--architecture-mermaid`` is explicitly enabled.
    Requires internet access for the Mermaid.js CDN.
    """
    from safeai.analysis.component_graph import export_component_graph
    exported = export_component_graph(graph_data)
    if not exported or not exported.get("nodes"):
        return ""

    seen = {}
    lines = ["graph TD"]

    for n in exported["nodes"]:
        node_id = _arch_node_id(n["id"], seen)
        label = _mermaid_escape(n["label"])
        ntype = n.get("type", "unknown").lower()
        shape_start, shape_end = _TYPE_SHAPES.get(ntype, ("[", "]"))
        lines.append(f'    {node_id}{shape_start}"{label}"{shape_end}')

        style = _TYPE_STYLES.get(ntype, _DEFAULT_STYLE)
        if n.get("is_orphan"):
            style += ",stroke-dasharray: 5 5"
        lines.append(f"    style {node_id} {style}")

    for e in exported["edges"]:
        src = _arch_node_id(e["source"], seen)
        dst = _arch_node_id(e["target"], seen)
        label = _mermaid_escape(e["label"])
        lines.append(f'    {src} -->|"{label}"| {dst}')

    mermaid_code = "\n".join(lines)

    return (
        "<h2>Architecture (Mermaid)</h2>"
        "<div class='card' style='overflow-x:auto; text-align:center;'>"
        f"<div class='mermaid'>\n{mermaid_code}\n</div>"
        "<p class='muted' style='margin-top:10px;'>"
        "Interactive diagram — requires internet access for Mermaid.js CDN."
        "</p></div>"
        '<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>'
        "<script>mermaid.initialize({startOnLoad:true})</script>"
    )


def write_html(report, path, include_architecture=True, include_mermaid=False):
    trust = report.get("trust_score", {})
    categories = trust.get("categories", {})
    counts = report.get("counts", {})
    frameworks = report.get("detected_frameworks", [])
    findings = report.get("findings", [])
    components = report.get("components", [])
    diagnostics = report.get("diagnostics", [])
    capability_diff = report.get("capability_diff", {})

    capability_rows = []
    for cap in report.get("normalized_capabilities", []):
        capability_rows.append(
            [
                cap.get("name", ""),
                cap.get("category", ""),
                ", ".join(cap.get("source_frameworks", [])),
                f"{float(cap.get('confidence', 0.0)):.2f}",
                "; ".join(cap.get("evidence", [])),
            ]
        )

    trust_rows = [[k, str(v)] for k, v in categories.items()]

    governance_summary = [
        f for f in findings if f.get("risk_category") in {"Governance", "Integration", "Identity"}
    ]

    from safeai.report.failure_matrix import build_failure_class_matrix
    failure_matrix = build_failure_class_matrix(findings)

    severity_counts = "".join(
        f"<div style='margin:2px 0'>{_sev_badge(k)} <strong>{v}</strong></div>"
        for k, v in counts.items()
    )

    diff_counts = capability_diff.get("counts") or {}
    baseline_summary = report.get("baseline")
    baseline_html = ""
    if baseline_summary:
        baseline_html = (
            f"<div class='kv'>"
            f"<dt>New</dt><dd>{baseline_summary.get('new', 0)}</dd>"
            f"<dt>Existing</dt><dd>{baseline_summary.get('existing', 0)}</dd>"
            f"<dt>Resolved</dt><dd>{baseline_summary.get('resolved', 0)}</dd>"
            f"<dt>New high+critical</dt><dd>{baseline_summary.get('new_high_critical', 0)}</dd>"
            f"</div>"
        )

    body = f"""
    <section class='hero'>
      {html_kit.kpi("Overall AI Risk Score", html_kit.risk_gauge(trust.get('overall_ai_risk_score')), accent='#0f766e')}
      {html_kit.kpi("Files Scanned", report.get('files_scanned', 0), accent='#2563eb')}
      {html_kit.kpi("Findings", len(findings), accent='#dc2626')}
      {html_kit.kpi("Frameworks", escape(', '.join(frameworks) if frameworks else 'None'), f"{len(report.get('mcp_assets', []))} MCP assets", accent='#7c3aed')}
    </section>
    <section class='hero'>
      <div class='card'><h3>Risk Summary</h3>{severity_counts}</div>
      <div class='card'><h3>Components</h3><div>{len(components)}</div><div class='muted'>Diagnostics: {len(diagnostics)}</div><div class='muted'>Capability diff: {escape(str(diff_counts or 'N/A'))}</div></div>
      <div class='card'><h3>Baseline</h3>{baseline_html or "<div class='muted'>No baseline supplied.</div>"}</div>
    </section>

    {_brief_section(report)}

    {_assurance_section(report)}

    {_found_section(report)}

    {_actions_section(report)}

    {_changes_section(report)}

    {_authority_section(report)}

    {_confidence_section(report)}

    <h2>Executive Summary</h2>
    <div class='card'><p>{escape("SafeAI scanned " + str(report.get("files_scanned", 0)) + " files" + (" for " + ", ".join(frameworks) if frameworks else "") + " and produced " + str(len(findings)) + " findings.")}</p>
    <p class='muted'>All results are static analysis evidence from source/configuration - they do not verify deployed runtime permissions, identities, or behavior.</p></div>

    <h2>Trust Scores</h2>
    {html_kit.data_table(["Category", "Score"], trust_rows, empty="No category scores.", searchable=False)}

    <h2>Capability Matrix</h2>
    {html_kit.data_table(["Capability", "Category", "Frameworks", "Confidence", "Evidence"], capability_rows, empty="No capabilities detected.")}

    {_architecture_table(report.get('component_graph', {})) if include_architecture else ''}
    {_architecture_mermaid(report.get('component_graph', {})) if include_architecture and include_mermaid else ''}

    {_escalation_section(report)}

    {_dependency_section(report)}

    <h2>Governance Summary</h2>
    {html_kit.data_table(
        ["Rule", "Category", "Message", "Recommendation"],
        [[f.get('rule_id', ''), f.get('risk_category', ''), f.get('message', ''), f.get('remediation', '')] for f in governance_summary],
        empty="No governance findings.",
    )}

    <h2>Failure-Class Coverage Matrix</h2>
    <p class='muted'>Groups governance findings by the class of failure they leave the agent unprepared for. A class is "uncovered" if any of its associated controls are missing.</p>
    {html_kit.data_table(
        ["Failure Class", "Status", "Description", "Uncovered Controls"],
        [[
            entry["failure_class"],
            '<span style="color:#dc2626">Uncovered</span>' if entry["status"] == "uncovered" else '<span style="color:#16a34a">Covered</span>',
            entry["description"],
            ", ".join(entry["covered_rules"]) or "—",
        ] for entry in failure_matrix],
        empty="No governance controls to evaluate.",
    )}

    <h2>Findings</h2>
    {html_kit.data_table(
        ["Severity", "Status", "Rule", "Category", "Location", "Message", "Evidence", "Recommendation"],
        [[
            f.get('severity', 'info'),
            f.get('status', ''),
            f.get('rule_id', ''),
            f.get('risk_category', ''),
            f"{f.get('file', '')}:{f.get('line', 1)}",
            f.get('message', ''),
            f.get('evidence', ''),
            f.get('remediation', ''),
        ] for f in findings],
        empty="No findings.",
    )}

    {_kya_section(report)}

    {_tool_surface_section(report)}
    """

    html = html_kit.page(
        title="SafeAI Early Preview Report",
        subtitle=escape(", ".join(frameworks) if frameworks else ""),
        body=body,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        footer="SafeAI - static AI capability & risk analysis. No source code or secrets are uploaded or stored in this file.",
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
