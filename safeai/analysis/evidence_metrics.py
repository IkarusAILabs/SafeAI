"""Authority evidence metrics: how much of a scan's authority picture is
evidence-backed, inferred, unattributed, or unknown.

ROADMAP Layer 2 research metric and the P0 "unknown-rate surfacing" gap:
the provenance fields SafeAI already emits are aggregated into a small,
deterministic block attached to the JSON report and the manifest summary.

Rules:
  * Pure and deterministic — identical input yields identical output.
  * Statement and finding metrics are computed from manifest-shaped data
    only (``tool_surface`` entries and finding ``provenance_class``), so an
    independent consumer can recompute them from a manifest without
    SafeAI internals. Authority-dimension metrics need the baseline diff's
    per-tool ``authority`` blocks (attributed tools plus the unattributed
    entry) and are absent without a baseline.
  * Rates follow the benchmark convention: an empty denominator is
    ``insufficient_evidence`` with ``value: None`` — never 0, never 1.
  * Unknown is counted, never reduced or reinterpreted. These metrics
    describe evidence quality; no gate, policy, or score consumes them.
"""

from safeai.analysis.tool_identity import UNATTRIBUTED_KEY
from safeai.kya.contract import PROVENANCE_CLASSES

METRICS_VERSION = 1

#: Per-tool authority dimensions carried by ``capability_diff`` tools
#: (``authority_for`` in ``safeai/analysis/capability_diff.py``).
AUTHORITY_DIMENSIONS = (
    "destinations", "data_scope", "approval", "autonomy",
    "delegation", "credential", "identity",
)

#: Measurements this block deliberately does not make, with the reason.
NOT_MEASURED = (
    {"metric": "false_attribution_rate",
     "reason": "requires annotated ground truth; measured by `safeai benchmark`"},
)


def _ratio(numerator, denominator, reason):
    if denominator <= 0:
        return {"value": None, "status": "insufficient_evidence",
                "numerator": 0, "denominator": 0, "reason": reason}
    return {"value": round(numerator / denominator, 4), "status": "measured",
            "numerator": numerator, "denominator": denominator}


def _capability_statements(tool_surface):
    """Yield ``(tool_key, capability)`` for every authority statement."""
    for tool in tool_surface or []:
        if not isinstance(tool, dict):
            continue
        key = str(tool.get("tool_key") or "")
        for capability in tool.get("capabilities") or []:
            if isinstance(capability, dict):
                yield key, capability


def _statement_counts(tool_surface):
    counts = {"total": 0, "evidence_backed": 0, "inferred": 0,
              "unattributed": 0, "with_evidence_refs": 0}
    for key, capability in _capability_statements(tool_surface):
        inferred = bool(capability.get("inferred"))
        unattributed = key == UNATTRIBUTED_KEY
        has_refs = bool(capability.get("evidence"))
        counts["total"] += 1
        counts["inferred"] += inferred
        counts["unattributed"] += unattributed
        counts["with_evidence_refs"] += has_refs
        counts["evidence_backed"] += (not inferred and not unattributed and has_refs)
    return counts


def _finding_provenance(findings):
    buckets = {cls: 0 for cls in PROVENANCE_CLASSES}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        cls = str(finding.get("provenance_class") or "unknown")
        # An out-of-contract class is not evidence of anything: unknown.
        buckets[cls if cls in buckets else "unknown"] += 1
    return dict(sorted(buckets.items()))


def _authority_dimensions(diff_tools):
    """Unknown counts per authority dimension across diffed tools.

    Returns ``None`` when no diffed tool carries an ``authority`` block
    (no baseline comparison), so the metric is absent rather than empty.
    """
    by_dimension = {dim: {"total": 0, "unknown": 0} for dim in AUTHORITY_DIMENSIONS}
    seen = False
    for tool in diff_tools or []:
        authority = tool.get("authority") if isinstance(tool, dict) else None
        if not isinstance(authority, dict):
            continue
        seen = True
        for dim in AUTHORITY_DIMENSIONS:
            block = authority.get(dim)
            provenance = block.get("provenance_class") if isinstance(block, dict) else None
            by_dimension[dim]["total"] += 1
            by_dimension[dim]["unknown"] += (provenance in (None, "unknown"))
    return by_dimension if seen else None


def _diffed_tools(capability_diff):
    """Attributed tools plus the separately carried unattributed entry."""
    if not isinstance(capability_diff, dict):
        return []
    tools = list(capability_diff.get("tools") or [])
    if isinstance(capability_diff.get("unattributed"), dict):
        tools.append(capability_diff["unattributed"])
    return tools


def compute_evidence_metrics(tool_surface, findings, capability_diff=None):
    """Return the evidence-metrics block for one scan.

    Parameters
    ----------
    tool_surface : list
        Per-tool capability surface (report or manifest ``tool_surface``).
    findings : list
        Findings carrying ``provenance_class`` (report or manifest).
    capability_diff : dict, optional
        The report's ``capability_diff`` from a baseline comparison.
    """
    statements = _statement_counts(tool_surface)
    provenance = _finding_provenance(findings)
    dimensions = _authority_dimensions(_diffed_tools(capability_diff))
    total = statements["total"]
    no_statements = "no authority statements in this scan"

    rates = {
        "evidence_backed_authority_rate": _ratio(
            statements["evidence_backed"], total, no_statements),
        "inferred_authority_rate": _ratio(
            statements["inferred"], total, no_statements),
        "unattributed_authority_rate": _ratio(
            statements["unattributed"], total, no_statements),
        "evidence_completeness": _ratio(
            statements["with_evidence_refs"], total, no_statements),
        "unknown_finding_rate": _ratio(
            provenance["unknown"], sum(provenance.values()),
            "no findings in this scan"),
    }
    if dimensions is None:
        rates["unknown_authority_dimension_rate"] = _ratio(
            0, 0, "no baseline comparison in this scan")
    else:
        rates["unknown_authority_dimension_rate"] = _ratio(
            sum(d["unknown"] for d in dimensions.values()),
            sum(d["total"] for d in dimensions.values()),
            "no diffed tools carry authority dimensions")

    return {
        "metrics_version": METRICS_VERSION,
        "authority_statements": statements,
        "finding_provenance": provenance,
        "authority_dimensions": dimensions,
        "rates": dict(sorted(rates.items())),
        "not_measured": [dict(item) for item in NOT_MEASURED],
    }


def summary_lines(metrics):
    """Short factual lines for human-facing reports (deterministic)."""
    if not isinstance(metrics, dict):
        return []
    rates = metrics.get("rates") or {}

    def fmt(name):
        entry = rates.get(name) or {}
        if entry.get("status") != "measured":
            return "insufficient evidence"
        return "{:.0%} ({}/{})".format(
            entry["value"], entry["numerator"], entry["denominator"])

    lines = [
        "Evidence-backed authority: " + fmt("evidence_backed_authority_rate"),
        "Inferred authority: " + fmt("inferred_authority_rate"),
        "Unattributed authority: " + fmt("unattributed_authority_rate"),
    ]
    if (rates.get("unknown_authority_dimension_rate") or {}).get("status") == "measured":
        lines.append("Unknown authority dimensions: "
                     + fmt("unknown_authority_dimension_rate"))
    return lines
