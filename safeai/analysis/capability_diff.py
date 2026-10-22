"""Tool-centric comparison of capability inventories between scan reports.

v1.3 keyed capabilities on ``(name, category)``. A repository whose
``invoice-lookup`` MCP server flipped from read-only to mutating showed
**no diff at all**, because the capability ``mcp`` was present before and
after. That is precisely the change a reviewer needs to see.

v1.4 keys on the triple ``(tool_key, capability_name, access_mode)`` and
reports per tool: what it gained, what it lost, how its access modes
moved, and which escalation rules fired.

Backward compatibility: the returned document still carries the v1 flat
``added``/``removed``/``changed``/``counts`` fields (also mirrored under
``legacy``) so v1.3 consumers, reports and tests keep working.
"""

from safeai.analysis.capabilities import access_mode_rank
from safeai.analysis.escalation import (
    DATA_NAMES,
    DESTINATION_NAMES,
    access_change_inferred,
    access_change_provenance,
    classify_escalations,
    highest_severity,
)
from safeai.analysis.tool_identity import UNATTRIBUTED_KEY
from safeai.analysis.tool_surface import build_tool_surface, surface_index
from safeai.severity import ESCALATION_SEVERITIES

CAPABILITY_DIFF_SCHEMA_VERSION = 2

_SEVERITIES = tuple(reversed(ESCALATION_SEVERITIES))


def _key(capability):
    return (
        str(capability.get("name", "capability")).lower(),
        str(capability.get("category", "Capability")).lower(),
    )


def compute_legacy_capability_diff(current_report, baseline_report):
    """The exact v1.3 flat diff, preserved for existing consumers.

    A baseline that carries no capability inventory (e.g. a KYA manifest,
    which stores the tool surface instead) yields an explicitly
    unavailable legacy block rather than a diff in which every existing
    capability looks new.
    """
    if "normalized_capabilities" not in (baseline_report or {}):
        return {
            "baseline_available": False,
            "reason": "baseline document carries no capability inventory",
            "added": [],
            "removed": [],
            "changed": [],
            "counts": {"added": 0, "removed": 0, "changed": 0},
        }
    current = {_key(cap): cap for cap in current_report.get("normalized_capabilities", [])}
    baseline = {_key(cap): cap for cap in baseline_report.get("normalized_capabilities", [])}

    added = [current[key] for key in sorted(current.keys() - baseline.keys())]
    removed = [baseline[key] for key in sorted(baseline.keys() - current.keys())]
    changed = []
    for key in sorted(current.keys() & baseline.keys()):
        before = baseline[key]
        after = current[key]
        fields = {}
        for field in ("confidence", "risk_weight", "source_frameworks", "sources", "evidence"):
            if before.get(field) != after.get(field):
                fields[field] = {"before": before.get(field), "after": after.get(field)}
        if fields:
            changed.append({"key": {"name": after.get("name"), "category": after.get("category")}, "changes": fields})

    return {
        "baseline_available": True,
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def _resolve_surface(report):
    """Return ``(surface, attributed)`` for a report.

    A pre-1.4 baseline has no ``tool_surface``; we say so rather than
    fabricating attribution from capability names.
    """
    surface = report.get("tool_surface")
    if isinstance(surface, list):
        return surface, True
    return [], False


def _capability_view(capability):
    return {
        "name": capability.get("name"),
        "category": capability.get("category"),
        "access_mode": capability.get("access_mode"),
        "evidence": capability.get("evidence") or [],
        "confidence": capability.get("confidence"),
        "inferred": bool(capability.get("inferred")),
    }


def _status_for(before_state, after_state):
    """Structural status of a tool, independent of the escalation ruleset."""
    if before_state is None:
        return "new"
    if after_state is None:
        return "removed"
    before_caps = {c["name"]: c for c in before_state.get("capabilities") or []}
    after_caps = {c["name"]: c for c in after_state.get("capabilities") or []}
    gained = set(after_caps) - set(before_caps)
    lost = set(before_caps) - set(after_caps)
    raised = any(
        access_mode_rank(after_caps[n].get("access_mode")) > access_mode_rank(before_caps[n].get("access_mode"))
        for n in set(after_caps) & set(before_caps)
    )
    lowered = any(
        access_mode_rank(after_caps[n].get("access_mode")) < access_mode_rank(before_caps[n].get("access_mode"))
        for n in set(after_caps) & set(before_caps)
    )
    if gained or raised:
        return "escalated"
    if lost or lowered:
        return "reduced"
    return "unchanged"


#: Material-change classification vocabulary (conceptual classes, never a
#: numerical score). UNKNOWN means the baseline lacked attribution, so the
#: change cannot be classified — unknown is an evidence state, and it never
#: fails a gate on its own.
CHANGE_CLASSES = (
    "NO_CHANGE",
    "LOW_CHANGE",
    "MATERIAL_CHANGE",
    "HIGH_RISK_CHANGE",
    "UNKNOWN",
)
_CHANGE_RANK = {name: index for index, name in enumerate(CHANGE_CLASSES)}


def change_class_for(status, escalations, access_mode_changes, added):
    """Classify one tool entry's authority change.

    Deterministic and structural: HIGH_RISK on any critical escalation,
    MATERIAL on new/escalated authority (new tool, gained capability,
    widened access), LOW on shrunk authority, NO_CHANGE when unchanged,
    UNKNOWN when the status itself is unknowable.
    """
    if status in (None, "unknown"):
        return "UNKNOWN"
    if status == "unchanged":
        return "NO_CHANGE"
    if status in ("reduced", "removed"):
        return "LOW_CHANGE"
    if any(str(e.get("severity", "")).lower() == "critical" for e in escalations or []):
        return "HIGH_RISK_CHANGE"
    if status in ("new", "escalated") and (added or access_mode_changes or escalations):
        return "MATERIAL_CHANGE"
    if status in ("new", "escalated"):
        return "LOW_CHANGE"
    return "UNKNOWN"


def _inferred_only(added, access_mode_changes):
    """True when every structural change signal is inferred evidence.

    Inferred-only changes print as review questions; they never fail a
    Lane-A deterministic gate on their own.
    """
    signals = list(added or []) + list(access_mode_changes or [])
    if not signals:
        return False
    return all(bool(s.get("inferred")) for s in signals)


#: Semantic authority change types, derived from tool status + escalation
#: ids (never from severity). Only types with observable signals exist:
#: infrastructure, credential-scope, and prompt/definition changes have no
#: per-tool signal yet and are intentionally absent.
CHANGE_TYPES = (
    "AUTHORITY_ADDED",
    "AUTHORITY_ESCALATED",
    "AUTHORITY_REDUCED",
    "AUTHORITY_REMOVED",
    "DESTINATION_ADDED",
    "DATA_REACH_EXPANDED",
    "APPROVAL_REMOVED",
    "AUTONOMY_INCREASED",
    "DELEGATION_ADDED",
    "UNKNOWN_CHANGE",
)

_ESCALATION_CHANGE_TYPE = {
    "ESC_SHELL_ADDED": "AUTHORITY_ADDED",
    "ESC_MCP_SERVER_ADDED": "AUTHORITY_ADDED",
    "ESC_WRITE_TOOL_ADDED": "AUTHORITY_ADDED",
    "ESC_ACCESS_MODE_INCREASED": "AUTHORITY_ESCALATED",
    "ESC_FILESYSTEM_WRITE_ADDED": "AUTHORITY_ESCALATED",
    "ESC_MCP_READ_TO_MUTATE": "AUTHORITY_ESCALATED",
    "ESC_EXTERNAL_ACCESS_ADDED": "DESTINATION_ADDED",
    "ESC_NEW_EXTERNAL_DESTINATION": "DESTINATION_ADDED",
    "ESC_MEMORY_SCOPE_EXPANDED": "DATA_REACH_EXPANDED",
    "ESC_APPROVAL_GATE_REMOVED": "APPROVAL_REMOVED",
    "ESC_AUTONOMY_INCREASED": "AUTONOMY_INCREASED",
    "ESC_COMBO_UNTRUSTED_INPUT_SHELL": "AUTHORITY_ESCALATED",
    "ESC_COMBO_AUTONOMY_BROAD_DATA": "AUTONOMY_INCREASED",
    "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT": "DELEGATION_ADDED",
}

_STATUS_CHANGE_TYPE = {
    "new": "AUTHORITY_ADDED",
    "escalated": "AUTHORITY_ESCALATED",
    "reduced": "AUTHORITY_REDUCED",
    "removed": "AUTHORITY_REMOVED",
    "unchanged": None,
    "unknown": "UNKNOWN_CHANGE",
}


def change_types_for(status, escalations):
    """Derive semantic change types for one tool entry.

    Escalation ids map to their semantic type; the structural status
    supplies the fallback (new → ADDED, reduced → REDUCED, ...).
    Unmapped escalation ids contribute nothing — severity never creates
    a type. Returns a sorted list (possibly empty for unchanged tools).
    """
    types = set()
    for escalation in escalations or []:
        mapped = _ESCALATION_CHANGE_TYPE.get(str(escalation.get("id") or ""))
        if mapped:
            types.add(mapped)
    fallback = _STATUS_CHANGE_TYPE.get(status)
    if fallback:
        types.add(fallback)
    elif status not in ("unchanged", None):
        types.add("UNKNOWN_CHANGE")
    types.discard(None)
    return sorted(types)
def _cap_provenance(cap):
    return "inferred" if cap.get("inferred") else "detected"


def authority_for(after_caps, escalations):
    """Build the per-tool authority dimension block.

    Every dimension carries its own provenance; dimensions with no
    observable signal are ``unknown`` — never guessed. In particular,
    ``credential`` has no per-tool signal yet and ``identity`` is
    unobservable to static analysis, so both are always unknown here.
    """
    after_caps = after_caps or []
    esc_ids = {str(e.get("id") or "") for e in escalations or []}

    def _matching(names):
        matched = [
            c for c in after_caps
            if str(c.get("name") or "").lower() in names
            or str(c.get("category") or "").lower() in names
        ]
        return matched

    dest_caps = _matching(DESTINATION_NAMES)
    data_caps = _matching(DATA_NAMES)

    def _list_dim(caps):
        if not caps:
            return {"values": [], "provenance_class": "unknown"}
        prov = "inferred" if all(c.get("inferred") for c in caps) else "detected"
        return {"values": sorted({str(c.get("name")) for c in caps if c.get("name")}),
                "provenance_class": prov}

    def _flag_dim(present, state):
        if present:
            return {"state": state, "provenance_class": "detected"}
        return {"state": "unknown", "provenance_class": "unknown"}

    return {
        "capabilities": [
            {"name": c.get("name"), "access_mode": c.get("access_mode"),
             "provenance_class": _cap_provenance(c)}
            for c in sorted(after_caps, key=lambda c: str(c.get("name")))
            if c.get("name")
        ],
        "destinations": _list_dim(dest_caps),
        "data_scope": _list_dim(data_caps),
        "approval": _flag_dim("ESC_APPROVAL_GATE_REMOVED" in esc_ids, "removed"),
        "autonomy": _flag_dim("ESC_AUTONOMY_INCREASED" in esc_ids, "increased"),
        "delegation": _flag_dim(
            "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT" in esc_ids, "present"),
        "credential": {"state": "unknown", "provenance_class": "unknown"},
        "identity": {"state": "unknown", "provenance_class": "unknown"},
    }


def authority_unknown():
    """All-unknown authority block for removed tools (no after-state)."""
    return {
        "capabilities": [],
        "destinations": {"values": [], "provenance_class": "unknown"},
        "data_scope": {"values": [], "provenance_class": "unknown"},
        "approval": {"state": "unknown", "provenance_class": "unknown"},
        "autonomy": {"state": "unknown", "provenance_class": "unknown"},
        "delegation": {"state": "unknown", "provenance_class": "unknown"},
        "credential": {"state": "unknown", "provenance_class": "unknown"},
        "identity": {"state": "unknown", "provenance_class": "unknown"},
    }


def authority_gate_tripped(tools, threshold):
    """True when a tool authority change meets a `--fail-on-authority-change`
    threshold (``"material"`` or ``"high-risk"``).

    Inferred-only changes never trip the gate; UNKNOWN never trips it:
    unknown is an evidence state, not evidence of unsafety.
    """
    threshold_rank = {"material": 2, "high-risk": 3}[threshold]
    for tool in tools or []:
        cls = tool.get("change_class", "UNKNOWN")
        # UNKNOWN is unrankable by construction: it never trips a gate.
        rank = -1 if cls == "UNKNOWN" else _CHANGE_RANK.get(cls, -1)
        if rank >= threshold_rank and not tool.get("inferred_only"):
            return True
    return False


def _tool_entry(tool_key_value, before_state, after_state,
evaluate_combinations):
    status = _status_for(before_state, after_state)
    before_caps = {c["name"]: c for c in (before_state or {}).get("capabilities") or []}
    after_caps = {c["name"]: c for c in (after_state or {}).get("capabilities") or []}

    added = [_capability_view(after_caps[n]) for n in sorted(set(after_caps) - set(before_caps))]
    removed = [_capability_view(before_caps[n]) for n in sorted(set(before_caps) - set(after_caps))]
    access_mode_changes = []
    for name in sorted(set(after_caps) & set(before_caps)):
        before, after = before_caps[name], after_caps[name]
        if before.get("access_mode") != after.get("access_mode"):
            provenance = access_change_provenance(before, after)
            access_mode_changes.append({
                "capability": name,
                "before": before.get("access_mode"),
                "after": after.get("access_mode"),
                "inferred": access_change_inferred(before, after),
                **provenance,
            })

    escalations = classify_escalations(
        before_state, after_state, status, evaluate_combinations=evaluate_combinations
    )
    reference = after_state or before_state or {}
    after_caps = (after_state or {}).get("capabilities") or []
    return {
        "tool_key": tool_key_value,
        "tool": reference.get("tool") or {"kind": "unknown", "name": None, "framework": None},
        "status": status,
        "change_class": change_class_for(status, escalations, access_mode_changes, added),
        "change_types": change_types_for(status, escalations),
        "authority": authority_for(after_caps, escalations) if after_state is not None
        else authority_unknown(),
        "inferred_only": _inferred_only(added, access_mode_changes),
        "access_summary": {
            "before": (before_state or {}).get("access_summary"),
            "after": (after_state or {}).get("access_summary"),
        },
        "capabilities_added": added,
        "capabilities_removed": removed,
        "access_mode_changes": access_mode_changes,
        "escalations": escalations,
    }


def compute_capability_diff(current_report, baseline_report):
    """Compare two reports, tool by tool.

    The comparison is deterministic and uses only serialized report data:
    no file access, no execution, no network.
    """
    legacy = compute_legacy_capability_diff(current_report, baseline_report)

    current_surface, current_attributed = _resolve_surface(current_report)
    baseline_surface, baseline_attributed = _resolve_surface(baseline_report)

    if not current_attributed:
        current_surface = build_tool_surface(current_report)
        current_attributed = True

    current_index = surface_index(current_surface)
    baseline_index = surface_index(baseline_surface)

    # Without baseline attribution every tool would look "new". Say so and
    # fall back to the capability-level view instead of misleading the
    # reviewer with a fabricated tool diff.
    tool_keys = sorted(set(current_index) | set(baseline_index))

    tools = []
    unattributed = None
    counts = {
        "tools_new": 0,
        "tools_escalated": 0,
        "tools_reduced": 0,
        "tools_removed": 0,
        "tools_unchanged": 0,
        "escalations_by_severity": {sev: 0 for sev in _SEVERITIES},
    }
    all_escalations = []

    for key in tool_keys:
        before_state = baseline_index.get(key) if baseline_attributed else None
        after_state = current_index.get(key)
        if before_state is None and after_state is None:
            continue
        evaluate_combinations = True
        entry = _tool_entry(key, before_state, after_state, evaluate_combinations)

        if not baseline_attributed:
            # Structural status is unknowable; report the surface without
            # asserting that the tool is new.
            entry["status"] = "unknown"
            entry["capabilities_added"] = []
            entry["escalations"] = [
                e for e in entry["escalations"]
                if e["id"].startswith("ESC_COMBO_")
            ]
            entry["change_class"] = change_class_for(
                "unknown", entry["escalations"], [], [])
            entry["change_types"] = change_types_for("unknown", entry["escalations"])
            entry["authority"] = authority_unknown()
            entry["inferred_only"] = False

        if entry["status"] != "unchanged" or entry["escalations"]:
            all_escalations.extend(entry["escalations"])
            for escalation in entry["escalations"]:
                severity = escalation["severity"]
                counts["escalations_by_severity"][severity] = (
                    counts["escalations_by_severity"].get(severity, 0) + 1
                )

        status_counter = {
            "new": "tools_new",
            "escalated": "tools_escalated",
            "reduced": "tools_reduced",
            "removed": "tools_removed",
            "unchanged": "tools_unchanged",
        }.get(entry["status"])
        if status_counter:
            counts[status_counter] += 1

        if key == UNATTRIBUTED_KEY:
            unattributed = entry
        else:
            tools.append(entry)

    tools.sort(key=lambda t: t["tool_key"])

    change_counts = {cls: 0 for cls in CHANGE_CLASSES}
    for entry in tools:
        change_counts[entry.get("change_class", "UNKNOWN")] += 1
    if unattributed and unattributed.get("change_class") in change_counts:
        change_counts[unattributed["change_class"]] += 1
    highest_change = "NO_CHANGE"
    for entry in tools:
        cls = entry.get("change_class", "UNKNOWN")
        if cls != "UNKNOWN" and _CHANGE_RANK.get(cls, 0) > _CHANGE_RANK[highest_change]:
            highest_change = cls

    result = {
        "schema_version": CAPABILITY_DIFF_SCHEMA_VERSION,
        "baseline_available": True,
        "baseline_tool_attribution": bool(baseline_attributed),
        "tools": tools,
        "unattributed": unattributed,
        "counts": {**counts, **legacy["counts"], "by_change_class": change_counts},
        "highest_escalation": highest_severity(all_escalations),
        "highest_change_class": highest_change,
        "legacy": legacy,
        # v1 fields kept at the top level for backward compatibility.
        "added": legacy["added"],
        "removed": legacy["removed"],
        "changed": legacy["changed"],
    }
    return result
