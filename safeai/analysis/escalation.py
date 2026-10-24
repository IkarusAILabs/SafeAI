"""Declarative escalation classification.

An *escalation* is a change in which a named tool acquired more authority
than it had in the baseline — or, for combination rules, a post-change
state in which individually-benign authorities combine into a dangerous
one.

The ruleset is a **data table** evaluated by a small handler registry,
not an ``if/elif`` chain. That keeps every rule independently testable
and lets the table move to YAML in a later release without touching the
evaluator.

Determinism contract: rules are evaluated in table order (generic
``access_increase`` rules last, so specific rules subsume them), evidence
is sorted, and no rule reads anything outside the two states it is given.
"""

from safeai.analysis.capabilities import (
    access_mode_rank,
    is_escalation,
    max_access_mode,
)
from safeai.analysis.escalation_remediation import remediation_for
from safeai.severity import ESCALATION_SEVERITIES
from safeai.severity import rank as severity_rank

_ESCALATION_SEVERITY_SET = frozenset(ESCALATION_SEVERITIES)

#: Severity ceiling applied when a rule fired on an *inferred* access mode.
#: Static inference must never produce a "critical" verdict on its own.
INFERRED_SEVERITY_CAP = "medium"

# --- Category vocabularies (data shared by several rules) ---------------

SHELL_CATEGORIES = {"shell", "container"}
SHELL_NAMES = {"shell", "code_exec", "subprocess_shell", "exec", "command", "bash"}
FILESYSTEM_NAMES = {"filesystem", "file", "fs"}
EXTERNAL_NAMES = {"external_apis", "http", "api", "network"}
MEMORY_NAMES = {"memory", "rag", "vector", "knowledge"}
APPROVAL_NAMES = {"human_approval", "approval", "hitl"}
AUTONOMY_NAMES = {"planner", "delegation", "multi_agent", "autonomy", "handoff"}
UNTRUSTED_NAMES = {"untrusted_input", "argument_injection", "user_input"}
DESTINATION_NAMES = {
    "filesystem", "databases", "cloud", "github", "slack", "email",
    "external_apis", "s3", "blob",
}
DATA_NAMES = {"databases", "rag", "memory", "cloud"}
SIDE_EFFECT_MODES = {"write", "mutate", "execute"}


def _matches(capability, names):
    """True when a capability's name or category falls in ``names``."""
    name = str(capability.get("name") or "").strip().lower()
    category = str(capability.get("category") or "").strip().lower().replace(" ", "_")
    if name in names or category in names:
        return True
    # MCP synthesises ``mcp_tool:<name>`` entries; match on the bare stem too.
    stem = name.split(":", 1)[-1]
    return stem in names


def _caps_matching(state, names):
    return [c for c in (state.get("capabilities") or []) if _matches(c, names)]


def _evidence_for(caps):
    seen = []
    for cap in caps:
        for item in cap.get("evidence") or []:
            entry = {"path": item.get("path"), "line": int(item.get("line") or 0)}
            if entry not in seen:
                seen.append(entry)
    return sorted(seen, key=lambda e: (e.get("path") or "", e.get("line")))[:5]


def _names(caps):
    return sorted({str(c.get("name")) for c in caps})


# --- Trigger handlers ---------------------------------------------------
# Each handler takes (rule, ctx) and returns a list of match dicts:
#   {"summary", "before", "after", "evidence", "inferred", "confidence"}


def _h_capability_added(rule, ctx):
    names = rule["names"]
    matched = [c for c in ctx["added"] if _matches(c, names)]
    if rule.get("min_access"):
        floor = access_mode_rank(rule["min_access"])
        matched = [c for c in matched if access_mode_rank(c.get("access_mode")) >= floor]
    if not matched:
        return []
    return [{
        "summary": rule["summary"].format(names=", ".join(_names(matched))),
        "before": "absent",
        "after": ", ".join(f"{c['name']} ({c.get('access_mode')})" for c in matched),
        "evidence": _evidence_for(matched),
        "inferred": all(bool(c.get("inferred")) for c in matched),
        "confidence": _confidence(matched),
    }]


def _h_capability_removed(rule, ctx):
    names = rule["names"]
    matched = [c for c in ctx["removed"] if _matches(c, names)]
    if not matched:
        return []
    return [{
        "summary": rule["summary"].format(names=", ".join(_names(matched))),
        "before": ", ".join(_names(matched)),
        "after": "absent",
        "evidence": _evidence_for(matched),
        "inferred": all(bool(c.get("inferred")) for c in matched),
        "confidence": _confidence(matched),
    }]


def _access_increase_matches(rule, ctx):
    """Match an ``access_increase`` rule against the change context.

    Returns ``(matched_changes, new_at_level, evidence_caps)`` where
    ``evidence_caps`` holds only the capabilities the rule actually
    speaks for: filtered by name for specific rules, and restricted to
    the capabilities that increased for the nameless generic rule (so its
    evidence and confidence never borrow from unrelated capabilities).
    """
    names = rule.get("names")
    floor = access_mode_rank(rule.get("min_after", "write"))
    if names:
        matched = [
            change for change in ctx["access_changes"]
            if _matches({"name": change["capability"], "category": change.get("category")}, names)
            and access_mode_rank(change["after"]) >= floor
        ]
        new_at_level = [
            c for c in ctx["added"]
            if _matches(c, names) and access_mode_rank(c.get("access_mode")) >= floor
        ]
        caps = [c for c in ctx["after"].get("capabilities") or [] if _matches(c, names)]
    else:
        matched = [
            change for change in ctx["access_changes"]
            if access_mode_rank(change["after"]) >= floor
        ]
        new_at_level = [
            c for c in ctx["added"]
            if access_mode_rank(c.get("access_mode")) >= floor
        ]
        changed_names = {c["capability"] for c in matched} | {str(c.get("name")) for c in new_at_level}
        caps = [
            c for c in ctx["after"].get("capabilities") or []
            if str(c.get("name")) in changed_names
        ]
    return matched, new_at_level, caps


def _h_access_increase(rule, ctx):
    matched, new_at_level, caps = _access_increase_matches(rule, ctx)
    # A capability that is newly present at write+ is also an increase.
    if not matched and not new_at_level:
        return []
    before = ", ".join(sorted({c["before"] for c in matched})) or "absent"
    after = ", ".join(sorted(
        {c["after"] for c in matched} | {str(c.get("access_mode")) for c in new_at_level}
    ))
    contributors = list(matched) + list(new_at_level)
    inferred = bool(contributors) and all(bool(c.get("inferred")) for c in contributors)
    label = ", ".join(sorted({c["capability"] for c in matched} | set(_names(new_at_level))))
    return [{
        "summary": rule["summary"].format(names=label),
        "before": before,
        "after": after,
        "evidence": _evidence_for(caps or new_at_level),
        "inferred": bool(inferred),
        "confidence": _confidence(caps or new_at_level),
    }]


def _h_tool_new(rule, ctx):
    if ctx["status"] != "new":
        return []
    kinds = rule.get("kinds")
    kind = (ctx["after"].get("tool") or {}).get("kind")
    if kinds and kind not in kinds:
        return []
    floor = access_mode_rank(rule.get("min_access", "none"))
    caps = ctx["after"].get("capabilities") or []
    summary = ctx["after"].get("access_summary") or max_access_mode(
        c.get("access_mode") for c in caps
    )
    if access_mode_rank(summary) < floor:
        return []
    return [{
        "summary": rule["summary"].format(
            name=(ctx["after"].get("tool") or {}).get("name") or ctx["after"].get("tool_key"),
            mode=summary,
        ),
        "before": "not present in baseline",
        "after": f"{summary} access",
        "evidence": _evidence_for(caps),
        "inferred": bool(caps) and all(bool(c.get("inferred")) for c in caps),
        "confidence": _confidence(caps),
    }]


def _h_combination(rule, ctx):
    before_state = ctx.get("before") or {}
    after_state = ctx["after"]

    def _groups_for(state):
        matched_groups = []
        for group in rule["groups"]:
            caps = _caps_matching(state, group["names"])
            floor = access_mode_rank(group.get("min_access", "none"))
            caps = [c for c in caps if access_mode_rank(c.get("access_mode")) >= floor]
            if not caps:
                return []
            matched_groups.append(caps)
        return matched_groups

    matched_groups_after = _groups_for(after_state)
    if not matched_groups_after:
        return []
    if _groups_for(before_state):
        return []

    flat = [c for group in matched_groups_after for c in group]
    return [{
        "summary": rule["summary"].format(names=", ".join(_names(flat))),
        "before": "absent",
        "after": ", ".join(f"{c['name']} ({c.get('access_mode')})" for c in flat),
        "evidence": _evidence_for(flat),
        "inferred": all(bool(c.get("inferred")) for c in flat),
        "confidence": _confidence(flat),
    }]


TRIGGER_HANDLERS = {
    "capability_added": _h_capability_added,
    "capability_removed": _h_capability_removed,
    "access_increase": _h_access_increase,
    "tool_new": _h_tool_new,
    "combination": _h_combination,
}


# --- The rule table -----------------------------------------------------

ESCALATION_RULES = [
    {
        "id": "ESC_SHELL_ADDED",
        "severity": "critical",
        "trigger": "capability_added",
        "names": SHELL_CATEGORIES | SHELL_NAMES,
        "summary": "Gained shell/code-execution capability ({names})",
    },
    {
        "id": "ESC_ACCESS_MODE_INCREASED",
        "severity": "high",
        "trigger": "access_increase",
        "min_after": "write",
        "summary": "Access mode widened to write/mutate/execute ({names})",
    },
    {
        "id": "ESC_FILESYSTEM_WRITE_ADDED",
        "severity": "high",
        "trigger": "access_increase",
        "names": FILESYSTEM_NAMES,
        "min_after": "write",
        "summary": "Filesystem access widened to write/mutate ({names})",
    },
    {
        "id": "ESC_EXTERNAL_ACCESS_ADDED",
        "severity": "high",
        "trigger": "capability_added",
        "names": EXTERNAL_NAMES,
        "summary": "Gained external HTTP/API access ({names})",
    },
    {
        "id": "ESC_MCP_SERVER_ADDED",
        "severity": "high",
        "trigger": "tool_new",
        "kinds": {"mcp_server"},
        "summary": "New MCP server bound: {name}",
    },
    {
        "id": "ESC_MCP_READ_TO_MUTATE",
        "severity": "critical",
        "trigger": "access_increase",
        "names": {"mcp"},
        "min_after": "write",
        "kinds": {"mcp_server"},
        "statuses": {"escalated", "reduced", "unchanged"},
        "summary": "MCP server gained mutating tools ({names})",
    },
    {
        "id": "ESC_APPROVAL_GATE_REMOVED",
        "severity": "critical",
        "trigger": "capability_removed",
        "names": APPROVAL_NAMES,
        "summary": "Human-approval gate removed ({names})",
    },
    {
        "id": "ESC_MEMORY_SCOPE_EXPANDED",
        "severity": "medium",
        "trigger": "access_increase",
        "names": MEMORY_NAMES,
        "min_after": "write",
        "summary": "Memory/RAG scope broadened ({names})",
    },
    {
        "id": "ESC_WRITE_TOOL_ADDED",
        "severity": "high",
        "trigger": "tool_new",
        "min_access": "write",
        "summary": "New tool with {mode} authority: {name}",
    },
    {
        "id": "ESC_NEW_EXTERNAL_DESTINATION",
        "severity": "high",
        "trigger": "capability_added",
        "names": DESTINATION_NAMES,
        "min_access": "write",
        "summary": "New write destination reachable ({names})",
    },
    {
        "id": "ESC_AUTONOMY_INCREASED",
        "severity": "high",
        "trigger": "capability_added",
        "names": AUTONOMY_NAMES,
        "requires_side_effect": True,
        "summary": "Planner/delegation added to a tool with side effects ({names})",
    },
    {
        "id": "ESC_COMBO_UNTRUSTED_INPUT_SHELL",
        "severity": "critical",
        "trigger": "combination",
        "groups": [
            {"names": UNTRUSTED_NAMES},
            {"names": SHELL_CATEGORIES | SHELL_NAMES, "min_access": "execute"},
        ],
        "summary": "Untrusted input reaches a tool with shell/exec authority ({names})",
    },
    {
        "id": "ESC_COMBO_AUTONOMY_BROAD_DATA",
        "severity": "high",
        "trigger": "combination",
        "groups": [
            {"names": AUTONOMY_NAMES},
            {"names": DATA_NAMES, "min_access": "read"},
        ],
        "summary": "Autonomous planning combined with broad data access ({names})",
    },
    {
        "id": "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT",
        "severity": "high",
        "trigger": "combination",
        "groups": [
            {"names": {"delegation", "multi_agent", "handoff"}},
            {"names": DESTINATION_NAMES, "min_access": "write"},
        ],
        "summary": "Delegation combined with an external write side effect ({names})",
    },
]

COMBINATION_RULE_IDS = tuple(
    rule["id"] for rule in ESCALATION_RULES if rule["trigger"] == "combination"
)


def _confidence(caps):
    """Aggregate a ``high|medium|low`` confidence label for the evidence."""
    if not caps:
        return "low"
    values = [float(c.get("confidence") or 0.6) for c in caps]
    lowest = min(values)
    if lowest >= 0.8:
        return "high"
    if lowest >= 0.5:
        return "medium"
    return "low"


def cap_severity(severity, inferred):
    """Apply the inference ceiling to a rule's default severity."""
    if not inferred:
        return severity
    if severity_rank(severity) > severity_rank(INFERRED_SEVERITY_CAP):
        return INFERRED_SEVERITY_CAP
    return severity


def access_change_inferred(before_cap, after_cap):
    """True when either side of a transition rests on inferred evidence.

    This is ADR-0008's rule and the disjunction is the point. An access-mode
    transition is a claim about *both* sides, so a baseline that only guessed
    ``read`` cannot support the claim that the tool widened to ``mutate``.
    Relaxing it would let an inferred baseline block, which ADR-0008 forbids
    in any release.

    The false positive the rule buys is concrete: a SafeAI upgrade, or a
    refactor that improves detection, lets the current scan *detect* an access
    mode the baseline only guessed. Nothing about the tool's authority
    changed, yet the transition would read as a confirmed widening and fail
    ``--fail-on-authority-change`` for everyone carrying an older baseline.
    The scanner cannot tell that case from a real widening; that uncertainty
    is exactly what the ``inferred`` flag records.

    The detected current state is still reported, as its own signal rather
    than as a change: see :func:`access_change_provenance` for the per-side
    provenance, and ``authority_for`` in ``safeai.analysis.capability_diff``,
    which publishes the current state's access with its own provenance class.
    """
    provenance = access_change_provenance(before_cap, after_cap)
    return provenance["before_inferred"] or provenance["after_inferred"]


def access_change_provenance(before_cap, after_cap):
    """Per-side provenance of a single access-mode transition.

    ``before_inferred`` records how well the *baseline* knew the access mode;
    ``after_inferred`` records how well the *current* scan knows the one it
    now reports. The two answer different questions, so they are reported
    separately: a consumer can tell "the old state was guessed" apart from
    "the new state is", which is what makes an asymmetric transition
    reviewable without letting it gate.
    """
    return {
        "before_inferred": bool(before_cap.get("inferred")),
        "after_inferred": bool(after_cap.get("inferred")),
    }


def _side_effect_present(state):
    return any(
        str(c.get("access_mode")) in SIDE_EFFECT_MODES
        for c in state.get("capabilities") or []
    )


def classify_escalations(before_state, after_state, status, evaluate_combinations=True):
    """Return the sorted escalations for one tool's before/after states.

    ``before_state`` is ``None`` for a newly-seen tool. ``after_state`` is
    ``None`` for a removed tool (no escalation can be raised in that case).

    Nameless (generic) ``access_increase`` rules are evaluated **after**
    every specific rule, against only the increases no specific rule
    claimed. One underlying change therefore raises exactly one
    escalation: the most specific applicable rule.
    """
    if after_state is None:
        return []

    before_caps = {c["name"]: c for c in (before_state or {}).get("capabilities") or []}
    after_caps = {c["name"]: c for c in after_state.get("capabilities") or []}

    added = [after_caps[n] for n in sorted(set(after_caps) - set(before_caps))]
    removed = [before_caps[n] for n in sorted(set(before_caps) - set(after_caps))]
    access_changes = []
    for name in sorted(set(after_caps) & set(before_caps)):
        before, after = before_caps[name], after_caps[name]
        if is_escalation(before.get("access_mode"), after.get("access_mode")):
            access_changes.append({
                "capability": name,
                "category": after.get("category"),
                "before": before.get("access_mode"),
                "after": after.get("access_mode"),
                "inferred": access_change_inferred(before, after),
            })

    ctx = {
        "before": before_state or {},
        "after": after_state,
        "status": status,
        "added": added,
        "removed": removed,
        "access_changes": access_changes,
    }

    kind = (after_state.get("tool") or {}).get("kind")
    escalations = []
    generic_rules = []
    covered_changes = set()
    covered_added = set()
    for rule in ESCALATION_RULES:
        if rule["trigger"] == "combination" and not evaluate_combinations:
            continue
        if rule.get("kinds") and kind not in rule["kinds"]:
            continue
        if rule.get("statuses") and status not in rule["statuses"]:
            continue
        if rule.get("requires_side_effect") and not _side_effect_present(after_state):
            continue
        if rule["trigger"] == "access_increase" and not rule.get("names"):
            # Generic rule: defer until specific rules have claimed their
            # capabilities, then evaluate only the unclaimed remainder.
            generic_rules.append(rule)
            continue
        if rule["trigger"] == "access_increase":
            matched, new_at_level, _ = _access_increase_matches(rule, ctx)
            covered_changes.update(c["capability"] for c in matched)
            covered_added.update(str(c.get("name")) for c in new_at_level)
        handler = TRIGGER_HANDLERS[rule["trigger"]]
        for match in handler(rule, ctx):
            severity = cap_severity(rule["severity"], match["inferred"])
            escalations.append({
                "id": rule["id"],
                "severity": severity,
                "summary": match["summary"],
                "before": match["before"],
                "after": match["after"],
                "evidence": match["evidence"],
                "confidence": match["confidence"],
                "inferred": bool(match["inferred"]),
                "remediation": remediation_for(rule["id"]),
            })

    for rule in generic_rules:
        remaining_ctx = dict(ctx)
        remaining_ctx["access_changes"] = [
            c for c in ctx["access_changes"] if c["capability"] not in covered_changes
        ]
        remaining_ctx["added"] = [
            c for c in ctx["added"] if str(c.get("name")) not in covered_added
        ]
        for match in _h_access_increase(rule, remaining_ctx):
            severity = cap_severity(rule["severity"], match["inferred"])
            escalations.append({
                "id": rule["id"],
                "severity": severity,
                "summary": match["summary"],
                "before": match["before"],
                "after": match["after"],
                "evidence": match["evidence"],
                "confidence": match["confidence"],
                "inferred": bool(match["inferred"]),
                "remediation": remediation_for(rule["id"]),
            })

    escalations.sort(key=lambda e: (-severity_rank(e["severity"]), e["id"]))
    return escalations


def highest_severity(escalations):
    """Return the most severe level present, or ``None``."""
    best = None
    for escalation in escalations or []:
        severity = str(escalation.get("severity") or "").lower()
        if severity not in _ESCALATION_SEVERITY_SET:
            continue
        if best is None or severity_rank(severity) > severity_rank(best):
            best = severity
    return best


def access_changes_for(before_state, after_state):
    """Public helper: the list of access-mode transitions between two states.

    Each transition carries ``inferred`` (the ADR-0008 gate) alongside the
    per-side ``before_inferred`` / ``after_inferred`` provenance, so the
    published shape matches what ``capability_diff`` emits.
    """
    before_caps = {c["name"]: c for c in (before_state or {}).get("capabilities") or []}
    after_caps = {c["name"]: c for c in (after_state or {}).get("capabilities") or []}
    changes = []
    for name in sorted(set(after_caps) & set(before_caps)):
        before, after = before_caps[name], after_caps[name]
        if before.get("access_mode") != after.get("access_mode"):
            provenance = access_change_provenance(before, after)
            changes.append({
                "capability": name,
                "before": before.get("access_mode"),
                "after": after.get("access_mode"),
                "inferred": access_change_inferred(before, after),
                **provenance,
            })
    return changes
