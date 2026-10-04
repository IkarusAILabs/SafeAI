"""Canonical benchmark truth (v2): implementation-independent gold + projection.

Pipeline::

    Human-reviewed source semantics
              |
    Canonical Gold Truth (this module's schema, ``truth_schema_version``)
              |
    SafeAI scan output
              |
    Canonical SafeAI Projection (``project_report``)
              |
    Comparison (entity / attribution / change / unknown)

The gold truth describes what is actually present in the fixture
(human agents, tools, capabilities, identities, grants and the
relationships between them). It never encodes SafeAI internals such
as ``unknown:unattributed`` tool keys: where the scanner cannot
reconstruct a relationship, gold says so explicitly
(``attribution: unresolved`` / ``resolvable: false``) and the miss is
measured, not hidden.

Design rules:

- Sets compare by neutral keys (names, kinds, namespaces, slugs) —
  never by ``tool_key`` strings.
- A missing gold section means the fixture asserts nothing there:
  the metric reports ``status = insufficient_evidence``, never 0/1.
- An explicitly empty gold section (``[]`` / ``{}``) asserts absence:
  anything observed is a false positive.
- Rates with an empty denominator report ``insufficient_evidence``,
  never ``0`` (a system that predicts nothing has not proven it
  predicts correctly).
"""

import os
import re

TRUTH_SCHEMA_VERSION = "2.0"

#: Authority statement outcomes (neutral vocabulary; PARTIAL covers
#: partially-resolved evidence, never a downgraded unknown).
GOLD_OUTCOMES = (
    "MATCH",
    "EXCESS_AUTHORITY",
    "AUTHORITY_MISMATCH",
    "UNVERIFIED_LINK",
    "UNKNOWN",
    "PARTIAL",
)

#: Expected material-change kinds (brief vocabulary, shared with ChangeGuard).
CHANGE_KINDS = (
    "NO_CHANGE",
    "NON_MATERIAL_CHANGE",
    "MATERIAL_CHANGE",
    "AUTHORITY_ESCALATION",
    "AUTHORITY_REDUCTION",
    "UNKNOWN_CHANGE",
)

MATERIAL_KINDS = {"MATERIAL_CHANGE", "AUTHORITY_ESCALATION", "AUTHORITY_REDUCTION"}
ESCALATION_KINDS = {"AUTHORITY_ESCALATION"}

#: Change-entry domains: tool-surface diffs, identity-set diffs,
#: grant-set diffs. Identity/grant changes are evaluated by comparing
#: baseline vs current reports (the harness passes both).
CHANGE_DOMAINS = ("tool-surface", "identity", "grant")

#: Uncertainty expectations gold may assert.
UNKNOWN_EXPECTATIONS = (
    "UNKNOWN",
    "UNVERIFIED_LINK",
    "PARTIAL",
    "INFERRED",
    "UNRESOLVED",
)

MEASURED = "measured"
INSUFFICIENT = "insufficient_evidence"


def slug(value):
    """Neutral slug: lowercase alphanumerics; used for name matching."""
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _basename(path):
    if not isinstance(path, str) or not path or path.startswith("<"):
        return ""
    return os.path.basename(path.replace("\\", "/"))


def _prf_counts(tp, fp, fn):
    """PRF from counts. Halves with an empty denominator stay None but are
    preserved; status is measured whenever any instance exists, so a lone
    false negative (recall 0.0, precision undefined) still fails loudly
    instead of dissolving into insufficient_evidence."""
    tp, fp, fn = int(tp), int(fp), int(fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0
    out = {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
    }
    if (tp + fp + fn) > 0:
        out.update(
            {
                "precision": round(precision, 4) if precision is not None else None,
                "recall": round(recall, 4) if recall is not None else None,
                "f1": round(f1, 4) if f1 is not None else None,
                "status": MEASURED,
            }
        )
    else:
        out.update(
            {
                "precision": None,
                "recall": None,
                "f1": None,
                "status": INSUFFICIENT,
            }
        )
    return out


def _empty_prf(reason):
    return {"true_positives": 0, "false_positives": 0, "false_negatives": 0,
            "precision": None, "recall": None, "f1": None,
            "status": INSUFFICIENT, "reason": reason}


# ---------------------------------------------------------------------------
# Gold model
# ---------------------------------------------------------------------------

def blank_gold():
    """Empty canonical gold: every section absent (all insufficient)."""
    return {"agents": None, "tools": None, "capabilities": None,
            "identities": None, "grants": None, "relationships": None,
            "authority_statements": None, "changes": None,
            "unknown_expectations": None, "annotation": None,
            "derived_from_legacy": False}


def gold_from_expected(expected):
    """Build canonical gold from an expected-truth document.

    Uses the ``canonical`` block when present (schema v2); otherwise
    derives an equivalent gold from the legacy reviewed sections and
    marks ``derived_from_legacy`` so the report can say so honestly.
    Returns ``(gold, notes)`` where notes lists derivation remarks.
    """
    gold = blank_gold()
    notes = []
    if not isinstance(expected, dict):
        return gold, ["expected truth is not an object"]
    canon = expected.get("canonical")
    if isinstance(canon, dict):
        for key in ("agents", "tools", "capabilities", "identities",
                    "grants", "relationships", "authority_statements",
                    "changes", "unknown_expectations"):
            if key in canon:
                gold[key] = canon[key]
        gold["annotation"] = canon.get("annotation")
        return gold, notes
    gold["derived_from_legacy"] = True
    notes.append("canonical block absent: gold derived from legacy reviewed sections")
    # Agents: human (framework, name) pairs.
    if "agents" in expected:
        gold["agents"] = [
            {"id": f"{a.get('framework')}:{a.get('name')}",
             "framework": a.get("framework"), "name": a.get("name")}
            for a in expected.get("agents") or []
        ]
    # Tools + capabilities: named tools stay; unattributed-bucket caps
    # become tool-less capabilities with unresolved attribution.
    tools, caps = [], []
    if "tools" in expected:
        for tool in expected.get("tools") or []:
            key = str(tool.get("tool_key") or "")
            if key == "unknown:unattributed" or key.startswith("unknown:"):
                for cap in tool.get("capabilities") or []:
                    caps.append({
                        "tool": None,
                        "capability": cap.get("name"),
                        "access_mode": cap.get("access_mode") or "",
                        "attribution": "unresolved",
                    })
                continue
            kind, _, rest = key.partition(":")
            name = rest.split(".")[-1] if rest else key
            tool_id = slug(name) or slug(key)
            tools.append({"id": tool_id, "name": name, "kind": kind,
                          "attributable": True})
            for cap in tool.get("capabilities") or []:
                caps.append({
                    "tool": tool_id,
                    "capability": cap.get("name"),
                    "access_mode": cap.get("access_mode") or "",
                    "attribution": "attributed",
                })
        gold["tools"] = tools
        gold["capabilities"] = caps
    if "identities" in expected:
        gold["identities"] = [
            {"id": f"{i.get('kind')}/{i.get('namespace') or ''}/{i.get('name')}",
             "kind": i.get("kind"), "name": i.get("name"),
             "namespace": i.get("namespace") or ""}
            for i in expected.get("identities") or []
        ]
    if "grants" in expected:
        gold["grants"] = [
            {"identity": g.get("identity"),
             "identity_namespace": g.get("namespace") or "",
             "actions": list(g.get("actions") or []),
             "resources": list(g.get("resources") or []),
             "resolution": g.get("resolution") or "resolved"}
            for g in expected.get("grants") or []
        ]
    # Relationships: tool edges resolvable; agent->tool edges beyond
    # the current model (documented limitation, not hidden).
    rels = []
    if "agents" in expected and "tools" in expected:
        for agent in gold["agents"] or []:
            for tool in tools:
                rels.append({"type": "agent_uses_tool", "agent": agent["id"],
                             "tool": tool["id"], "resolvable": False})
    if "tools" in expected:
        for cap in caps:
            if cap["tool"] is not None:
                rels.append({"type": "tool_has_capability",
                             "tool": cap["tool"],
                             "capability": cap["capability"],
                             "access_mode": cap["access_mode"],
                             "resolvable": True})
    if "links" in expected:
        for link in expected.get("links") or []:
            rels.append({"type": "agent_linked_identity",
                         "agent": None,
                         "identity": str(link.get("identity")),
                         "identity_namespace": str(link.get("namespace") or ""),
                         "resolvable": True})
        gold["relationships"] = rels
    elif rels:
        gold["relationships"] = rels
    if "verdicts" in expected:
        gold["authority_statements"] = [
            {"capability": None, "domain": domain, "identity": None,
             "resource": None, "outcome": outcome}
            for domain, outcome in (expected.get("verdicts") or {}).items()
        ]
        # Covered-grant edges derive from statements at compare time
        # (_gold_covered_edges); they are never stored in gold.
    # Covered edges derive from statements, so verdict-only cases reach
    # here with rels possibly empty but statements present.
    if rels and gold.get("relationships") is None:
        gold["relationships"] = rels
    if "changes" in expected:
        gold["changes"] = [_legacy_change(e) for e in expected.get("changes") or []]
    if "uncertainty" in expected:
        kind_map = {"unlinked": "UNVERIFIED_LINK"}
        expectations = []
        for u in expected.get("uncertainty") or []:
            if not isinstance(u, dict):
                continue
            kind = str(u.get("kind") or "")
            outcome = kind_map.get(kind, kind.upper())
            if outcome not in UNKNOWN_EXPECTATIONS:
                outcome = "UNKNOWN"
                notes.append(f"unmappable uncertainty kind kept as UNKNOWN: {kind}")
            expectations.append({"area": kind, "expected": outcome,
                                 "match": str(u.get("match") or "")})
        gold["unknown_expectations"] = expectations
    return gold, notes


def _legacy_change(entry):
    """Legacy descriptive change -> canonical change entry."""
    if not isinstance(entry, dict):
        return {"subject": "<?>", "kind": "UNKNOWN_CHANGE", "status": "",
                "domain": "tool-surface", "evidence": [],
                "surface_expected": False}
    subject = str(entry.get("tool") or entry.get("subject") or "<?>")
    kind = str(entry.get("materiality") or entry.get("kind") or "UNKNOWN_CHANGE")
    if kind not in CHANGE_KINDS:
        kind = "UNKNOWN_CHANGE"
    status = str(entry.get("status") or "")
    lowered = subject.lower()
    if "identity (" in lowered or lowered.startswith("identity"):
        domain = "identity"
    elif "grant (" in lowered:
        domain = "grant"
    else:
        domain = "tool-surface"
    evidence = re.findall(r"\(([^()]+)\)", subject)
    # Legacy truth never claimed surface-channel detection (the legacy
    # harness fails such claims by design): the surface miss is an
    # explicitly counted blind spot, while findings/summary channels
    # remain enforced by the legacy checks. New fixtures set this
    # explicitly where the surface should catch the change.
    return {"subject": subject, "kind": kind, "status": status,
            "domain": domain,
            "evidence": [e for e in evidence if "." in e],
            "surface_expected": False}


def validate_gold(gold):
    """Schema problems in a canonical gold (loud failure, never silent pass)."""
    problems = []
    for agent in gold.get("agents") or []:
        if not agent.get("name"):
            problems.append("agent without name")
    for tool in gold.get("tools") or []:
        if not tool.get("id"):
            problems.append("tool without id")
    for cap in gold.get("capabilities") or []:
        if not cap.get("capability"):
            problems.append("capability without name")
        if cap.get("attribution") not in ("attributed", "unresolved"):
            problems.append(f"capability with bad attribution: {cap}")
    for rel in gold.get("relationships") or []:
        if rel.get("type") not in ("agent_uses_tool", "tool_has_capability",
                                   "agent_linked_identity",
                                   "capability_covered_by_grant"):
            problems.append(f"relationship with bad type: {rel}")
    for stmt in gold.get("authority_statements") or []:
        if stmt.get("outcome") not in GOLD_OUTCOMES:
            problems.append(f"statement with bad outcome: {stmt}")
    for change in gold.get("changes") or []:
        if change.get("kind") not in CHANGE_KINDS:
            problems.append(f"change with bad kind: {change}")
        if change.get("domain") not in CHANGE_DOMAINS:
            problems.append(f"change with bad domain: {change}")
        if ((change.get("domain") or "tool-surface") == "tool-surface"
                and change.get("surface_expected", True)
                and not change.get("status")):
            problems.append(f"surface-expected change without status: {change}")
    for unk in gold.get("unknown_expectations") or []:
        if unk.get("expected") not in UNKNOWN_EXPECTATIONS:
            problems.append(f"unknown expectation with bad outcome: {unk}")
    return problems


# ---------------------------------------------------------------------------
# Projection: SafeAI output -> canonical observed
# ---------------------------------------------------------------------------

def _tool_tokens(tool_key):
    """Neutral match tokens for a scanner tool key (never compared raw)."""
    key = str(tool_key or "")
    tokens = {key, slug(key)}
    if ":" in key:
        _, _, rest = key.partition(":")
        tokens.add(rest)
        tokens.add(slug(rest))
        tokens.add(slug(rest.split(".")[-1]))
    return {t for t in tokens if t}


def project_report(report):
    """Project a scan report into canonical observed sets."""
    report = report or {}
    agents = set()
    for model in report.get("agent_models") or []:
        if not isinstance(model, dict):
            continue
        for agent in (model.get("data") or {}).get("agents") or []:
            if isinstance(agent, dict) and agent.get("name"):
                agents.add((str(model.get("framework") or ""),
                            str(agent.get("name"))))
    named_tools = {}  # match-token set per tool key
    unattributed_caps = set()
    named_caps = set()  # (tool_key, capability, access_mode)
    for tool in report.get("tool_surface") or []:
        if not isinstance(tool, dict):
            continue
        key = str(tool.get("tool_key") or "")
        if key.startswith("unknown:"):
            for cap in tool.get("capabilities") or []:
                if isinstance(cap, dict) and cap.get("name"):
                    unattributed_caps.add(
                        (str(cap.get("name")),
                         str(cap.get("access_mode") or "")))
            continue
        named_tools[key] = _tool_tokens(key)
        for cap in tool.get("capabilities") or []:
            if isinstance(cap, dict) and cap.get("name"):
                named_caps.add((key, str(cap.get("name")),
                                str(cap.get("access_mode") or "")))
    iac = report.get("iac_correlations") or {}
    if not isinstance(iac, dict):
        iac = {}
    identities = set()
    for ident in iac.get("identities") or []:
        if isinstance(ident, dict) and ident.get("name"):
            identities.add((str(ident.get("kind") or ""),
                            str(ident.get("name")),
                            str(ident.get("namespace") or "")))
    grants = []  # (name, namespace, actions, resources, resolution)
    for grant in iac.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        ident = grant.get("identity") or {}
        actions = grant.get("actions") or {}
        resources = grant.get("resources") or {}
        grants.append((str(ident.get("name") or ""),
                       str(ident.get("namespace") or ""),
                       tuple(sorted(actions.get("values") or [])),
                       tuple(sorted(resources.get("values") or [])),
                       str(actions.get("resolution") or "")))
    links = set()  # (agent, name, namespace)
    for link in iac.get("agent_identity_links") or []:
        if not isinstance(link, dict):
            continue
        ident = link.get("identity") or {}
        if ident.get("name"):
            links.add((str(link.get("agent") or ""),
                       str(ident.get("name")),
                       str(ident.get("namespace") or "")))
    verdicts = {}  # domain -> (verdict, resolution)
    for verdict in iac.get("verdicts") or []:
        if isinstance(verdict, dict) and verdict.get("domain"):
            verdicts[str(verdict.get("domain"))] = (
                str(verdict.get("verdict") or ""),
                str(verdict.get("resolution") or ""))
    resolutions = set()  # observed field resolutions (for PARTIAL)
    for grant in iac.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        for field in (grant.get("actions"), grant.get("resources")):
            if isinstance(field, dict) and field.get("resolution"):
                resolutions.add(str(field.get("resolution")))
    return {"agents": agents, "named_tools": named_tools,
            "named_caps": named_caps, "unattributed_caps": unattributed_caps,
            "identities": identities, "grants": grants, "links": links,
            "verdicts": verdicts, "resolutions": resolutions}


def _match_tool(gold_tool, named_tools):
    """Gold tool -> observed tool key by neutral slug, or None."""
    want = {slug(gold_tool.get("id")), slug(gold_tool.get("name"))} - {""}
    for key, tokens in named_tools.items():
        if want & tokens:
            return key
    return None


# ---------------------------------------------------------------------------
# Entity discovery
# ---------------------------------------------------------------------------

def compare_entities(gold, obs):
    """Per-entity TP/FP/FN. Missing gold section -> insufficient_evidence."""
    out = {}

    if gold.get("agents") is None:
        out["agents"] = _empty_prf("no agent truth in fixture")
    else:
        want = {str(a.get("name")) for a in gold["agents"] if a.get("name")}
        got = {name for _, name in obs["agents"]}
        out["agents"] = _prf(want & got, got - want, want - got)

    if gold.get("tools") is None:
        out["tools"] = _empty_prf("no tool truth in fixture")
    else:
        want = {slug(t.get("id")) or slug(t.get("name"))
                for t in gold["tools"] if t.get("attributable", True)}
        want.discard("")
        got = set()
        for key in obs["named_tools"]:
            got.add(slug(key.split(":")[-1].split(".")[-1]) or slug(key))
        got.discard("")
        out["tools"] = _prf(want & got, got - want, want - got)

    if gold.get("capabilities") is None:
        out["capabilities"] = _empty_prf("no capability truth in fixture")
    else:
        want = {(str(c.get("capability")), str(c.get("access_mode") or ""))
                for c in gold["capabilities"] if c.get("capability")}
        got_named = {(cap, mode) for _, cap, mode in obs["named_caps"]}
        got_unattr = set(obs["unattributed_caps"])
        got = got_named | got_unattr
        out["capabilities"] = _prf(want & got, got - want, want - got)

    if gold.get("identities") is None:
        out["identities"] = _empty_prf("no identity truth in fixture")
    else:
        want = {str(i.get("name")) for i in gold["identities"] if i.get("name")}
        got = {name for _, name, _ in obs["identities"]}
        out["identities"] = _prf(want & got, got - want, want - got)

    if gold.get("grants") is None:
        out["grants"] = _empty_prf("no grant truth in fixture")
    else:
        want = {str(g.get("identity")) for g in gold["grants"]
                if g.get("identity")}
        got = {name for name, _, _, _, _ in obs["grants"]}
        out["grants"] = _prf(want & got, got - want, want - got)

    if gold.get("relationships") is None and gold.get("capabilities") is None:
        out["relationships"] = _empty_prf("no relationship truth in fixture")
    else:
        want = set()
        for rel in gold.get("relationships") or []:
            if rel.get("resolvable", True):
                want.add(_rel_key(rel))
        want |= _gold_tool_edges(gold)
        want |= _gold_covered_edges(gold)
        if not want:
            out["relationships"] = _empty_prf("no resolvable relationship truth")
        else:
            got = set()
            for rel in _observed_relationships(gold, obs):
                got.add(_rel_key(rel))
            out["relationships"] = _prf(want & got, got - want, want - got)

    if gold.get("authority_statements") is None:
        out["statements"] = _empty_prf("no authority-statement truth")
    else:
        want = {(str(s.get("domain") or "")) for s in gold["authority_statements"]
                if s.get("domain")}
        got = set(obs["verdicts"])
        out["statements"] = _prf(want & got, got - want, want - got)

    return out


# ---------------------------------------------------------------------------
# Attribution levels (8)
# ---------------------------------------------------------------------------

def compare_attribution(gold, obs):
    """Eight independent attribution measurements with TP/FP/FN."""
    out = {}
    tools = [t for t in gold.get("tools") or []] if gold.get("tools") is not None else None
    caps = gold.get("capabilities")

    # L1 tool attribution: attributable gold tools reconstructed by name.
    if tools is None:
        out["tool"] = _empty_prf("no tool truth in fixture")
    else:
        want = {t.get("id") for t in tools if t.get("attributable", True)}
        got = {t.get("id") for t in tools
               if t.get("attributable", True)
               and _match_tool(t, obs["named_tools"])}
        extra = set()
        for key in obs["named_tools"]:
            if not any(_match_tool(t, {key: obs["named_tools"][key]})
                       for t in tools if t.get("attributable", True)):
                extra.add(key)
        out["tool"] = _prf_counts(len(got), len(extra), len(want - got))

    # L2 capability attribution: attributed caps under the right tool.
    if caps is None:
        out["capability"] = _empty_prf("no capability truth in fixture")
    else:
        want = {(c.get("tool"), str(c.get("capability")),
                 str(c.get("access_mode") or ""))
                for c in caps if c.get("attribution") == "attributed"}
        got = set()
        for tool_id, cap, mode in want:
            gold_tool = {"id": tool_id, "name": tool_id}
            key = _match_tool(gold_tool, obs["named_tools"])
            if key and (key, cap, mode) in obs["named_caps"]:
                got.add((tool_id, cap, mode))
        out["capability"] = _prf_counts(len(got), 0, len(want - got))

    # L3 agent attribution: exact (framework, name) identification.
    if gold.get("agents") is None:
        out["agent"] = _empty_prf("no agent truth in fixture")
    else:
        want = {(str(a.get("framework") or ""), str(a.get("name") or ""))
                for a in gold["agents"]}
        got_names = {n for _, n in obs["agents"]}
        got = {(f, n) for f, n in obs["agents"]} & want
        fn = {(f, n) for f, n in want
              if n in got_names and (f, n) not in got}
        fn |= {(f, n) for f, n in want if n not in got_names}
        fp = {(f, n) for f, n in obs["agents"]
              if n not in {nn for _, nn in want}}
        out["agent"] = _prf_counts(len(got), len(fp), len(fn))

    # L4 identity attribution: full (kind, name, namespace) triples.
    if gold.get("identities") is None:
        out["identity"] = _empty_prf("no identity truth in fixture")
    else:
        want = {(str(i.get("kind") or ""), str(i.get("name") or ""),
                 str(i.get("namespace") or "")) for i in gold["identities"]}
        out["identity"] = _prf(want & obs["identities"],
                               obs["identities"] - want, want - obs["identities"])

    # L5 grant attribution: actions + resources + resolution per identity.
    if gold.get("grants") is None:
        out["grant"] = _empty_prf("no grant truth in fixture")
    else:
        tp = fp = fn = 0
        unmatched_obs = list(obs["grants"])
        for grant in gold["grants"]:
            name = str(grant.get("identity") or "")
            ns = str(grant.get("identity_namespace") or "")
            cands = [g for g in unmatched_obs
                     if g[0] == name and (not ns or g[1] == ns or not g[1])]
            hit = False
            for cand in cands:
                if (sorted(cand[2]) == sorted(grant.get("actions") or []) and
                        sorted(cand[3]) == sorted(grant.get("resources") or []) and
                        (not grant.get("resolution") or
                         cand[4] == grant.get("resolution"))):
                    hit = True
                    unmatched_obs.remove(cand)
                    break
            if hit:
                tp += 1
            else:
                fn += 1
        fp = len(unmatched_obs)
        out["grant"] = _prf_counts(tp, fp, fn)

    # L6 agent -> identity attribution.
    rels = gold.get("relationships")
    if rels is None:
        out["agent_identity"] = _empty_prf("no relationship truth in fixture")
    else:
        want = {(str(r.get("identity") or ""),
                 str(r.get("identity_namespace") or ""))
                for r in rels if r.get("type") == "agent_linked_identity"}
        if not want and not any(r.get("type") == "agent_linked_identity"
                                for r in rels):
            out["agent_identity"] = _empty_prf("no agent-identity truth")
        else:
            got = {(name, ns) for _, name, ns in obs["links"]}
            out["agent_identity"] = _prf(want & got, got - want, want - got)

    # L7 capability -> grant attribution (outcome must match).
    stmts = gold.get("authority_statements")
    if stmts is None:
        out["capability_grant"] = _empty_prf("no authority-statement truth")
    else:
        want = {str(s.get("domain")): str(s.get("outcome"))
                for s in stmts if s.get("domain")}
        if not want:
            out["capability_grant"] = _empty_prf("no domain truth in fixture")
        else:
            tp = sum(1 for d, o in want.items()
                     if d in obs["verdicts"] and obs["verdicts"][d][0] == o)
            fp = sum(1 for d in obs["verdicts"] if d not in want)
            fn = len(want) - tp
            out["capability_grant"] = _prf_counts(tp, fp, fn)

    # L8 end-to-end: complete chains with matching outcomes.
    if stmts is None:
        out["end_to_end"] = _empty_prf("no authority-statement truth")
    else:
        full = [s for s in stmts
                if s.get("domain") and s.get("capability") and s.get("identity")]
        if not full:
            out["end_to_end"] = _empty_prf(
                "no complete authority chains in fixture truth")
        else:
            tp = 0
            for stmt in full:
                domain = str(stmt.get("domain"))
                if (domain in obs["verdicts"] and
                        obs["verdicts"][domain][0] == stmt.get("outcome")):
                    tp += 1
            out["end_to_end"] = _prf_counts(tp, 0, len(full) - tp)

    return out


def _prf(tp_set, fp_set, fn_set):
    return _prf_counts(len(tp_set), len(fp_set), len(fn_set))


def _rel_key(rel):
    rtype = rel.get("type")
    if rtype == "agent_uses_tool":
        return (rtype, str(rel.get("agent") or ""), str(rel.get("tool") or ""))
    if rtype == "tool_has_capability":
        return (
            rtype,
            str(rel.get("tool") or ""),
            str(rel.get("capability") or ""),
            str(rel.get("access_mode") or ""),
        )
    if rtype == "agent_linked_identity":
        return (
            rtype,
            str(rel.get("identity") or ""),
            str(rel.get("identity_namespace") or ""),
        )
    if rtype == "capability_covered_by_grant":
        return (
            rtype,
            str(rel.get("capability") or ""),
            str(rel.get("domain") or ""),
            str(rel.get("outcome") or ""),
        )
    return (str(rtype),)


def _gold_tool_edges(gold):
    """Tool->capability edges derived from attributed gold capabilities.

    Every attributed capability trivially asserts its tool edge; listing
    all of them by hand in every fixture would duplicate the
    capabilities section and rot. Only agent_uses_tool and
    agent_linked_identity need explicit gold relationships.
    """
    edges = set()
    for cap in gold.get("capabilities") or []:
        if cap.get("attribution") == "attributed" and cap.get("tool"):
            edges.add(
                ("tool_has_capability", str(cap.get("tool")),
                 str(cap.get("capability") or ""),
                 str(cap.get("access_mode") or ""))
            )
    return edges


def _gold_covered_edges(gold):
    """Capability->grant edges derived from authority statements.

    Same rationale as tool edges: the statement already asserts the
    (capability, domain, outcome) triple, so storing the edge again
    would duplicate truth and rot independently.
    """
    edges = set()
    for stmt in gold.get("authority_statements") or []:
        if stmt.get("domain"):
            edges.add(
                ("capability_covered_by_grant",
                 str(stmt.get("capability") or ""),
                 str(stmt.get("domain")),
                 str(stmt.get("outcome") or ""))
            )
    return edges


def _observed_relationships(gold, obs):
    """Relationships the scanner output evidences (neutral keys)."""
    rels = []
    gold_tools = [t for t in gold.get("tools") or [] if isinstance(t, dict)]
    for key, cap, mode in obs["named_caps"]:
        for gold_tool in gold_tools:
            if _match_tool(gold_tool, {key: obs["named_tools"][key]}):
                rels.append({"type": "tool_has_capability",
                             "tool": gold_tool.get("id"), "capability": cap,
                             "access_mode": mode})
                break
    for agent, name, namespace in obs["links"]:
        rels.append({"type": "agent_linked_identity",
                     "agent": agent or None, "identity": name,
                     "identity_namespace": namespace})
    for domain, (verdict, _) in obs["verdicts"].items():
        for stmt in gold.get("authority_statements") or []:
            if stmt.get("domain") == domain:
                rels.append({"type": "capability_covered_by_grant",
                             "capability": stmt.get("capability") or "",
                             "domain": domain, "outcome": verdict})
    return rels


# ---------------------------------------------------------------------------
# Change evaluation (ChangeGuard quality, both sides)
# ---------------------------------------------------------------------------

def _diff_evidence(current):
    """Per diff-tool evidence basenames + (status, materiality).

    Includes the ``unattributed`` block: it is a real diff entry, and
    ignoring it would hide surface behavior on unattributed tools.
    """
    from safeai.benchmark.metrics import materiality

    entries = []

    def add(tool):
        if not isinstance(tool, dict):
            return
        files = set()
        for cap in (tool.get("capabilities_added") or []) + (
            tool.get("capabilities_removed") or []
        ):
            if not isinstance(cap, dict):
                continue
            for ev in cap.get("evidence") or []:
                if isinstance(ev, dict):
                    base = _basename(ev.get("path"))
                    if base:
                        files.add(base)
        entries.append(
            {
                "tool_key": str(tool.get("tool_key") or ""),
                "status": str(tool.get("status") or ""),
                "materiality": materiality(tool.get("status"), tool.get("change_class")),
                "evidence": files,
            }
        )

    diff = (current or {}).get("capability_diff") or {}
    for tool in diff.get("tools") or []:
        add(tool)
    if isinstance(diff.get("unattributed"), dict):
        add(diff.get("unattributed"))
    return entries


def _identity_set(report):
    iac = (report or {}).get("iac_correlations") or {}
    return {
        (str(i.get("kind") or ""), str(i.get("name") or ""), str(i.get("namespace") or ""))
        for i in iac.get("identities") or []
        if isinstance(i, dict)
    }


def _grant_set(report):
    iac = (report or {}).get("iac_correlations") or {}
    out = set()
    for grant in iac.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        ident = grant.get("identity") or {}
        actions = grant.get("actions") or {}
        resources = grant.get("resources") or {}
        out.add(
            (
                str(ident.get("name") or ""),
                str(ident.get("namespace") or ""),
                tuple(sorted(actions.get("values") or [])),
                tuple(sorted(resources.get("values") or [])),
            )
        )
    return out


def compare_change(gold, current, baseline):
    """Material-change + escalation PRF over gold change entries.

    Non-baseline cases (no gold changes section, or no baseline pair)
    report insufficient_evidence. UNKNOWN_CHANGE entries are preserved
    uncertainty: counted separately, never in P/R denominators.
    """
    changes = gold.get("changes")
    if changes is None or baseline is None:
        empty = _empty_prf("no baseline-pair change truth in fixture")
        return {
            "material_change": empty,
            "escalation": _empty_prf("no baseline-pair change truth"),
            "no_change_correct": 0, "no_change_total": 0,
            "unknown_changes": 0, "surface_blind": 0,
            "false_escalation_rate": {
                "value": None,
                "status": INSUFFICIENT,
                "reason": "not a baseline pair",
            },
            "missed_material_rate": {
                "value": None,
                "status": INSUFFICIENT,
                "reason": "not a baseline pair",
            },
            "failures": [],
        }
    diff = _diff_evidence(current)
    base_idents, cur_idents = _identity_set(baseline), _identity_set(current)
    base_grants, cur_grants = _grant_set(baseline), _grant_set(current)

    mat_tp = mat_fp_extra = mat_fn = 0
    esc_tp = esc_fn = 0
    esc_fp = 0
    no_ok = no_total = 0
    unknown_changes = 0
    surface_blind = 0
    failures = []
    matched_diff = set()

    for entry in changes:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind") or "UNKNOWN_CHANGE"
        domain = entry.get("domain") or "tool-surface"
        subject = entry.get("subject") or "<?>"
        if kind == "UNKNOWN_CHANGE":
            unknown_changes += 1
            continue
        if (domain == "tool-surface"
                and not entry.get("surface_expected", True)):
            # Explicitly out of the surface model: counted blind spot,
            # detection enforced via findings/summary by legacy checks.
            surface_blind += 1
            continue
        if kind == "NO_CHANGE":
            no_total += 1
            if _subject_quiet(entry, diff, base_idents, cur_idents, base_grants, cur_grants):
                no_ok += 1
            else:
                failures.append(
                    f"'{subject}' expected NO_CHANGE but authority moved")
            continue
        material = kind in MATERIAL_KINDS
        hit = _find_correspondent(
            entry, diff, base_idents, cur_idents, base_grants, cur_grants)
        if hit is None:
            if material:
                mat_fn += 1
            failures.append(f"change missed: '{subject}' expected {kind}")
            if kind in ESCALATION_KINDS:
                esc_fn += 1
            continue
        observed_kind = None
        if isinstance(hit, int):
            matched_diff.add(hit)
            observed_kind = diff[hit].get("materiality")
        else:  # "IDENTITY" / "GRANT": direction verified by the finder
            observed_kind = kind
        if material:
            if observed_kind == kind:
                mat_tp += 1
            else:
                mat_fn += 1
                failures.append(
                    f"change misclassified: '{subject}' expected {kind}, "
                    f"observed {observed_kind}")
        if kind in ESCALATION_KINDS:
            if observed_kind == kind:
                esc_tp += 1
            else:
                esc_fn += 1
    for idx, entry in enumerate(diff):
        if idx in matched_diff:
            continue
        if entry["materiality"] in MATERIAL_KINDS:
            mat_fp_extra += 1
            failures.append(
                f"observed {entry['materiality']} on "
                f"{entry['tool_key'] or '?'} with no expected change")
        if entry["materiality"] in ESCALATION_KINDS:
            esc_fp += 1

    material_change = _prf_counts(mat_tp, mat_fp_extra, mat_fn)
    escalation = _prf_counts(esc_tp, esc_fp, esc_fn)
    esc_obs = esc_tp + esc_fp
    if esc_obs > 0:
        fer = {"value": round(esc_fp / esc_obs, 4), "status": "measured"}
    else:
        fer = {"value": None, "status": INSUFFICIENT,
               "reason": "no HIGH_RISK diffs observed on this case"}
    mat_exp = mat_tp + mat_fn
    if mat_exp > 0:
        mmr = {"value": round(mat_fn / mat_exp, 4), "status": "measured"}
    else:
        mmr = {"value": None, "status": INSUFFICIENT,
               "reason": "no material changes expected on this case"}
    return {"material_change": material_change, "escalation": escalation,
            "no_change_correct": no_ok, "no_change_total": no_total,
            "unknown_changes": unknown_changes,
            "surface_blind": surface_blind,
            "false_escalation_rate": fer, "missed_material_rate": mmr,
            "failures": failures}


def _subject_quiet(entry, diff, base_idents, cur_idents, base_grants, cur_grants):
    domain = entry.get("domain") or "tool-surface"
    evidence = set(entry.get("evidence") or [])
    if domain == "identity":
        return base_idents == cur_idents
    if domain == "grant":
        return base_grants == cur_grants
    for cand in diff:
        if evidence and (cand["evidence"] & evidence):
            return False
    return True


def _find_correspondent(entry, diff, base_idents, cur_idents, base_grants, cur_grants):
    """Diff index (int), 'IDENTITY'/'GRANT' direction marker, or None."""
    domain = entry.get("domain") or "tool-surface"
    evidence = set(entry.get("evidence") or [])
    subject = entry.get("subject") or ""
    kind = entry.get("kind") or "UNKNOWN_CHANGE"
    if domain == "identity":
        name = entry.get("identity") or subject.split()[0]
        base_names = {n for _, n, _ in base_idents}
        cur_names = {n for _, n, _ in cur_idents}
        if kind == "AUTHORITY_REDUCTION" and name in base_names and name not in cur_names:
            return "IDENTITY"
        if kind == "AUTHORITY_ESCALATION" and name in cur_names and name not in base_names:
            return "IDENTITY"
        if kind in ("MATERIAL_CHANGE", "NON_MATERIAL_CHANGE") and base_idents != cur_idents:
            return "IDENTITY"
        return None
    if domain == "grant":
        if base_grants != cur_grants:
            return "GRANT"
        return None
    name_part = subject.split("(")[0].strip().lower()
    best = None
    for idx, cand in enumerate(diff):
        if cand["status"] in ("unchanged", ""):
            continue
        overlap = bool(evidence and (cand["evidence"] & evidence))
        name_hit = bool(name_part and name_part in (cand["tool_key"] or "").lower())
        if (overlap or (not evidence and name_hit)) and (
            best is None or (overlap and not best[1])
        ):
            best = (idx, overlap)
    if best is None:
        return None
    return best[0]


# ---------------------------------------------------------------------------
# Unknown validation
# ---------------------------------------------------------------------------

def compare_unknown(gold, obs, pools):
    """Unknown preservation: every gold expectation must stay expressed.

    pools: observed uncertainty pools (inferred/unresolved/unknown/
    unlinked sets) plus field resolutions. Never converts unknown into
    safe or into mismatch without evidence: PARTIAL matches only
    observed partially-resolved evidence.
    """
    expectations = gold.get("unknown_expectations")
    failures = []
    if expectations is None:
        return {"preserved": {"expected": 0, "matched": 0},
                "failures": failures, "status": INSUFFICIENT}
    matched = 0
    total = 0
    for item in expectations:
        if not isinstance(item, dict):
            continue
        total += 1
        expected = item.get("expected")
        match = str(item.get("match") or "")
        if expected == "INFERRED" and any(match in c for c in pools["inferred"]) or expected == "UNRESOLVED" and any(match in c for c in pools["unresolved"]) or expected == "UNKNOWN" and any(match in c for c in pools["unknown"]) or expected == "UNVERIFIED_LINK" and any(match in c for c in pools["unlinked"]) or expected == "PARTIAL" and (
            "partially-resolved" in obs.get("resolutions", set())
        ):
            matched += 1
        else:
            failures.append(
                f"unknown not preserved: expected {expected} for '{match}'")
    return {"preserved": {"expected": total, "matched": matched},
            "failures": failures,
            "status": "measured" if total else INSUFFICIENT}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def compare_all(gold, obs, current, baseline):
    """Run entity + attribution + change + unknown comparison."""
    from safeai.benchmark.compare import _uncertainty_pools

    failures = []
    parts = {}
    parts["entities"] = compare_entities(gold, obs)
    for name, res in parts["entities"].items():
        if res.get("status") == "measured" and (
            res.get("false_negatives") or res.get("false_positives")
        ):
            failures.append(
                f"entity {name}: TP {res['true_positives']} "
                f"FP {res['false_positives']} FN {res['false_negatives']}")
    parts["attribution"] = compare_attribution(gold, obs)
    for name, res in parts["attribution"].items():
        if res.get("status") == "measured" and (
            res.get("false_negatives") or res.get("false_positives")
        ):
            failures.append(
                f"attribution {name}: TP {res['true_positives']} "
                f"FP {res['false_positives']} FN {res['false_negatives']}")
    change = compare_change(gold, current, baseline)
    failures.extend(change.pop("failures", []))
    parts["change"] = {k: v for k, v in change.items()
                       if k not in ("false_escalation_rate", "missed_material_rate")}
    parts["change"]["false_escalation_rate"] = change["false_escalation_rate"]
    parts["change"]["missed_material_rate"] = change["missed_material_rate"]
    pools = _uncertainty_pools(current)
    unknown = compare_unknown(gold, obs, pools)
    failures.extend(unknown.pop("failures", []))
    parts["unknown"] = unknown
    return {"failures": failures, "parts": parts}