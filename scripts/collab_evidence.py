#!/usr/bin/env python3
"""Static authority evidence vs runtime authorization: the SafeAI half.

Draft tooling for the experiment proposed in GitHub discussion #251
(research/collab/static-vs-runtime/SPEC.md). It does three things:

``static``
    Scan each scenario fixture with SafeAI and write one provider-neutral
    *static evidence record* per scenario.
``check``
    Validate the scenario files and the committed static records, and
    fail when a record no longer matches what a scan produces.
``compare``
    Join static records with *runtime observation records* (produced by a
    runtime harness, not by this script) and classify every comparison
    unit as agreement, disagreement or insufficient evidence. Every unit
    stays in the denominator.

Nothing here runs an agent, a tool or a runtime. No runtime observation
is produced or assumed by this script.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

SPEC_VERSION = "0.1-draft"
ROOT = REPO / "research" / "collab" / "static-vs-runtime"
SCENARIOS = ROOT / "scenarios"
STATIC_RECORDS = ROOT / "records" / "static"

ACCESS_MODES = ("read", "write", "mutate", "execute")
SCOPES = ("narrower", "equal", "broader_or_different", "unknown")
DECISIONS = ("PERMIT", "DENY")
EXECUTIONS = ("executed", "not_executed", "unknown")
EFFECTS = ("observed", "not_observed", "unknown")
OUTCOMES = ("agreement", "disagreement", "insufficient_evidence")

#: What a static record can never establish, stated in every record.
STATIC_LIMITS = (
    ("Potential authority only: a claim says the source gives the agent a path to "
     "the tool, not that any runtime will grant or has granted it."),
    ("Delegation scope compares tool-name sets at each end of the edge. It does not "
     "show that a runtime narrows, checks or enforces the delegated scope."),
    ("Capabilities come from calls in the tool function's own body; helpers the tool "
     "calls are not followed."),
    "An identity link is established only by configuration in the repository.",
)


class CollabError(Exception):
    """A scenario, record or argument that does not meet the draft spec."""


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

def load_scenario(directory):
    """Read and validate ``scenario.yml`` in a scenario directory."""
    path = Path(directory) / "scenario.yml"
    if not path.is_file():
        raise CollabError(f"{directory}: no scenario.yml")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    problems = scenario_problems(doc, Path(directory))
    if problems:
        raise CollabError(f"{path}: " + "; ".join(problems))
    return doc


def scenario_problems(doc, directory):
    problems = []
    if doc.get("id") != directory.name:
        problems.append(f"id {doc.get('id')!r} does not match directory {directory.name!r}")
    for key in ("title", "question", "annotation", "intent"):
        if not doc.get(key):
            problems.append(f"missing {key}")
    if not (directory / "fixture").is_dir():
        problems.append("no fixture directory")
    annotation = doc.get("annotation") or {}
    if annotation.get("status") not in ("pending_human_review", "reviewed"):
        problems.append("annotation.status must be pending_human_review or reviewed")
    if annotation.get("status") == "reviewed" and not annotation.get("reviewers"):
        problems.append("a reviewed scenario names its reviewers")
    intent = doc.get("intent") or {}
    for item in intent.get("authority") or []:
        if not item.get("agent") or not item.get("tool"):
            problems.append(f"intent.authority item without agent or tool: {item}")
        if item.get("action") not in ACCESS_MODES:
            problems.append(f"intent.authority action not in {ACCESS_MODES}: {item}")
    for item in intent.get("delegations") or []:
        if item.get("scope") not in SCOPES:
            problems.append(f"intent.delegations scope not in {SCOPES}: {item}")
    for item in (doc.get("runtime") or {}).get("requests") or []:
        if item.get("expect_decision") not in DECISIONS:
            problems.append(f"runtime.requests expect_decision not in {DECISIONS}: {item}")
    for item in doc.get("expected_outcomes") or []:
        if item.get("outcome") not in OUTCOMES:
            problems.append(f"expected_outcomes outcome not in {OUTCOMES}: {item}")
    return problems


def scenario_dirs(root=SCENARIOS):
    return sorted(p for p in Path(root).iterdir() if (p / "scenario.yml").is_file())


# --------------------------------------------------------------------------
# Static evidence record
# --------------------------------------------------------------------------

def _loc(file, line):
    return {"file": str(file or "").replace("\\", "/"), "line": int(line or 0)}


def _tool_capabilities(report):
    """``{tool name: [capability dict]}`` from the attributed tool surface."""
    out = {}
    for entry in report.get("tool_surface") or []:
        tool = entry.get("tool") or {}
        if tool.get("kind") != "tool" or not tool.get("name"):
            continue
        out[tool["name"]] = [
            {"name": cap["name"], "access_mode": cap["access_mode"],
             "inferred": bool(cap.get("inferred")),
             "evidence": [_loc(e.get("path"), e.get("line")) for e in cap.get("evidence") or []]}
            for cap in entry.get("capabilities") or []
        ]
    return out


def _paths(start, edges):
    """Every acyclic delegation path from ``start``: ``[[start, a, b], ...]``."""
    out, stack = [], [[start]]
    while stack:
        path = stack.pop()
        for nxt in sorted(edges.get(path[-1], ())):
            if nxt in path:
                continue
            out.append(path + [nxt])
            stack.append(path + [nxt])
    return sorted(out)


def _scope(delegator_tools, delegate_tools):
    """How the delegate's tool set relates to the delegator's."""
    a, b = set(delegator_tools), set(delegate_tools)
    if b - a:
        return "broader_or_different"
    return "equal" if a == b else "narrower"


def static_record(scenario_id, report):
    """Build the provider-neutral static evidence record from a scan report."""
    graph = report.get("delegation_graph") or {}
    nodes = {n["id"]: n for n in graph.get("nodes") or [] if n.get("kind") == "agent"}
    name = {node_id: n["name"] for node_id, n in nodes.items()}
    tools_of = {n["name"]: list(n.get("authority") or []) for n in nodes.values()}
    caps = _tool_capabilities(report)
    edges = {}
    for edge in graph.get("edges") or []:
        if edge["from"] in name and edge["to"] in name:
            edges.setdefault(name[edge["from"]], set()).add(name[edge["to"]])

    claims = []
    for agent in sorted(tools_of):
        for path in [[agent]] + _paths(agent, edges):
            holder, via = path[-1], path[1:]
            for tool in sorted(tools_of.get(holder, ())):
                tool_caps = caps.get(tool, [])
                claims.append({
                    "id": f"tool_access:{'>'.join(path)}:{tool}",
                    "kind": "tool_access",
                    "agent": agent,
                    "tool": tool,
                    "via": via,
                    "status": "established",
                    "capabilities": tool_caps,
                    "capabilities_status": "detected" if tool_caps else "none_detected",
                })
    for edge in graph.get("edges") or []:
        if edge["from"] not in name or edge["to"] not in name:
            continue
        src, dst = name[edge["from"]], name[edge["to"]]
        claims.append({
            "id": f"delegation:{src}>{dst}",
            "kind": "delegation",
            "from": src,
            "to": dst,
            "mechanism": edge.get("kind"),
            "status": "established",
            "scope": _scope(tools_of[src], tools_of[dst]),
            "scope_basis": "tool-name sets",
            "delegate_exceeds_delegator": sorted(edge.get("exceeds") or []),
            "evidence": [_loc(e.get("file"), e.get("line")) for e in edge.get("evidence") or []],
        })
    for item in graph.get("unresolved") or []:
        src = name.get(item.get("from"), str(item.get("from") or "").rsplit(":", 1)[-1])
        claims.append({
            "id": f"delegation:{src}>?:{item.get('line', 0)}",
            "kind": "delegation",
            "from": src,
            "to": None,
            "mechanism": item.get("kind"),
            "status": "unresolved",
            "scope": "unknown",
            "reason": item.get("reason") or "target not statically resolvable",
            "evidence": [_loc(item.get("file") or item.get("source_file"), item.get("line"))],
        })

    iac = report.get("iac_correlations") or {}
    identities = [
        {"kind": i.get("kind"), "name": i.get("name"), "source": i.get("source_ref")}
        for i in iac.get("identities") or []
    ]
    links = iac.get("agent_identity_links") or []
    for agent in sorted(tools_of):
        link = next((ln for ln in links if ln.get("agent") in (agent, "<repo>")), None)
        if link:
            identity = link.get("identity") or {}
            claim = {"status": "established",
                     "principal": {"kind": identity.get("kind"), "name": identity.get("name")},
                     "link_scope": "agent" if link.get("agent") == agent else "repository",
                     "evidence": [_loc(e.get("file"), e.get("line"))
                                  for e in link.get("evidence") or []]}
        else:
            claim = {"status": "unresolved", "principal": None,
                     "reason": ("identity_present_not_linked" if identities
                                else "no_identity_in_repository")}
        claims.append({"id": f"identity_link:{agent}", "kind": "identity_link",
                       "agent": agent, **claim})

    return {
        "spec_version": SPEC_VERSION,
        "scenario": scenario_id,
        "producer": {"tool": "safeai", "kind": "static",
                     "version": (report.get("scanner_metadata") or {}).get("engine_version")},
        "agents": [
            {"id": n["name"], "framework": n.get("framework"),
             "source": _loc(n.get("source_file"), n.get("line"))}
            for n in sorted(nodes.values(), key=lambda n: n["name"])
        ],
        "identities": identities,
        "claims": sorted(claims, key=lambda c: c["id"]),
        "limits": list(STATIC_LIMITS),
    }


def scan_scenario(directory):
    from safeai.engine.orchestrator import run_scan

    return static_record(Path(directory).name, run_scan(str(Path(directory) / "fixture")))


def _dump(doc):
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _without_version(record):
    record = json.loads(json.dumps(record))
    record.get("producer", {}).pop("version", None)
    return record


# --------------------------------------------------------------------------
# Draft intent vs static evidence
# --------------------------------------------------------------------------

def intent_coverage(scenario, record):
    """Which intended authority paths the static record establishes.

    The intent is a draft until humans on both sides review it, so this is
    a consistency check on the scenario, not a measurement.
    """
    def key(agent, tool, via):
        return (agent, tool, tuple(via or ()))

    intended = {key(i["agent"], i["tool"], i.get("via"))
                for i in (scenario.get("intent") or {}).get("authority") or []}
    found = {key(c["agent"], c["tool"], c["via"])
             for c in record["claims"] if c["kind"] == "tool_access"}
    return {"intended": len(intended), "established": len(intended & found),
            "missing": sorted(map(list, intended - found)),
            "not_in_intent": sorted(map(list, found - intended))}


# --------------------------------------------------------------------------
# Runtime observation record and comparison
# --------------------------------------------------------------------------

def runtime_problems(record):
    problems = []
    if record.get("spec_version") != SPEC_VERSION:
        problems.append(f"spec_version is not {SPEC_VERSION}")
    if (record.get("producer") or {}).get("kind") != "runtime":
        problems.append("producer.kind is not 'runtime'")
    seen = set()
    for obs in record.get("observations") or []:
        rid = obs.get("request_id")
        if not rid or rid in seen:
            problems.append(f"missing or duplicate request_id: {rid!r}")
        seen.add(rid)
        if not obs.get("agent") or not obs.get("tool"):
            problems.append(f"{rid}: observation without agent or tool")
        if obs.get("decision") not in DECISIONS:
            problems.append(f"{rid}: decision not in {DECISIONS}")
        if obs.get("execution", "unknown") not in EXECUTIONS:
            problems.append(f"{rid}: execution not in {EXECUTIONS}")
        if obs.get("effect", "unknown") not in EFFECTS:
            problems.append(f"{rid}: effect not in {EFFECTS}")
    return problems


def classify(claim, obs):
    """``(outcome, reason)`` for one comparison unit.

    ``claim`` is the static ``tool_access`` claim for the unit, or ``None``.
    ``obs`` is one runtime observation, or ``None`` when the unit was never
    requested at run time. The rules are ordered; the first that applies
    wins. See SPEC.md, "Outcome rules".
    """
    if obs is None:
        return "insufficient_evidence", "not_tested"
    if not obs.get("principal"):
        return "insufficient_evidence", "principal_unresolved"
    if claim is not None and claim.get("status") != "established":
        return "insufficient_evidence", "static_unresolved"
    execution = obs.get("execution", "unknown")
    effect = obs.get("effect", "unknown")
    if obs["decision"] == "DENY":
        if execution == "executed" or effect == "observed":
            return "disagreement", "denied_but_effect_observed"
        return "agreement", ("potential_restricted" if claim else "absent_and_denied")
    if claim is None:
        return "disagreement", "permitted_without_static_path"
    if effect == "observed":
        return "agreement", "potential_exercised"
    return "insufficient_evidence", "effect_unverified"


def compare(static, runtime):
    """Rows and a summary for one scenario. Every unit stays in the total."""
    problems = runtime_problems(runtime)
    if problems:
        raise CollabError(f"runtime record for {runtime.get('scenario')}: "
                          + "; ".join(problems))
    if static["scenario"] != runtime.get("scenario"):
        raise CollabError("static and runtime records are for different scenarios")
    claims = {}
    for claim in static["claims"]:
        if claim["kind"] == "tool_access":
            unit = (claim["agent"], claim["tool"])
            # The shortest path represents the unit; the others stay in the record.
            if unit not in claims or len(claim["via"]) < len(claims[unit]["via"]):
                claims[unit] = claim
    rows, observed = [], set()
    for obs in sorted(runtime.get("observations") or [], key=lambda o: o["request_id"]):
        unit = (obs["agent"], obs["tool"])
        observed.add(unit)
        claim = claims.get(unit)
        outcome, reason = classify(claim, obs)
        rows.append({"agent": unit[0], "tool": unit[1],
                     "via": claim["via"] if claim else None,
                     "static_claim": claim["id"] if claim else None,
                     "request_id": obs["request_id"], "decision": obs["decision"],
                     "outcome": outcome, "reason": reason})
    for unit in sorted(set(claims) - observed):
        outcome, reason = classify(claims[unit], None)
        rows.append({"agent": unit[0], "tool": unit[1], "via": claims[unit]["via"],
                     "static_claim": claims[unit]["id"], "request_id": None,
                     "decision": None, "outcome": outcome, "reason": reason})
    return {"scenario": static["scenario"], "rows": rows, "summary": summarize(rows)}


def summarize(rows):
    counts = {o: sum(1 for r in rows if r["outcome"] == o) for o in OUTCOMES}
    resolved = counts["agreement"] + counts["disagreement"]
    reasons = {}
    for row in rows:
        reasons[row["reason"]] = reasons.get(row["reason"], 0) + 1
    return {
        "units": len(rows),
        **counts,
        "resolved": resolved,
        # Both denominators are reported: a rate over resolved units must
        # not hide how many units stayed unresolved.
        "agreement_over_resolved": f"{counts['agreement']}/{resolved}",
        "agreement_over_all_units": f"{counts['agreement']}/{len(rows)}",
        "reasons": dict(sorted(reasons.items())),
    }


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_static(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for directory in scenario_dirs(args.scenarios):
        scenario = load_scenario(directory)
        record = scan_scenario(directory)
        (out / f"{directory.name}.json").write_text(_dump(record), encoding="utf-8",
                                                    newline="\n")
        cover = intent_coverage(scenario, record)
        print(f"{directory.name}: {len(record['claims'])} claims; draft intent "
              f"{cover['established']}/{cover['intended']} established")
    return 0


def cmd_check(args):
    failed = False
    for directory in scenario_dirs(args.scenarios):
        try:
            scenario = load_scenario(directory)
        except CollabError as exc:
            print(f"FAIL {exc}")
            failed = True
            continue
        record = scan_scenario(directory)
        path = Path(args.records) / f"{directory.name}.json"
        if not path.is_file():
            print(f"FAIL {directory.name}: no static record at {path}")
            failed = True
            continue
        committed = json.loads(path.read_text(encoding="utf-8"))
        if _without_version(committed) != _without_version(record):
            print(f"FAIL {directory.name}: static record is out of date; "
                  f"run `collab_evidence.py static`")
            failed = True
            continue
        cover = intent_coverage(scenario, record)
        status = (scenario.get("annotation") or {}).get("status")
        print(f"ok   {directory.name}: intent {cover['established']}/{cover['intended']} "
              f"established, {len(cover['not_in_intent'])} not in intent ({status})")
    return 1 if failed else 0


def cmd_compare(args):
    results = []
    for path in sorted(Path(args.runtime).glob("*.json")):
        runtime = json.loads(path.read_text(encoding="utf-8"))
        static_path = Path(args.records) / f"{runtime.get('scenario')}.json"
        if not static_path.is_file():
            raise CollabError(f"{path}: no static record for {runtime.get('scenario')!r}")
        results.append(compare(json.loads(static_path.read_text(encoding="utf-8")), runtime))
    if not results:
        raise CollabError(f"no runtime observation records in {args.runtime}")
    total = summarize([row for result in results for row in result["rows"]])
    for result in results:
        print(f"\n{result['scenario']}")
        for row in result["rows"]:
            via = ">".join(row["via"]) if row["via"] else "direct" if row["via"] == [] else "-"
            print(f"  {row['agent']:>10} -> {row['tool']:<18} via {via:<10} "
                  f"{row['decision'] or 'untested':<8} {row['outcome']} ({row['reason']})")
    print(f"\nAll scenarios: {total['units']} units; agreement {total['agreement']}, "
          f"disagreement {total['disagreement']}, insufficient evidence "
          f"{total['insufficient_evidence']}")
    print(f"Agreement over resolved units: {total['agreement_over_resolved']}; "
          f"over all units: {total['agreement_over_all_units']}")
    if args.json:
        Path(args.json).write_text(_dump({"spec_version": SPEC_VERSION, "scenarios": results,
                                          "summary": total}), encoding="utf-8", newline="\n")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name, func in (("static", cmd_static), ("check", cmd_check), ("compare", cmd_compare)):
        cmd = sub.add_parser(name)
        cmd.set_defaults(func=func)
        cmd.add_argument("--scenarios", default=str(SCENARIOS))
        if name == "static":
            cmd.add_argument("--out", default=str(STATIC_RECORDS))
        else:
            cmd.add_argument("--records", default=str(STATIC_RECORDS))
        if name == "compare":
            cmd.add_argument("--runtime", required=True,
                             help="directory of runtime observation records (*.json)")
            cmd.add_argument("--json", help="write the comparison as JSON")
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CollabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
