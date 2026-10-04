"""Validation report writers for the authority benchmark.

JSON is the machine-readable record; Markdown is the reviewer-facing
brief. Both describe the same aggregate dict produced by
``safeai.benchmark.metrics.aggregate``. Neither writer gates anything.
"""

import json


def to_dict(aggregate):
    """Return a JSON-serializable copy of the aggregate evaluation."""
    return json.loads(json.dumps(aggregate, default=str))


def write_json(aggregate, path):
    """Write the full aggregate evaluation as pretty-printed JSON.

    Keys are sorted so repeated runs byte-compare equal (determinism).
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(aggregate), fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def _cell(value):
    """Render a metric half: number, or n/a (insufficient evidence)."""
    return "n/a" if value is None else str(value)


def _row(name, res):
    status = res.get("status") or "insufficient_evidence"
    if status != "measured":
        return (f"- {name}: n/a (insufficient evidence — fixture truth "
                f"asserts nothing here)")
    return (f"- {name}: precision {_cell(res.get('precision'))}, "
            f"recall {_cell(res.get('recall'))}, F1 {_cell(res.get('f1'))} "
            f"(TP {res.get('true_positives')}, FP {res.get('false_positives')}, "
            f"FN {res.get('false_negatives')})")


def _weakest(canon, top=2):
    """Weakest measured categories by recall (research triage, automatic)."""
    scored = []
    for section in ("entities", "attribution_levels"):
        for name, res in (canon.get(section) or {}).items():
            if res.get("status") == "measured" and res.get("recall") is not None:
                scored.append((res["recall"], f"{section}/{name}"))
    for name in ("change_detection", "escalation_detection"):
        res = canon.get(name) or {}
        if res.get("status") == "measured" and res.get("recall") is not None:
            scored.append((res["recall"], name))
    scored.sort()
    return [name for _, name in scored[:top]]


def render_markdown(aggregate):
    """Render the aggregate evaluation as Markdown text.

    This is a research artifact about SafeAI ("how well SafeAI
    performs"); it never belongs inside a customer scan report
    ("your project"). Rates are observed-on-corpus, never universal
    product accuracy guarantees.
    """
    summary = aggregate.get("summary") or {}
    metrics = aggregate.get("metrics") or {}
    canon = metrics.get("canonical") or {}
    lane_a = metrics.get("lane_a") or {}
    classes = metrics.get("lane_a_classes") or {}
    cases = aggregate.get("cases") or []
    lines = []
    lines.append("# Authority Evidence Validation — benchmark report")
    lines.append("")
    lines.append(f"Status: {classes.get('overall', 'RESEARCH / NOT LANE-A READY')}")
    lines.append("")
    lines.append(
        "This report measures SafeAI on a fixed offline corpus "
        f"({summary.get('total', 0)} cases); it is not a claim about "
        "arbitrary customer scans. 'Rule-level detection' counts fired "
        "rules only. 'Observed false-escalation rate on benchmark "
        "corpus' is exactly that — corpus-observed, not universal."
    )
    lines.append("")
    lines.append(
        f"Cases: {summary.get('total', 0)} total, "
        f"{summary.get('passed', 0)} passed, "
        f"{summary.get('failed', 0)} mismatched."
    )
    lines.append("")
    lines.append("## Discovery (entity P/R/F1 on corpus; n/a = no gold truth)")
    lines.append("")
    lines.append(
        "Entity rows verify harness calibration against reviewed truth: "
        "they move only when the scanner or the truth changes, which is "
        "their scientific use. They are not product accuracy guarantees."
    )
    for name, res in (canon.get("entities") or {}).items():
        lines.append(_row(f"Entity {name}", res))
    rule = metrics.get("discovery") or {}
    lines.append(
        f"- Rule-level detection: precision {rule.get('precision')}, "
        f"recall {rule.get('recall')}, F1 {rule.get('f1')} "
        f"(TP {rule.get('true_positives')}, "
        f"FP {rule.get('false_positives')}, "
        f"FN {rule.get('false_negatives')}; rule firing only, "
        f"not authority discovery)"
    )
    lines.append("")
    lines.append("## Attribution (8 levels, P/R/F1 where gold permits)")
    lines.append("")
    for name, res in (canon.get("attribution_levels") or {}).items():
        lines.append(_row(f"Attribution {name}", res))
    legacy = metrics.get("attribution") or {}
    lines.append(
        f"- End-to-end legacy rate (incl. unattributed bucket): "
        f"{legacy.get('end_to_end')} "
        f"({legacy.get('matched')}/{legacy.get('expected')}); "
        f"attributable-only accuracy: "
        f"{legacy.get('attributable_accuracy')} "
        f"({legacy.get('attributable_matched')}/"
        f"{legacy.get('attributable_expected')})"
    )
    lines.append("")
    lines.append("## ChangeGuard (baseline pairs only)")
    lines.append("")
    lines.append(_row("Material change",
                      canon.get("change_detection") or {}))
    lines.append(_row("Escalation", canon.get("escalation_detection") or {}))
    fer = canon.get("false_escalation_rate") or {}
    if fer.get("status") == "measured":
        lines.append(
            f"- Observed false-escalation rate on benchmark corpus: "
            f"{fer.get('value')}")
    else:
        lines.append(
            "- Observed false-escalation rate on benchmark corpus: n/a "
            f"({fer.get('reason') or 'insufficient evidence'})")
    mmr = canon.get("missed_material_rate") or {}
    if mmr.get("status") == "measured":
        lines.append(f"- Missed material-change rate: {mmr.get('value')}")
    else:
        lines.append(
            "- Missed material-change rate: n/a "
            f"({mmr.get('reason') or 'insufficient evidence'})")
    lines.append(
        f"- Surface-blind material entries (explicitly out of the "
        f"surface model, detection via findings/summary): "
        f"{canon.get('surface_blind', 0)}")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    evidence = metrics.get("evidence_completeness") or {}
    lines.append(
        f"- Evidence completeness: {evidence.get('completeness')} "
        f"({evidence.get('matched')}/{evidence.get('expected')})")
    unknown = canon.get("unknown_preservation") or {}
    if unknown.get("status") == "measured":
        lines.append(
            f"- Unknown preservation recall: {unknown.get('recall')} "
            f"({unknown.get('true_positives')}/"
            f"{unknown.get('true_positives') + unknown.get('false_negatives')})")
    else:
        lines.append("- Unknown preservation recall: n/a (insufficient evidence)")
    determinism = metrics.get("determinism") or {}
    lines.append(
        f"- Determinism: {determinism.get('rate')} "
        f"({determinism.get('clean')}/{determinism.get('checked')} "
        f"cases clean)"
    )
    lines.append(
        f"- Unknown/unresolved observed: {metrics.get('unknown_unresolved_count')}")
    lines.append("")
    lines.append("## Lane-A graduation (PROPOSED targets, report-only)")
    lines.append("")
    for cls in classes.get("classes") or []:
        lines.append(
            f"- {cls.get('class')}: {cls.get('status')} "
            f"(precision {cls.get('precision')}, recall {cls.get('recall')}; "
            f"targets P {cls.get('precision_target')} "
            f"R {cls.get('recall_target')})"
            + (f" — {cls.get('extra')}" if cls.get("extra") else ""))
    lines.append(f"- Overall: {classes.get('overall')}")
    lines.append(f"- Note: {classes.get('note')}")
    lines.append(f"- Legacy global eligible (reference): {lane_a.get('eligible')}")
    for note in lane_a.get("notes") or []:
        lines.append(f"- Note: {note}")
    lines.append("")
    lines.append("## Known limitations (weakest measured categories first)")
    lines.append("")
    for name in _weakest(canon):
        lines.append(f"- Watch: {name}")
    lines.append(
        "- Primary limitation: agent-to-tool attribution "
        "(agent_uses_tool edges beyond the current model; counted, not hidden)")
    lines.append(
        "- Secondary limitation: infrastructure identity correlation "
        "without tool-scoped need (repo-level links yield UNKNOWN verdicts)")
    lines.append(
        f"- End-to-end legacy rate {legacy.get('end_to_end')}: "
        f"{(legacy.get('expected') or 0) - (legacy.get('matched') or 0)} "
        f"capabilities sit in unknown:unattributed (code-defined tools).")
    lines.append("")
    lines.append("## Cases")
    lines.append("")
    for result in cases:
        mark = "PASS" if result.get("passed") else "FAIL"
        lines.append(f"### [{mark}] {result.get('id')}")
        for failure in result.get("failures") or []:
            lines.append(f"- {failure}")
        if result.get("harness_error"):
            lines.append(f"- harness_error: {result['harness_error']}")
        lines.append("")
    return "\n".join(lines)


def write_markdown(aggregate, path):
    """Write the Markdown brief to ``path``."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(aggregate))
    return path
