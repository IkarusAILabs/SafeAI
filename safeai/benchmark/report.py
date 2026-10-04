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


def _coverage_row(name, res):
    """Accuracy-vs-coverage row: resolvable P/R/F1 plus the coverage split."""
    status = res.get("status") or "insufficient_evidence"
    if status != "measured":
        return (f"- {name}: n/a (insufficient evidence — fixture truth "
                f"asserts nothing here)")
    return (f"- {name}: resolvable precision {_cell(res.get('precision'))}, "
            f"resolvable recall {_cell(res.get('recall'))}, "
            f"F1 {_cell(res.get('f1'))}; applicable {res.get('applicable')}, "
            f"resolvable {res.get('resolvable')}, correctly resolved "
            f"{res.get('correct')}, contradicted {res.get('contradicted')}, "
            f"unresolved {res.get('unresolved')}; resolution coverage "
            f"{_cell(res.get('coverage'))}")


def _weakest(canon, top=3):
    """Weakest measured categories by recall, then coverage (auto triage)."""
    scored = []
    for section in ("entities", "attribution_levels"):
        for name, res in (canon.get(section) or {}).items():
            if res.get("status") == "measured":
                recall = res.get("recall")
                coverage = res.get("coverage")
                key = (recall if recall is not None else 2.0,
                       coverage if coverage is not None else 2.0)
                scored.append((key, f"{section}/{name}"))
    for name in ("change_detection", "escalation_detection"):
        res = canon.get(name) or {}
        if res.get("status") == "measured" and res.get("recall") is not None:
            scored.append(((res["recall"], 2.0), name))
    scored.sort(key=lambda item: item[0])
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
    provenance = metrics.get("provenance") or {}
    cases = aggregate.get("cases") or []
    legacy = metrics.get("attribution") or {}
    lines = []
    lines.append("# Authority Evidence Validation — benchmark report")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    lines.append("v2.6 Authority Evidence Validation.")
    lines.append(
        f"Overall status: {classes.get('overall', 'RESEARCH / NOT LANE-A READY')}")
    lines.append(
        f"Lane-A status: {classes.get('overall', 'RESEARCH / NOT LANE-A READY')}")
    lines.append(
        f"Major strengths: rule-level detection P/R/F1 1.0; resolvable "
        f"attribution exact wherever the model reaches; determinism "
        f"{(metrics.get('determinism') or {}).get('rate')}; evidence "
        f"completeness "
        f"{(metrics.get('evidence_completeness') or {}).get('completeness')}.")
    lines.append(
        f"Major limitations: end-to-end exercised authority attribution "
        f"coverage {legacy.get('end_to_end')} "
        f"({legacy.get('matched')}/{legacy.get('expected')}); "
        f"{canon.get('surface_blind', 0)} surface-blind material changes; "
        f"{metrics.get('unknown_unresolved_count')} observed "
        f"unknown/unresolved items veto graduation.")
    lines.append("")
    lines.append(
        "This report measures SafeAI on a fixed offline corpus "
        f"({summary.get('total', 0)} cases: "
        f"{summary.get('passed', 0)} passed, "
        f"{summary.get('failed', 0)} mismatched); it is not a claim about "
        "arbitrary customer scans, and benchmark numbers never belong in "
        "customer reports. 'Rule-level detection' counts fired rules "
        "only. 'Observed false-escalation rate on benchmark corpus' is "
        "exactly that — corpus-observed, not universal. Accuracy "
        "(resolvable P/R) and coverage (share of applicable expectations "
        "resolved) are distinct properties; both are shown everywhere."
    )
    lines.append("")
    lines.append("## Discovery")
    lines.append("")
    lines.append(
        "Entity rows verify harness calibration against reviewed truth: "
        "they move only when the scanner or the truth changes, which is "
        "their scientific use. They are not product accuracy guarantees. "
        "Coverage here equals recall (detection has no unresolvable "
        "marking); the attribution section below is where coverage bites."
    )
    lines.append("")
    lines.append(
        "| Entity | TP | FP | FN | Precision | Recall | F1 | Coverage |")
    lines.append(
        "| --- | --- | --- | --- | --- | --- | --- | --- |")
    for name, res in (canon.get("entities") or {}).items():
        if (res.get("status") or "") != "measured":
            lines.append(f"| {name} | n/a (insufficient evidence) "
                         f"| | | | | | |")
            continue
        lines.append(
            f"| {name} | {res.get('true_positives')} | "
            f"{res.get('false_positives')} | {res.get('false_negatives')} | "
            f"{_cell(res.get('precision'))} | {_cell(res.get('recall'))} | "
            f"{_cell(res.get('f1'))} | {_cell(res.get('coverage'))} |")
    rule = metrics.get("discovery") or {}
    lines.append(
        f"| rule-level detection (rules only, not authority) | "
        f"{rule.get('true_positives')} | {rule.get('false_positives')} | "
        f"{rule.get('false_negatives')} | {rule.get('precision')} | "
        f"{rule.get('recall')} | {rule.get('f1')} | n/a |")
    lines.append("")
    lines.append("## Attribution")
    lines.append("")
    lines.append(
        "Resolvable accuracy is exactness within the model's reach; "
        "resolution coverage is share of ALL applicable expectations "
        "resolved (unresolved items count in coverage, never as silent "
        "passes; contradicted items always fail the case)."
    )
    for name, res in (canon.get("attribution_levels") or {}).items():
        lines.append(_coverage_row(f"Resolvable {name} attribution", res))
    lines.append(
        f"- End-to-end exercised authority attribution coverage: "
        f"{legacy.get('end_to_end')} "
        f"({legacy.get('matched')}/{legacy.get('expected')} exercised "
        f"capabilities correctly attributed end to end; "
        f"{(legacy.get('expected') or 0) - (legacy.get('matched') or 0)} "
        f"unresolved, mostly code-defined tools in unknown:unattributed). "
        f"This is the blind-spot metric: it must stay visible. "
        f"Attributable-only accuracy (resolvable subset): "
        f"{legacy.get('attributable_accuracy')} "
        f"({legacy.get('attributable_matched')}/"
        f"{legacy.get('attributable_expected')})."
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
            f"- False escalation (observed rate on benchmark corpus): "
            f"{fer.get('value')}")
    else:
        lines.append(
            "- False escalation (observed rate on benchmark corpus): n/a "
            f"({fer.get('reason') or 'insufficient evidence'})")
    mmr = canon.get("missed_material_rate") or {}
    if mmr.get("status") == "measured":
        lines.append(f"- Missed material change: {mmr.get('value')}")
    else:
        lines.append(
            "- Missed material change: n/a "
            f"({mmr.get('reason') or 'insufficient evidence'})")
    lines.append(
        f"- Surface-blind cases: {canon.get('surface_blind', 0)} "
        f"({canon.get('surface_blind_escalations', 0)} of them escalations)")
    lines.append("")
    lines.append("Important:")
    lines.append("Surface-blind cases are changes represented in the "
                 "benchmark truth that the current SafeAI analysis surface "
                 "does not attempt to evaluate (detection rests on the "
                 "findings/summary channels instead). A material-change or "
                 "escalation F1 of 1.0 covers only surface-expected changes; "
                 "it must never be read as SafeAI detecting every possible "
                 "authority change.")
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
            f"- UNKNOWN recall: {unknown.get('recall')} "
            f"({unknown.get('true_positives')}/"
            f"{unknown.get('true_positives') + unknown.get('false_negatives')}; "
            f"UNKNOWN/UNVERIFIED_LINK/PARTIAL/INFERRED/UNRESOLVED all stay "
            f"expressed, never downgraded to safe)")
    else:
        lines.append("- UNKNOWN recall: n/a (insufficient evidence)")
    lines.append(
        "- UNVERIFIED handling: UNVERIFIED_LINK verdicts and unlinked "
        "pools preserved (see UNKNOWN recall); repo-level links without "
        "tool-scoped need stay UNKNOWN, never MATCH.")
    determinism = metrics.get("determinism") or {}
    lines.append(
        f"- Determinism: {determinism.get('rate')} "
        f"({determinism.get('clean')}/{determinism.get('checked')} "
        f"cases clean; repeat + order-shuffle; aggregate digest "
        f"{aggregate.get('digest', 'n/a')})"
    )
    lines.append(
        f"- Unknown/unresolved observed: {metrics.get('unknown_unresolved_count')}")
    lines.append("")
    lines.append("## Gold provenance")
    lines.append("")
    prov_cases = provenance.get("cases") or {}
    lines.append(
        f"- Total benchmark cases: {provenance.get('total', len(cases))}")
    lines.append(
        f"- Independently annotated cases: "
        f"{prov_cases.get('independent_annotation', 0)}")
    lines.append(
        f"- Legacy-migrated cases: "
        f"{prov_cases.get('migrated_from_legacy', 0)}")
    other = sum(v for k, v in prov_cases.items()
                if k not in ("independent_annotation",
                             "migrated_from_legacy"))
    lines.append(f"- Other derivation types: {other}")
    lines.append(
        "- Migrated status never passes or fails a case: provenance is "
        "transparency, not a score input. Canonical-vs-legacy "
        "contradictions fail loudly (gold contradiction) so drift "
        "cannot hide.")
    lines.append("")
    lines.append("## Lane-A graduation (PROPOSED targets, report-only)")
    lines.append("")
    for cls in classes.get("classes") or []:
        lines.append(
            f"- {cls.get('class')}: {cls.get('status')} "
            f"(precision {cls.get('precision')}, recall {cls.get('recall')}, "
            f"coverage {cls.get('coverage')}; targets P "
            f"{cls.get('precision_target')} R {cls.get('recall_target')} "
            f"coverage-floor {cls.get('coverage_floor')} PROPOSED)"
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
        f"- End-to-end exercised authority attribution coverage "
        f"{legacy.get('end_to_end')}: "
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
