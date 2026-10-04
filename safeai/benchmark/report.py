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
    """Write the full aggregate evaluation as pretty-printed JSON."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(aggregate), fh, indent=2, sort_keys=False)
        fh.write("\n")
    return path


def render_markdown(aggregate):
    """Render the aggregate evaluation as Markdown text."""
    summary = aggregate.get("summary") or {}
    metrics = aggregate.get("metrics") or {}
    lane_a = aggregate.get("lane_a") or {}
    cases = aggregate.get("cases") or []
    lines = []
    lines.append("# Authority Evidence Validation — benchmark report")
    lines.append("")
    lines.append(
        f"Cases: {summary.get('total', 0)} total, "
        f"{summary.get('passed', 0)} passed, "
        f"{summary.get('failed', 0)} mismatched."
    )
    lines.append("")
    lines.append("## Corpus metrics (measured, not targets)")
    lines.append("")
    discovery = metrics.get("discovery") or {}
    lines.append(
        f"- Discovery: precision {discovery.get('precision')}, "
        f"recall {discovery.get('recall')}, "
        f"F1 {discovery.get('f1')} "
        f"(TP {discovery.get('true_positives')}, "
        f"FP {discovery.get('false_positives')}, "
        f"FN {discovery.get('false_negatives')})"
    )
    lines.append(f"- Tool recall: {metrics.get('tool_recall')}")
    lines.append(f"- Capability recall: {metrics.get('capability_recall')}")
    attribution = metrics.get("attribution") or {}
    lines.append(
        f"- Attribution end-to-end (incl. unattributed bucket): "
        f"{attribution.get('end_to_end')} "
        f"({attribution.get('matched')}/"
        f"{attribution.get('expected')}); "
        f"attributable-only accuracy: "
        f"{attribution.get('attributable_accuracy')} "
        f"({attribution.get('attributable_matched')}/"
        f"{attribution.get('attributable_expected')})"
    )
    change = metrics.get("change") or {}
    lines.append(
        f"- False escalation rate: "
        f"{change.get('false_escalation_rate')} "
        f"({change.get('false_escalations')}/"
        f"{change.get('observed_escalations')} observed)"
    )
    evidence = metrics.get("evidence_completeness") or {}
    lines.append(
        f"- Evidence completeness: "
        f"{evidence.get('completeness')} "
        f"({evidence.get('matched')}/{evidence.get('expected')})"
    )
    uncertainty = metrics.get("uncertainty_expression") or {}
    lines.append(
        f"- Uncertainty expression recall: "
        f"{uncertainty.get('recall')} "
        f"({uncertainty.get('matched')}/"
        f"{uncertainty.get('expected')})"
    )
    determinism = metrics.get("determinism") or {}
    lines.append(
        f"- Determinism: {determinism.get('rate')} "
        f"({determinism.get('clean')}/{determinism.get('checked')} "
        f"cases clean)"
    )
    lines.append(
        f"- Unknown/unresolved observed: {metrics.get('unknown_unresolved_count')}"
    )
    lines.append("")
    lines.append("## Lane-A graduation (PROPOSED targets, report-only)")
    lines.append("")
    lines.append(f"Eligible: {lane_a.get('eligible')}")
    for gate in lane_a.get("gates") or []:
        mark = "PASS" if gate.get("passed") else "FAIL"
        lines.append(
            f"- [{mark}] {gate.get('name')}: {gate.get('value')} "
            f"(target {gate.get('threshold')})"
        )
    for note in lane_a.get("notes") or []:
        lines.append(f"- Note: {note}")
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
