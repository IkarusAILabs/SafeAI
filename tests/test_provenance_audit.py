"""Provenance audit over the authority benchmark corpus (v2.8, plan item 2.8-1).

Every finding, capability and per-tool authority statement that a real
scan emits must carry an enum-valid provenance class and a well-formed
evidence reference. #277 made the enums single-source and checked them
against the manifest schema; this checks the scanner's output against
them, case by case, so a detector that forgets provenance fails here
rather than silently landing in the ``unknown`` bucket of the evidence
metrics.
"""

import pytest

from safeai.benchmark.runner import default_corpus, discover_cases, scan_case
from safeai.kya.contract import (
    AUTHORITY_DIMENSIONS,
    GATEABILITY_VALUES,
    PROVENANCE_CLASSES,
)

CASES = discover_cases(default_corpus())


def _is_line(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _finding_problems(finding):
    where = f"finding {finding.get('rule_id')} at {finding.get('file')}:{finding.get('line')}"
    problems = []
    if finding.get("provenance_class") not in PROVENANCE_CLASSES:
        problems.append(f"{where}: provenance_class {finding.get('provenance_class')!r}")
    if finding.get("gateability") not in GATEABILITY_VALUES:
        problems.append(f"{where}: gateability {finding.get('gateability')!r}")
    if not isinstance(finding.get("file"), str) or not finding["file"]:
        problems.append(f"{where}: file {finding.get('file')!r}")
    if not _is_line(finding.get("line")):
        problems.append(f"{where}: line {finding.get('line')!r}")
    return problems


def _capability_problems(tool_key, capability):
    where = f"capability {capability.get('name')!r} on {tool_key}"
    problems = []
    if not capability.get("name"):
        problems.append(f"{where}: no name")
    if not isinstance(capability.get("inferred"), bool):
        problems.append(f"{where}: inferred {capability.get('inferred')!r}")
    evidence = capability.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        problems.append(f"{where}: no evidence refs")
        return problems
    for ref in evidence:
        if not isinstance(ref, dict) or not isinstance(ref.get("path"), str) or not ref["path"]:
            problems.append(f"{where}: evidence ref {ref!r}")
        elif not _is_line(ref.get("line")):
            problems.append(f"{where}: evidence line {ref.get('line')!r}")
    return problems


def _authority_problems(tool):
    authority = tool.get("authority")
    if authority is None:
        return []
    where = f"authority of {tool.get('tool_key')}"
    problems = []
    for capability in authority.get("capabilities") or []:
        if capability.get("provenance_class") not in PROVENANCE_CLASSES:
            problems.append(
                f"{where}: capability {capability.get('name')!r} "
                f"provenance_class {capability.get('provenance_class')!r}"
            )
    for dimension in AUTHORITY_DIMENSIONS:
        block = authority.get(dimension)
        if not isinstance(block, dict):
            problems.append(f"{where}: dimension {dimension} missing")
        elif block.get("provenance_class") not in PROVENANCE_CLASSES:
            problems.append(
                f"{where}: dimension {dimension} provenance_class {block.get('provenance_class')!r}"
            )
    return problems


def audit_report(report):
    """Every provenance problem in one JSON report, as readable strings."""
    problems = []
    for finding in report.get("findings") or []:
        problems += _finding_problems(finding)
    for tool in report.get("tool_surface") or []:
        for capability in tool.get("capabilities") or []:
            problems += _capability_problems(tool.get("tool_key"), capability)
    diff = report.get("capability_diff") or {}
    tools = list(diff.get("tools") or [])
    if isinstance(diff.get("unattributed"), dict):
        tools.append(diff["unattributed"])
    for tool in tools:
        problems += _authority_problems(tool)
    return problems


def test_corpus_is_present():
    assert len(CASES) >= 58


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_every_emitted_statement_carries_valid_provenance(case, tmp_path, capsys):
    current, baseline = scan_case(case["dir"], str(tmp_path))
    capsys.readouterr()  # the scan's terminal summary is not under test
    problems = audit_report(current)
    if baseline is not None:
        problems += [f"baseline: {p}" for p in audit_report(baseline)]
    assert problems == []


def test_audit_reports_out_of_contract_values():
    report = {
        "findings": [{"rule_id": "X", "file": "", "line": -1,
                      "provenance_class": "guessed", "gateability": "maybe"}],
        "tool_surface": [{"tool_key": "t", "capabilities": [
            {"name": "shell", "inferred": "no", "evidence": [{"path": "a.py", "line": None}]}]}],
        "capability_diff": {"tools": [{"tool_key": "t", "authority": {
            "capabilities": [{"name": "shell", "provenance_class": None}],
            "destinations": {"values": [], "provenance_class": "unknown"}}}]},
    }
    problems = audit_report(report)
    assert any("provenance_class 'guessed'" in p for p in problems)
    assert any("gateability 'maybe'" in p for p in problems)
    assert any("file ''" in p for p in problems)
    assert any("line -1" in p for p in problems)
    assert any("inferred 'no'" in p for p in problems)
    assert any("evidence line None" in p for p in problems)
    assert any("capability 'shell' provenance_class None" in p for p in problems)
    assert any("dimension identity missing" in p for p in problems)
