"""Canonical benchmark tests: gold schema, entity/attribution/change/unknown
comparison, 8-area mutation sensitivity, determinism, customer separation.

All synthetic (no corpus scans): each test feeds a hand-built gold truth
plus a hand-built scanner report through the real comparison path and
asserts the harness measures honestly — hits pass, mutations fail.
"""

import json
import os

from safeai.benchmark import canonical as canon_mod
from safeai.benchmark import compare, metrics, report, runner

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _report(**over):
    base = {
        "tool_surface": [],
        "findings": [],
        "iac_correlations": {},
        "capability_diff": {"tools": []},
    }
    base.update(over)
    return base


def _v2(**over):
    doc = {"case": "test/only", "truth_schema_version": "2.0",
           "annotation": {"basis": "human_reviewed_source",
                          "confidence": "high",
                          "rationale": "synthetic unit truth"},
           "canonical": {}}
    doc["canonical"].update(over)
    return doc


# --- gold schema ---


def test_truth_schema_version_is_2():
    assert canon_mod.TRUTH_SCHEMA_VERSION == "2.0"


def test_validate_gold_catches_bad_outcomes():
    gold = canon_mod.blank_gold()
    gold["authority_statements"] = [{"domain": "aws:s3", "outcome": "SAFE"}]
    gold["changes"] = [{"subject": "x", "kind": "MAYBE",
                        "domain": "tool-surface", "status": "new",
                        "surface_expected": True}]
    gold["unknown_expectations"] = [{"area": "a", "expected": "SAFE",
                                     "match": "x"}]
    problems = canon_mod.validate_gold(gold)
    assert len(problems) == 3


def test_blank_gold_is_all_insufficient():
    gold, _ = canon_mod.gold_from_expected({})
    assert gold["agents"] is None
    result = canon_mod.compare_all(gold, canon_mod.project_report(_report()),
                                   _report(), None)
    assert result["failures"] == []
    for section in ("entities", "attribution"):
        for res in result["parts"][section].values():
            assert res["status"] == "insufficient_evidence"


def test_gold_never_encodes_scanner_keys():
    import glob

    for path in glob.glob(os.path.join(
            REPO_ROOT, "tests", "benchmarks", "authority", "*", "*",
            "expected", "expected.json")):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        canon = doc.get("canonical") or {}
        for tool in canon.get("tools") or []:
            assert ":" not in str(tool.get("id") or ""), (path, tool)
        for cap in canon.get("capabilities") or []:
            assert cap.get("tool") is None or ":" not in str(cap["tool"]), path


# --- entities ---


def test_entity_discovery_measures_fp_and_fn():
    expected = _v2(
        agents=[{"id": "a", "framework": "f", "name": "n"}],
        identities=[{"id": "i", "kind": "k", "name": "wanted", "namespace": ""}],
    )
    current = _report(
        agent_models=[{"framework": "f", "data": {"agents": [{"name": "n"}]}}],
        iac_correlations={"identities": [
            {"kind": "k", "name": "wanted", "namespace": ""},
            {"kind": "k", "name": "extra", "namespace": ""},
        ]},
    )
    result = compare.compare_case(expected, current)
    agents = result["parts"]["canonical"]["entities"]["agents"]
    assert (agents["true_positives"], agents["false_negatives"]) == (1, 0)
    idents = result["parts"]["canonical"]["entities"]["identities"]
    assert idents["false_positives"] == 1
    assert any("entity identities" in f for f in result["failures"])


# --- attribution levels ---


def test_capability_attribution_fn_when_tool_unresolved():
    expected = _v2(
        tools=[{"id": "deploy", "name": "deploy", "kind": "tool",
                "attributable": True}],
        capabilities=[{"tool": "deploy", "capability": "shell",
                       "access_mode": "execute",
                       "attribution": "attributed"}],
    )
    current = _report(tool_surface=[
        {"tool_key": "unknown:unattributed", "capabilities": [
            {"name": "shell", "access_mode": "execute"}]},
    ])
    result = compare.compare_case(expected, current)
    level = result["parts"]["canonical"]["attribution"]["capability"]
    assert level["false_negatives"] == 1
    assert not result["passed"]


def test_end_to_end_requires_complete_chain():
    expected = _v2(authority_statements=[
        {"capability": None, "domain": "aws:s3", "identity": None,
         "resource": None, "outcome": "UNKNOWN"}])
    current = _report(iac_correlations={"verdicts": [
        {"domain": "aws:s3", "verdict": "UNKNOWN"}]})
    result = compare.compare_case(expected, current)
    e2e = result["parts"]["canonical"]["attribution"]["end_to_end"]
    assert e2e["status"] == "insufficient_evidence"
    l7 = result["parts"]["canonical"]["attribution"]["capability_grant"]
    assert l7["true_positives"] == 1


# --- change ---


def test_change_without_baseline_is_insufficient():
    expected = _v2(changes=[
        {"subject": "x", "kind": "MATERIAL_CHANGE", "domain": "tool-surface",
         "evidence": [], "surface_expected": True}])
    result = compare.compare_case(expected, _report(), None)
    change = result["parts"]["canonical"]["change"]
    assert change["material_change"]["status"] == "insufficient_evidence"
    assert change["missed_material_rate"]["status"] == "insufficient_evidence"


def test_change_measures_hit_and_miss_on_synthetic_diff():
    def diffed(entries):
        return _report(capability_diff={"tools": entries})

    entry = {"tool_key": "mcp_server:shell", "status": "new",
             "change_class": "HIGH_RISK_CHANGE",
             "capabilities_added": [
                 {"name": "shell", "evidence": [{"path": "mcp.json"}]}],
             "capabilities_removed": []}
    expected = _v2(changes=[
        {"subject": "mcp_server:shell (mcp.json)",
         "kind": "AUTHORITY_ESCALATION", "status": "new",
         "domain": "tool-surface",
         "evidence": ["mcp.json"], "surface_expected": True}])
    hit = compare.compare_case(expected, diffed([entry]), _report())
    assert hit["passed"], hit["failures"]
    assert hit["parts"]["canonical"]["change"]["escalation"][
        "true_positives"] == 1
    missed = compare.compare_case(expected, diffed([]), _report())
    assert not missed["passed"]
    assert missed["parts"]["canonical"]["change"]["escalation"][
        "false_negatives"] == 1


def test_zero_rates_are_insufficient_not_zero():
    assert metrics.sum_prf([])["status"] == "insufficient_evidence"
    assert metrics.maybe_rate(0, 0) is None
    assert metrics.maybe_rate(1, 2) == 0.5


# --- 8-area mutation sensitivity ---

MUTATION_BASE = {
    "agents": [{"framework": "langchain", "name": "initialize_agent"}],
    "tools": [{"id": "storage", "name": "storage", "kind": "mcp_server",
               "attributable": True}],
    "capabilities": [
        {"tool": "storage", "capability": "cloud", "access_mode": "read",
         "attribution": "attributed"}],
    "identities": [{"id": "r", "kind": "aws_iam_role", "name": "agent-role",
                    "namespace": ""}],
    "grants": [{"identity": "agent-role", "identity_namespace": "",
                "actions": ["s3:GetObject"],
                "resources": ["arn:aws:s3:::agent-bucket/*"],
                "resolution": "resolved"}],
    "relationships": [
        {"type": "tool_has_capability", "tool": "storage",
         "capability": "cloud", "access_mode": "read", "resolvable": True},
        {"type": "agent_linked_identity", "agent": None,
         "identity": "agent-role", "identity_namespace": "",
         "resolvable": True},
        {"type": "capability_covered_by_grant", "capability": "cloud",
         "domain": "aws:s3", "outcome": "MATCH", "resolvable": True},
    ],
    "authority_statements": [
        {"capability": "cloud", "domain": "aws:s3", "identity": "agent-role",
         "resource": "arn:aws:s3:::agent-bucket/*", "outcome": "MATCH"}],
}


def _v2_legacy(**over):
    """v2 doc plus matching legacy agent section (legacy checks run too)."""
    doc = _v2(**over)
    agents = (over.get("agents") or [])
    doc["agents"] = [{"framework": a.get("framework"), "name": a.get("name")}
                     for a in agents if a.get("name")]
    return doc

SCAN_BASE = {
    "agent_models": [{"framework": "langchain",
                      "data": {"agents": [{"name": "initialize_agent"}]}}],
    "tool_surface": [{"tool_key": "mcp_server:storage", "capabilities": [
        {"name": "cloud", "access_mode": "read"}]}],
    "iac_correlations": {
        "identities": [{"kind": "aws_iam_role", "name": "agent-role",
                        "namespace": ""}],
        "grants": [{"identity": {"kind": "aws_iam_role", "name": "agent-role"},
                    "actions": {"values": ["s3:GetObject"],
                                "resolution": "resolved"},
                    "resources": {"values": ["arn:aws:s3:::agent-bucket/*"],
                                  "resolution": "resolved"}}],
        "agent_identity_links": [
            {"agent": "<repo>",
             "identity": {"kind": "aws_iam_role", "name": "agent-role",
                           "namespace": ""}}],
        "verdicts": [{"domain": "aws:s3", "verdict": "MATCH"}],
    },
}


def _clean_result():
    import copy

    return compare.compare_case(_v2_legacy(**copy.deepcopy(MUTATION_BASE)),
                                _report(**copy.deepcopy(SCAN_BASE)))


def test_mutation_baseline_passes():
    result = _clean_result()
    assert result["passed"], result["failures"]


def test_mutation_identity_matching():
    import copy

    scan = copy.deepcopy(SCAN_BASE)
    scan["iac_correlations"]["identities"][0]["name"] = "other-role"
    result = compare.compare_case(_v2_legacy(**copy.deepcopy(MUTATION_BASE)),
                                  _report(**scan))
    assert not result["passed"]
    assert any("identity" in f for f in result["failures"])


def test_mutation_namespace_isolation():
    import copy

    scan = copy.deepcopy(SCAN_BASE)
    scan["iac_correlations"]["identities"][0]["namespace"] = "prod"
    result = compare.compare_case(_v2_legacy(**copy.deepcopy(MUTATION_BASE)),
                                  _report(**scan))
    assert not result["passed"]


def test_mutation_wildcard_matching():
    import copy

    scan = copy.deepcopy(SCAN_BASE)
    scan["iac_correlations"]["grants"][0]["actions"]["values"] = ["s3:*"]
    result = compare.compare_case(_v2_legacy(**copy.deepcopy(MUTATION_BASE)),
                                  _report(**scan))
    assert not result["passed"]
    assert any("grant" in f for f in result["failures"])


def test_mutation_grant_extraction():
    import copy

    scan = copy.deepcopy(SCAN_BASE)
    scan["iac_correlations"]["grants"] = []
    result = compare.compare_case(_v2_legacy(**copy.deepcopy(MUTATION_BASE)),
                                  _report(**scan))
    assert not result["passed"]


def test_mutation_capability_attribution():
    import copy

    scan = copy.deepcopy(SCAN_BASE)
    scan["tool_surface"] = [{"tool_key": "unknown:unattributed",
                             "capabilities": [
                                 {"name": "cloud",
                                  "access_mode": "read"}]}]
    result = compare.compare_case(_v2_legacy(**copy.deepcopy(MUTATION_BASE)),
                                  _report(**scan))
    assert not result["passed"]
    assert any("capability" in f for f in result["failures"])


def test_mutation_authority_correlation():
    import copy

    scan = copy.deepcopy(SCAN_BASE)
    scan["iac_correlations"]["verdicts"][0]["verdict"] = "EXCESS_AUTHORITY"
    result = compare.compare_case(_v2_legacy(**copy.deepcopy(MUTATION_BASE)),
                                  _report(**scan))
    assert not result["passed"]


def test_mutation_change_classification():

    expected = _v2(changes=[
        {"subject": "mcp_server:storage (mcp.json)",
         "kind": "AUTHORITY_ESCALATION", "status": "new",
         "domain": "tool-surface", "evidence": ["mcp.json"],
         "surface_expected": True}])
    mutated = _report(capability_diff={"tools": [
        {"tool_key": "mcp_server:storage", "status": "new",
         "change_class": "LOW_CHANGE",
         "capabilities_added": [{"name": "shell",
                                  "evidence": [{"path": "mcp.json"}]}],
         "capabilities_removed": []}]})
    result = compare.compare_case(expected, mutated, _report())
    assert not result["passed"]
    assert any("misclassified" in f for f in result["failures"])


def test_mutation_unknown_handling_downgrade():
    import copy

    scan = copy.deepcopy(SCAN_BASE)
    scan["iac_correlations"]["verdicts"][0]["verdict"] = "MATCH"
    expected = _v2_legacy(**copy.deepcopy(MUTATION_BASE))
    expected["canonical"]["authority_statements"][0]["outcome"] = "UNKNOWN"
    expected["canonical"]["relationships"] = [
        r for r in expected["canonical"]["relationships"]
        if r["type"] != "capability_covered_by_grant"
    ] + [{"type": "capability_covered_by_grant", "capability": "cloud",
          "domain": "aws:s3", "outcome": "UNKNOWN", "resolvable": True}]
    result = compare.compare_case(expected, _report(**scan))
    assert not result["passed"]
    assert any("capability_grant" in f or "UNKNOWN" in f
               for f in result["failures"])


# --- UNKNOWN no-downgrade ---


def test_partial_requires_partially_resolved_evidence():
    expected = _v2(unknown_expectations=[
        {"area": "grant-content", "expected": "PARTIAL", "match": "x"}])
    result = compare.compare_case(expected, _report())
    assert not result["passed"]
    assert any("PARTIAL" in f for f in result["failures"])


def test_unknown_never_silently_safe():
    expected = _v2(
        authority_statements=[
            {"capability": None, "domain": "aws:s3", "identity": None,
             "resource": None, "outcome": "UNKNOWN"}],
        unknown_expectations=[
            {"area": "grant-linkage", "expected": "UNKNOWN",
             "match": "aws:s3"}],
    )
    current = _report(iac_correlations={"verdicts": [
        {"domain": "aws:s3", "verdict": "UNKNOWN"}]})
    result = compare.compare_case(expected, current)
    assert result["passed"], result["failures"]
    assert result["parts"]["canonical"]["unknown"]["preserved"] == {
        "expected": 1, "matched": 1}


# --- determinism ---


def test_lane_a_authority_gate_uses_end_to_end_and_veto():
    canon = {
        "entities": {"capabilities": {"precision": 1.0, "recall": 1.0,
                                      "status": "measured"}},
        "attribution_levels": {
            "identity": {"precision": 1.0, "recall": 1.0,
                         "status": "measured"}},
        "change_detection": {"precision": 1.0, "recall": 1.0,
                             "status": "measured"},
        "escalation_detection": {"precision": 1.0, "recall": 1.0,
                                 "status": "measured"},
        "false_escalation_rate": {"value": 0.0, "status": "measured"},
    }
    legacy = {"end_to_end": 0.464, "matched": 58, "expected": 125}
    out = metrics.check_lane_a_classes({"canonical": canon}, legacy, 10)
    by_class = {c["class"]: c for c in out["classes"]}
    assert by_class["authority_attribution"]["status"] == "LANE-B"
    assert "NOT LANE-A READY" in out["overall"]
    assert "vetoed by 10" in out["overall"]
    assert out["unknown_veto"] is True
    clean = metrics.check_lane_a_classes(
        {"canonical": canon}, {"end_to_end": 1.0, "matched": 5,
                               "expected": 5}, 0)
    assert clean["overall"] == "LANE-A READY"


def test_aggregate_digest_stable():
    first = metrics.aggregate(
        [{"id": "a/1", "category": "a", "passed": True, "failures": [],
          "parts": {}, "determinism": {"checked": False, "violations": []}}])
    second = metrics.aggregate(
        [{"id": "a/1", "category": "a", "passed": True, "failures": [],
          "parts": {}, "determinism": {"checked": False, "violations": []}}])
    assert first["digest"] == second["digest"]
    assert len(first["digest"]) == 64


def test_report_rendering_stable_and_sorted_json(tmp_path):
    agg = metrics.aggregate(
        [{"id": "b/2", "category": "b", "passed": False,
          "failures": ["boom"], "parts": {},
          "determinism": {"checked": False, "violations": []}},
         {"id": "a/1", "category": "a", "passed": True, "failures": [],
          "parts": {}, "determinism": {"checked": False,
                                       "violations": []}}])
    assert report.render_markdown(agg) == report.render_markdown(agg)
    first = str(tmp_path / "one.json")
    second = str(tmp_path / "two.json")
    report.write_json(agg, first)
    report.write_json(agg, second)
    with open(first, encoding="utf-8") as fh:
        first_text = fh.read()
    with open(second, encoding="utf-8") as fh:
        second_text = fh.read()
    assert first_text == second_text
    assert "RESEARCH / NOT LANE-A READY" in report.render_markdown(agg)


def test_discover_cases_sorted_and_canonical_projection_order_free():
    cases = runner.discover_cases(runner.default_corpus())
    assert [c["id"] for c in cases] == sorted(c["id"] for c in cases)
    first = _report(tool_surface=[
        {"tool_key": "b", "capabilities": []},
        {"tool_key": "a", "capabilities": []}])
    second = _report(tool_surface=[
        {"tool_key": "a", "capabilities": []},
        {"tool_key": "b", "capabilities": []}])
    assert runner.canonical_projection(first) == runner.canonical_projection(
        second)
    gold = canon_mod.gold_from_expected(
        {"canonical": {"tools": [{"id": "a", "attributable": True}]}})[0]
    assert canon_mod.project_report(first)["named_tools"].keys() == \
        canon_mod.project_report(second)["named_tools"].keys()
    assert gold["tools"] == [{"id": "a", "attributable": True}]


# --- customer separation ---


def test_customer_reports_contain_no_benchmark_numbers():
    import glob

    banned = ("benchmark", "lane_a", "lane-a", "attribution_accuracy",
              "false_escalation_rate", "canonical")
    hits = []
    for path in glob.glob(os.path.join(REPO_ROOT, "safeai", "report", "*.py")):
        with open(path, encoding="utf-8") as fh:
            text = fh.read().lower()
        for term in banned:
            if term in text:
                hits.append((os.path.basename(path), term))
    assert hits == [], hits
