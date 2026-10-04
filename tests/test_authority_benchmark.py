"""Authority benchmark unit tests: metrics, comparison, aggregation, reports.

Pure-function tests only (no corpus scans); corpus execution is
exercised via ``safeai benchmark`` itself.
"""

import json
import os

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


# --- metrics ---


def test_prf_zero_division_never_nan():
    out = metrics.prf(0, 0, 0)
    assert out == {
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
    }


def test_prf_perfect():
    out = metrics.prf(3, 0, 0)
    assert out["precision"] == 1.0 and out["recall"] == 1.0
    assert out["f1"] == 1.0


def test_rate_bounded_and_empty_safe():
    assert metrics.rate(5, 0) == 0.0
    assert metrics.rate(7, 4) == 1.0
    assert metrics.rate(-1, 4) == 0.0
    assert metrics.rate(1, 4) == 0.25


def test_materiality_mapping_spots():
    assert metrics.materiality("new", "HIGH_RISK_CHANGE") == "AUTHORITY_ESCALATION"
    assert metrics.materiality("removed", "MATERIAL_CHANGE") == "AUTHORITY_REDUCTION"
    assert metrics.materiality("changed", "MATERIAL_CHANGE") == "MATERIAL_CHANGE"
    assert metrics.materiality("new", "UNKNOWN") == "UNKNOWN_CHANGE"
    assert metrics.materiality("bogus", "bogus") == "UNKNOWN_CHANGE"


def test_lane_a_targets_labeled_proposed():
    assert "PROPOSED" in metrics.LANE_A_TARGETS["_status"]


def test_check_lane_a_reports_without_gating():
    lane = metrics.check_lane_a({})
    assert lane["eligible"] is False
    assert lane["gates"], "gates must be enumerated even when empty"
    assert any("PROPOSED" in n for n in lane["notes"])


# --- compare ---


def test_compare_must_fire_hit_and_miss():
    current = _report(
        findings=[
            {"rule_id": "CAP_shell", "file": "a.py", "line": 1, "status": "existing"}
        ]
    )
    ok = compare.compare_case(
        {"must_fire": ["CAP_shell"], "must_not_fire": ["NOPE"]}, current
    )
    assert ok["passed"], ok["failures"]
    assert ok["parts"]["must_fire"] == {
        "expected": 1,
        "matched": 1,
        "false_positives": 0,
    }
    bad = compare.compare_case(
        {"must_fire": ["CAP_shell", "MISSING"], "must_not_fire": ["CAP_shell"]}, current
    )
    assert not bad["passed"]
    assert any("MISSING" in f for f in bad["failures"])
    assert any("must_not_fire" in f for f in bad["failures"])


def test_compare_evidence_and_uncertainty():
    current = _report(
        findings=[{"rule_id": "R", "file": "agent.py", "line": 1}],
        tool_surface=[
            {
                "tool_key": "unknown:unattributed",
                "capabilities": [
                    {
                        "name": "planner_chain",
                        "access_mode": "read",
                        "inferred": True,
                        "evidence": [{"path": "agent.py"}],
                    }
                ],
            }
        ],
    )
    result = compare.compare_case(
        {
            "evidence_refs": ["agent.py", "ghost.tf"],
            "uncertainty": [
                {"kind": "inferred", "match": "planner_chain"},
                {"kind": "unknown", "match": "aws:s3"},
            ],
        },
        current,
    )
    assert not result["passed"]
    assert any("ghost.tf" in f for f in result["failures"])
    assert any("aws:s3" in f for f in result["failures"])
    assert result["parts"]["evidence"] == {"expected": 2, "matched": 1}
    assert result["parts"]["uncertainty"] == {"expected": 2, "matched": 1}


def test_compare_changes_findings_channel():
    current = _report(
        findings=[{"rule_id": "CAP_shell", "file": "a.py", "line": 2, "status": "new"}],
        baseline={"new": 1, "existing": 0, "resolved": 0, "new_high_critical": []},
    )
    entry = {
        "tool": "x",
        "status": "new",
        "materiality": "AUTHORITY_ESCALATION",
        "channels": ["findings"],
        "new_findings": ["CAP_shell"],
    }
    result = compare.compare_case({"changes": [entry]}, current)
    assert result["passed"], result["failures"]
    assert result["parts"]["changes"]["matched"] == 1
    entry["new_findings"] = ["CAP_shell", "ABSENT_RULE"]
    result = compare.compare_case({"changes": [entry]}, current)
    assert not result["passed"]


def test_compare_changes_summary_channel_removed():
    current = _report(
        baseline={"new": 0, "existing": 0, "resolved": 1, "new_high_critical": []}
    )
    entry = {
        "tool": "gone tool",
        "status": "removed",
        "materiality": "AUTHORITY_REDUCTION",
        "channels": ["summary"],
        "new_findings": [],
    }
    result = compare.compare_case({"changes": [entry]}, current)
    assert result["passed"], result["failures"]
    current["baseline"]["resolved"] = 0
    result = compare.compare_case({"changes": [entry]}, current)
    assert not result["passed"]


def test_compare_false_escalation_detected():
    current = _report(
        capability_diff={
            "tools": [
                {"tool_key": "k", "status": "new", "change_class": "HIGH_RISK_CHANGE"}
            ]
        }
    )
    result = compare.compare_case({}, current)
    assert not result["passed"]
    assert any("false escalation" in f for f in result["failures"])
    assert result["parts"]["escalations"]["false"] == 1


def test_compare_empty_expected_passes_quiet_report():
    result = compare.compare_case({}, _report())
    assert result["passed"], result["failures"]


def test_attribution_split_counts_unattributed_bucket():
    current = _report(
        tool_surface=[
            {
                "tool_key": "tool:a",
                "capabilities": [{"name": "shell", "access_mode": "execute"}],
            },
            {
                "tool_key": "unknown:unattributed",
                "capabilities": [
                    {"name": "planner_chain", "access_mode": "read"}
                ],
            },
        ]
    )
    expected = {
        "tools": [
            {
                "tool_key": "tool:a",
                "capabilities": [{"name": "shell", "access_mode": "execute"}],
            },
            {
                "tool_key": "unknown:unattributed",
                "capabilities": [
                    {"name": "planner_chain", "access_mode": "read"}
                ],
            },
        ]
    }
    result = compare.compare_case(expected, current)
    assert result["passed"], result["failures"]
    assert result["parts"]["attribution"] == {
        "expected": 2,
        "matched": 1,
        "attributable_expected": 1,
        "attributable_matched": 1,
    }


def test_mutated_input_fails_benchmark(tmp_path):
    """Sensitivity proof: neutering a case input must fail its truth."""
    import shutil

    from safeai.benchmark import runner as runner_mod

    src = os.path.join(
        REPO_ROOT,
        "tests",
        "benchmarks",
        "authority",
        "capabilities",
        "shell_tool",
    )
    case_dir = str(tmp_path / "shell_tool")
    shutil.copytree(src, case_dir)
    with open(
        os.path.join(case_dir, "input", "agent.py"), "w", encoding="utf-8"
    ) as fh:
        fh.write('"""Neutered: no tools, no imports."""\n')
    current, baseline = runner_mod.scan_case(case_dir, str(tmp_path / "work"))
    expected = runner_mod.load_expected(case_dir)
    result = compare.compare_case(expected, current, baseline)
    assert not result["passed"]
    assert result["failures"]


# --- aggregate + report ---


def _case(cid, passed, parts=None, failures=None):
    return {
        "id": cid,
        "category": cid.split("/")[0],
        "passed": passed,
        "failures": failures or [],
        "parts": parts or {},
        "determinism": {"checked": False, "violations": []},
    }


def test_aggregate_counts_and_lane_a():
    agg = metrics.aggregate(
        [
            _case(
                "a/one",
                True,
                {
                    "must_fire": {"expected": 2, "matched": 2, "false_positives": 0},
                    "evidence": {"expected": 1, "matched": 1},
                },
            ),
            _case(
                "b/two",
                False,
                {"must_fire": {"expected": 1, "matched": 0, "false_positives": 1}},
                failures=["must_fire rule silent: X"],
            ),
        ]
    )
    assert agg["summary"] == {"total": 2, "passed": 1, "failed": 1}
    assert agg["metrics"]["discovery"]["true_positives"] == 2
    assert agg["metrics"]["discovery"]["false_positives"] == 1
    assert agg["metrics"]["discovery"]["false_negatives"] == 1
    assert "eligible" in agg["lane_a"]
    assert agg["lane_a"]["eligible"] is False


def test_report_roundtrip_and_markdown(tmp_path):
    agg = metrics.aggregate([_case("a/one", False, failures=["boom"])])
    out = str(tmp_path / "eval.json")
    report.write_json(agg, out)
    with open(out, encoding="utf-8") as fh:
        assert json.load(fh)["summary"]["failed"] == 1
    text = report.render_markdown(agg)
    assert "a/one" in text and "boom" in text and "Lane-A" in text
    md = str(tmp_path / "brief.md")
    report.write_markdown(agg, md)
    assert os.path.isfile(md)


# --- runner discovery ---


def test_corpus_discovers_cases_with_v2_truth():
    cases = runner.discover_cases(runner.default_corpus())
    assert len(cases) == 56, [c["id"] for c in cases]
    assert len({c["id"] for c in cases}) == 56
    for case in cases:
        expected = runner.load_expected(case["dir"])
        assert expected["case"] == case["id"]
        assert expected.get("truth_schema_version") == "2.0", case["id"]
        assert (expected.get("annotation") or {}).get("basis") == (
            "human_reviewed_source"
        ), case["id"]


def test_canonical_projection_stable_and_order_free():
    first = _report(
        tool_surface=[
            {"tool_key": "b", "capabilities": []},
            {"tool_key": "a", "capabilities": []},
        ]
    )
    second = _report(
        tool_surface=[
            {"tool_key": "a", "capabilities": []},
            {"tool_key": "b", "capabilities": []},
        ]
    )
    assert runner.canonical_projection(first) == runner.canonical_projection(second)


def test_cli_parses_benchmark_args():
    from safeai.cmd.cli import _build_parser

    args = _build_parser().parse_args(
        ["benchmark", "--case", "terraform/x", "--json", "o.json"]
    )
    assert args.command == "benchmark"
    assert args.case == "terraform/x"
    assert args.json_path == "o.json"
    assert args.no_determinism is False
