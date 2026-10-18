"""Authority benchmark unit tests: metrics, comparison, aggregation, reports.

Pure-function tests only (no corpus scans); corpus execution is
exercised via ``safeai benchmark`` itself.
"""

import copy
import json
import os
import re
from html.parser import HTMLParser

import pytest

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
    assert len(cases) == 58, [c["id"] for c in cases]
    assert len({c["id"] for c in cases}) == 58
    for case in cases:
        expected = runner.load_expected(case["dir"])
        assert expected["case"] == case["id"]
        assert expected.get("truth_schema_version") == "2.0", case["id"]
        assert (expected.get("annotation") or {}).get("basis") == (
            "human_reviewed_source"
        ), case["id"]
        assert (expected.get("annotation") or {}).get("derivation") in (
            "independent_annotation", "migrated_from_legacy",
            "generated_from_source"), case["id"]


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


# --- offline HTML presentation (no scans or metric recalculation) ---


class _BenchmarkHTML(HTMLParser):
    """Read visible current-brief text, source bytes, and table cells separately."""

    def __init__(self, text):
        super().__init__()
        self.current = False
        self.source = False
        self.visible = []
        self.markdown = []
        self.tags = []
        self.meters = []
        self.rows = []
        self.row = None
        self.cell = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "article":
            self.current = attrs.get("aria-label") == "Current benchmark brief"
        if tag == "pre":
            self.source = attrs.get("id") == "markdown-source"
        if tag == "meter":
            self.meters.append(attrs)
        if tag == "tr":
            self.row = []
        if tag in ("td", "th"):
            self.cell = []

    def handle_endtag(self, tag):
        if self.current and tag in ("h1", "h2", "h3", "p", "li", "td", "th"):
            self.visible.append(" ")
        if tag == "article":
            self.current = False
        if tag == "pre":
            self.source = False
        if tag in ("td", "th"):
            self.row.append("".join(self.cell))
            self.cell = None
        if tag == "tr":
            self.rows.append(self.row)
            self.row = None

    def handle_data(self, data):
        if self.current:
            self.visible.append(data)
        if self.source:
            self.markdown.append(data)
        if self.cell is not None:
            self.cell.append(data)


def _committed_evaluation():
    with open(os.path.join(REPO_ROOT, "docs", "benchmarks", "authority",
                           "evaluation.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _brief_words(markdown):
    """Strip only the Markdown writer's block markers for visible parity."""
    lines = []
    for line in markdown.splitlines():
        if re.fullmatch(r"[| \-]+", line):
            continue
        if line.startswith("#"):
            line = line.split(" ", 1)[1]
        elif line.startswith("- "):
            line = line[2:]
        elif line.startswith("| "):
            line = line.replace("|", " ")
        lines.append(line)
    return " ".join(" ".join(lines).split())


def test_html_preserves_complete_markdown_content_and_all_eight_levels():
    aggregate = _committed_evaluation()
    markdown = report.render_markdown(aggregate)
    page = _BenchmarkHTML(report.render_html(aggregate))
    assert " ".join("".join(page.visible).split()) == _brief_words(markdown)
    assert "".join(page.markdown).encode("utf-8") == markdown.encode("utf-8")
    levels = aggregate["metrics"]["canonical"]["attribution_levels"]
    assert len(levels) == 8
    for name in levels:
        assert any(row[0] == f"Resolvable {name} attribution: " for row in page.rows)
    for cls in aggregate["metrics"]["lane_a_classes"]["classes"]:
        row = next(row for row in page.rows if row[0] == cls["class"] + ": ")
        assert row[1].startswith(cls["status"] + " (precision ")
        assert "PROPOSED" in row[1]
    assert any(attrs.get("class") == "limitations" for _, attrs in page.tags)
    assert sum(attrs.get("class") == "watch" for _, attrs in page.tags) == 3
    assert page.meters
    assert all(m["aria-hidden"] == "true" and m["min"] == "0" and m["max"] == "1"
               for m in page.meters)


def test_html_deterministic_bytes_and_input_immutability(tmp_path):
    aggregate = _committed_evaluation()
    history = [("revision-before", copy.deepcopy(aggregate))]
    before = copy.deepcopy((aggregate, history))
    markdown = report.render_markdown(aggregate)
    first = tmp_path / "one.html"
    second = tmp_path / "two.html"
    assert report.write_html(aggregate, first, history=history) == first
    report.write_html(aggregate, second, history=history)
    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes() == report.render_html(
        aggregate, history=history).encode("utf-8")
    assert b"\r\n" not in first.read_bytes()
    assert (aggregate, history) == before
    assert report.render_markdown(aggregate) == markdown


def test_html_escapes_artifact_text_and_revision_labels():
    aggregate = _committed_evaluation()
    payload = '<script>alert("x")</script>&<img src=x onerror="alert(1)">'
    aggregate["digest"] = payload
    aggregate["cases"] = [{"id": payload, "passed": False,
                           "failures": [payload], "harness_error": payload}]
    aggregate["metrics"]["lane_a_classes"]["overall"] = payload
    aggregate["metrics"]["lane_a_classes"]["classes"][0]["extra"] = payload
    aggregate["metrics"]["canonical"]["false_escalation_rate"] = {
        "status": "insufficient_evidence", "reason": payload,
    }
    html = report.render_html(aggregate, history=[(payload, aggregate)], label=payload)
    page = _BenchmarkHTML(html)
    assert payload not in html
    assert payload in "".join(page.visible)
    assert "".join(page.markdown) == report.render_markdown(aggregate)
    assert not {tag for tag, _ in page.tags} & {"script", "img", "iframe", "link"}
    assert not any(key.startswith("on") for _, attrs in page.tags for key in attrs)
    assert any(row[0] == payload for row in page.rows)


def test_html_preserves_missing_zero_and_insufficient_evidence():
    aggregate = {"metrics": {"canonical": {
        "attribution_levels": {
            "absent": {},
            "unmeasured": {"status": "insufficient_evidence", "coverage": 0.9},
            "measured": {"status": "measured", "precision": 0.0,
                         "recall": None, "f1": 0.0, "coverage": None},
        },
        "false_escalation_rate": {"status": "measured", "value": 0.0},
        "missed_material_rate": {"status": "insufficient_evidence", "value": 0.0},
    }}}
    page = _BenchmarkHTML(report.render_html(aggregate))
    assert " ".join("".join(page.visible).split()) == _brief_words(
        report.render_markdown(aggregate))
    rows = {row[0]: row[1] for row in page.rows if len(row) == 2}
    assert rows["Resolvable absent attribution: "].startswith(
        "n/a (insufficient evidence")
    assert rows["Resolvable unmeasured attribution: "].startswith(
        "n/a (insufficient evidence")
    assert "resolvable precision 0.0, resolvable recall n/a, F1 0.0" in rows[
        "Resolvable measured attribution: "]
    assert rows["False escalation (observed rate on benchmark corpus): "] == "0.0"
    assert rows["Missed material change: "] == "n/a (insufficient evidence)"
    assert [m["value"] for m in page.meters] == ["0.0", "0.0", "0.0"]
    empty = _BenchmarkHTML(report.render_html({}))
    assert " ".join("".join(empty.visible).split()) == _brief_words(
        report.render_markdown({}))
    assert not empty.meters


def test_html_history_keeps_explicit_order_counts_and_corpus_caveat():
    old = {"summary": {"total": 10}, "metrics": {
        "attribution": {"end_to_end": 0.25, "matched": 1, "expected": 4},
        "lane_a_classes": {"overall": "UNKNOWN / NOT LANE-A READY"},
        "canonical": {"false_escalation_rate": {
            "status": "insufficient_evidence", "value": 0.0,
            "reason": "no baseline pairs"}},
    }}
    current = {"summary": {"total": 20}, "metrics": {
        "attribution": {"end_to_end": 0.5, "matched": 4, "expected": 8},
        "canonical": {"false_escalation_rate": {"status": "measured", "value": 0.0}},
    }}
    assert "Artifact trends" not in report.render_html(current)
    for history in ([("z-old", old)], [("z-old", old), ("a-next", current)]):
        html = report.render_html(current, history=history, label="current-revision")
        page = _BenchmarkHTML(html)
        labels = [label for label, _ in history] + ["current-revision"]
        rows = [row for row in page.rows if row[0] in labels]
        assert [row[0] for row in rows] == labels
        assert rows[0] == ["z-old", "10", "UNKNOWN / NOT LANE-A READY", "0.25 (1/4)",
                           "n/a (no baseline pairs)", "n/a (insufficient evidence)"]
        assert rows[-1] == ["current-revision", "20", "RESEARCH / NOT LANE-A READY",
                            "0.5 (4/8)", "0.0", "n/a (insufficient evidence)"]
        assert "mix or truth do not prove scanner improvement" in html
        assert "Historical brief: z-old" in html
        assert "".join(page.markdown) == report.render_markdown(current)


def test_html_history_limit_preserves_order_at_the_boundary():
    history = [(f"revision-{index}", {}) for index in range(20)]
    page = _BenchmarkHTML(report.render_html({}, history=history))
    assert [row[0] for row in page.rows if row[0].startswith("revision-")] == [
        label for label, _ in history]


@pytest.mark.parametrize("existing", [False, True])
def test_html_excess_history_is_rejected_before_rendering_or_writing(tmp_path, monkeypatch, existing):
    destination = tmp_path / "report.html"
    if existing:
        destination.write_bytes(b"previous report")

    def unexpected_render(_):
        pytest.fail("excess history must be rejected before rendering any brief")

    monkeypatch.setattr(report, "render_markdown", unexpected_render)
    history = [("revision", {})] * 21
    with pytest.raises(ValueError, match="at most 20"):
        report.render_html({}, history=history)
    with pytest.raises(ValueError, match="at most 20"):
        report.write_html({}, destination, history=history)
    if existing:
        assert destination.read_bytes() == b"previous report"
    else:
        assert not destination.exists()


@pytest.mark.parametrize("payload", [
    '</style><script>alert(1)</script>',
    '</summary><svg onload="alert(1)">',
    '\"><iframe src="https://example.invalid"></iframe>',
    '</pre><img src=x onerror=alert(1)>',
    '<a href="javascript:alert(1)">click</a>',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
])
def test_html_history_keeps_adversarial_labels_and_metrics_inert(payload):
    aggregate = _committed_evaluation()
    aggregate["digest"] = payload
    aggregate["cases"] = [{"id": payload, "passed": False, "failures": [payload]}]
    aggregate["metrics"]["attribution"]["end_to_end"] = payload
    aggregate["metrics"]["canonical"]["false_escalation_rate"] = {
        "status": "measured", "value": payload}
    before = copy.deepcopy(aggregate)
    page = _BenchmarkHTML(report.render_html(aggregate, history=[(payload, aggregate)], label=payload))
    assert not {tag for tag, _ in page.tags} & {"script", "svg", "img", "iframe", "a", "link"}
    assert not any(key.startswith("on") for _, attrs in page.tags for key in attrs)
    assert all(re.fullmatch(r"0(?:\.\d+)?|1(?:\.0+)?", m["value"]) for m in page.meters)
    assert any(row[0] == payload for row in page.rows)
    assert "".join(page.markdown) == report.render_markdown(aggregate)
    assert aggregate == before
