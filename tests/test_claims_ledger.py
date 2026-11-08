"""C-8 claims ledger: public wording stays in step with the code (docs/research/CREDIBILITY_TRACK.md)."""

import importlib.util
import os
import sys

import pytest

from safeai.engine.orchestrator import run_scan

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def _load():
    spec = importlib.util.spec_from_file_location(
        "claims_check", os.path.join(ROOT, "scripts", "claims_check.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules["claims_check"] = module
    spec.loader.exec_module(module)
    return module


claims = _load()


def test_committed_ledger_is_consistent_with_the_code_and_the_wording():
    assert claims.main([]) == 0


def _ledger(**claim):
    base = {"id": "c", "source": "README.md", "quote": "Know what your AI agent can do",
            "kind": "property", "status": "limitation"}
    return {"claims": [{**base, **claim}]}


@pytest.mark.parametrize(("claim", "problem"), [
    ({"quote": "SafeAI guarantees safety"}, "quote no longer in README.md"),
    ({"status": "counted", "kind": "count", "count": "frameworks", "claimed": 3},
     "the code has"),
    ({"status": "counted", "kind": "count", "count": "nonsense", "claimed": 3},
     "unknown count"),
    ({"status": "tested"}, "needs backing.tests"),
    ({"status": "tested", "backing": {"tests": ["tests/test_nope.py"]}}, "not found"),
    ({"status": "tested", "backing": {"tests": ["tests/test_claims_ledger.py::test_nope"]}},
     "not found"),
    ({"status": "unmeasured", "kind": "quality"}, "name its study"),
    ({"status": "great"}, "status must be"),
    ({"source": "https://example.org"}, "needs 'retrieved'"),
    ({"source": "NOPE.md"}, "not found"),
])
def test_ledger_problems_are_reported(claim, problem):
    assert any(problem in p for p in claims.check(_ledger(**claim)))


def test_quotes_match_across_line_breaks_and_emphasis():
    assert claims._normalise("a **b**\n  c") == claims._normalise("a b c")


def test_support_matrix_table_is_parsed_by_prefix():
    text = "| `CAP_*` | 21 | x |\n| `PROMPT_FILE_*` | 4 | y |\n"
    assert claims.support_matrix_counts(text) == {"CAP": 21, "PROMPT_FILE": 4}
    assert claims.rule_prefix_counts(["CAP_a", "PROMPT_FILE_b", "PROMPT_c", "DATAFLOW_d"]) == {
        "CAP": 1, "PROMPT_FILE": 1, "PROMPT": 1, "DATAFLOW": 1}


def _fixture_findings():
    for name in sorted(os.listdir(FIXTURES)):
        path = os.path.join(FIXTURES, name, "representative")
        if os.path.isdir(path):
            for finding in run_scan(path)["findings"]:
                yield name, finding


def test_every_fixture_finding_has_a_location_and_remediation():
    """Website: "Every finding includes evidence and remediation guidance"."""
    findings = list(_fixture_findings())
    assert len(findings) > 100
    missing = [(name, f["rule_id"]) for name, f in findings
               if not f.get("file") or not f.get("remediation")]
    assert missing == []


def test_the_unattributed_bucket_is_never_an_orphan_tool():
    orphans = [f for _, f in _fixture_findings() if f["rule_id"] == "TOOL_ORPHAN_IMPLEMENTED"]
    assert all("unattributed" not in f["message"] for f in orphans)
