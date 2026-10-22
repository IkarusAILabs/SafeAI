"""CLI wiring for the PR comment and the escalation exit-code axis.

Also holds the end-to-end proof that motivates the whole release: a
single MCP server flipping from read-only to mutating must surface as a
named escalation, where the v1 flat capability diff sees nothing.
"""

import json
import os

from safeai.analysis.capability_diff import compute_legacy_capability_diff
from safeai.cmd.cli import main
from safeai.engine.scan import run_scan
from safeai.report.pr_comment import MARKER

READ_ONLY = {
    "mcpServers": {
        "invoice-lookup": {
            "command": "node",
            "args": ["server.js"],
            "tools": [
                {"name": "get_invoice", "description": "Read a single invoice"},
                {"name": "list_invoices", "description": "List invoices"},
            ],
        }
    }
}

MUTATING = {
    "mcpServers": {
        "invoice-lookup": {
            "command": "node",
            "args": ["server.js"],
            "tools": [
                {"name": "get_invoice", "description": "Read a single invoice"},
                {"name": "list_invoices", "description": "List invoices"},
                {"name": "create_invoice", "description": "Create a new invoice"},
                {"name": "delete_invoice", "description": "Delete an invoice"},
            ],
        }
    }
}


def write_project(root, payload):
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (root / "agent.py").write_text(
        "from langgraph.graph import StateGraph\n\n"
        "def build():\n    return StateGraph(dict)\n",
        encoding="utf-8",
    )
    return str(root)


# --- the end-to-end proof ------------------------------------------------


def test_read_only_to_mutating_mcp_server_is_named(tmp_path):
    before_root = write_project(tmp_path / "before", READ_ONLY)
    after_root = write_project(tmp_path / "after", MUTATING)

    baseline = run_scan(before_root)
    current = run_scan(after_root, baseline_report=baseline)
    diff = current["capability_diff"]

    server = next(t for t in diff["tools"] if t["tool_key"] == "mcp_server:invoice-lookup")
    assert "ESC_MCP_READ_TO_MUTATE" in {e["id"] for e in server["escalations"]}
    # The server already spawned a process, so its tool-wide maximum mode is
    # unchanged. The escalation lives at the capability level.
    # Both sides are detected here: the baseline is a real scan of the
    # read-only project, not a hand-written guess, so the transition is
    # confirmed on both sides and nothing is inferred.
    assert {
        "capability": "mcp",
        "before": "read",
        "after": "mutate",
        "inferred": False,
        "before_inferred": False,
        "after_inferred": False,
    } in server["access_mode_changes"]


def test_v1_flat_diff_sees_nothing_for_the_same_change(tmp_path):
    """The gap v1.4 exists to close."""
    baseline = run_scan(write_project(tmp_path / "before", READ_ONLY))
    current = run_scan(write_project(tmp_path / "after", MUTATING))

    legacy = compute_legacy_capability_diff(current, baseline)
    assert legacy["counts"] == {"added": 0, "removed": 0, "changed": 0}


def test_pr_comment_names_the_server_that_escalated(tmp_path):
    from safeai.report.pr_comment import render_pr_comment

    baseline = run_scan(write_project(tmp_path / "before", READ_ONLY))
    current = run_scan(write_project(tmp_path / "after", MUTATING), baseline_report=baseline)

    text = render_pr_comment(current)
    assert "`mcp_server:invoice-lookup`" in text
    assert "mcp: read → mutate" in text


# --- CLI flags -----------------------------------------------------------


def scan_with_baseline(tmp_path, extra_args):
    """Scan the mutating project against a read-only baseline report."""
    before_root = write_project(tmp_path / "before", READ_ONLY)
    after_root = write_project(tmp_path / "after", MUTATING)
    baseline_json = str(tmp_path / "baseline.json")
    main(["scan", before_root, "--json", baseline_json, "--no-registry",
          "--sarif", str(tmp_path / "b.sarif")])
    code = main(["scan", after_root, "--baseline", baseline_json, "--no-registry",
                 "--sarif", str(tmp_path / "a.sarif"), *extra_args])
    return code


def test_pr_comment_flag_writes_a_file(tmp_path):
    output = str(tmp_path / "comment.md")
    scan_with_baseline(tmp_path, ["--pr-comment", output])

    assert os.path.exists(output)
    with open(output, encoding="utf-8") as handle:
        text = handle.read()
    assert text.splitlines()[0] == MARKER
    assert "invoice-lookup" in text


def test_pr_comment_stdout_flag_prints_the_comment(tmp_path, capsys):
    scan_with_baseline(tmp_path, ["--pr-comment-stdout"])
    assert MARKER in capsys.readouterr().out


def test_pr_comment_file_is_byte_identical_across_runs(tmp_path):
    first = str(tmp_path / "one.md")
    second = str(tmp_path / "two.md")
    scan_with_baseline(tmp_path, ["--pr-comment", first])
    scan_with_baseline(tmp_path, ["--pr-comment", second])

    with open(first, "rb") as a, open(second, "rb") as b:
        assert a.read() == b.read()


def test_fail_on_escalation_fails_on_a_critical_escalation(tmp_path):
    assert scan_with_baseline(tmp_path, ["--fail-on-escalation", "critical"]) == 1


def test_fail_on_escalation_requires_a_baseline(tmp_path):
    import pytest

    root = write_project(tmp_path / "solo", MUTATING)
    with pytest.raises(SystemExit):
        main(["scan", root, "--no-registry", "--fail-on-escalation", "high",
              "--sarif", str(tmp_path / "s.sarif")])


def test_default_exit_semantics_are_unchanged(tmp_path):
    """Without the new flag, a pure escalation must not change the exit code."""
    clean_before = tmp_path / "cb"
    clean_after = tmp_path / "ca"
    write_project(clean_before, READ_ONLY)
    write_project(clean_after, MUTATING)

    baseline_json = str(tmp_path / "baseline.json")
    main(["scan", str(clean_before), "--json", baseline_json, "--no-registry",
          "--sarif", str(tmp_path / "b.sarif")])
    with_flag = main(["scan", str(clean_after), "--baseline", baseline_json, "--no-registry",
                      "--sarif", str(tmp_path / "a1.sarif"), "--fail-on-escalation", "critical"])
    without_flag = main(["scan", str(clean_after), "--baseline", baseline_json, "--no-registry",
                         "--sarif", str(tmp_path / "a2.sarif")])
    assert with_flag == 1
    assert without_flag == 0


def test_no_pr_comment_written_unless_requested(tmp_path):
    scan_with_baseline(tmp_path, [])
    assert not any(name.endswith(".md") for name in os.listdir(tmp_path))
