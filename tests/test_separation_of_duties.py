"""Separation of Duties (v2.11, plan item 2.11-2)."""

import json

import pytest
import yaml

from safeai.analysis import sod
from safeai.cmd.cli import main
from safeai.controls.mappings import RULE_MAPPINGS
from safeai.engine.orchestrator import run_scan
from safeai.kya.enrich import LANE_B_RULES


def _scan(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return run_scan(str(tmp_path))


def _conflicts(report):
    return sorted((c["holder"], c["pair"])
                  for c in report["separation_of_duties"]["conflicts"])


def _settings(*allow):
    return json.dumps({"permissions": {"allow": list(allow)}})


# --- role predicates ------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "roles"),
    [
        ("create_invoice", {("request", ("invoice",))}),
        ("approveInvoice", {("approve", ("invoice",))}),
        ("refund_approve", {("approve", ("refund",))}),
        ("create_issue", set()),
        ("list_invoices", set()),
        ("merge_pull_request", {("merge-approve", None)}),
        ("push_files", {("code-change", None)}),
    ],
)
def test_tool_name_roles(name, roles):
    assert sod._tool_name_roles(name) == roles


@pytest.mark.parametrize(
    ("entry", "roles"),
    [
        ("Edit(src/**)", {"code-change"}),
        ("Edit(.claude/settings.json)", {"code-change", "self-grant"}),
        ("Write(./.claude/agents/a.md)", {"code-change", "self-grant"}),
        ("Bash(gh pr merge:*)", {"merge-approve", "act"}),
        ("Bash(git push origin main)", {"code-change", "merge-approve", "act"}),
        ("Bash(npm test:*)", set()),
        ("Bash", set()),
        ("Write(*)", set()),
        ("Edit", set()),
        ("mcp__github__merge_pull_request", {"merge-approve"}),
    ],
)
def test_claude_entry_roles(entry, roles):
    assert {r for r, _ in sod._claude_entry_roles(entry)} == roles


@pytest.mark.parametrize(
    ("action", "roles"),
    [("s3:PutObject", {"act"}), ("cloudtrail:StopLogging", {"erase-audit"}),
     ("logs:DeleteLogGroup", {"erase-audit"}), ("cloudtrail:LookupEvents", set()),
     ("s3:GetObject", set()), ("*", set())],
)
def test_action_roles(action, roles):
    assert {r for r, _ in sod._action_roles(action)} == roles


def test_request_and_approve_must_share_an_object():
    items = {"create_invoice": sod._tool_name_roles("create_invoice"),
             "approve_refund": sod._tool_name_roles("approve_refund")}
    assert sod._conflicts(items) == []
    items["approve_invoice"] = sod._tool_name_roles("approve_invoice")
    assert sod._conflicts(items) == [
        ("SOD-REQUEST-APPROVE", ["create_invoice"], ["approve_invoice"])]


# --- holders, end to end ----------------------------------------------------------


def test_claude_code_session_without_subagents_is_a_holder(tmp_path):
    report = _scan(tmp_path, {".claude/settings.json": _settings(
        "Edit(src/**)", "Bash(gh pr merge:*)", "Edit(.claude/settings.json)")})
    assert _conflicts(report) == [("claude_code:session", "SOD-CHANGE-MERGE"),
                                  ("claude_code:session", "SOD-SELF-GRANT")]
    findings = [f for f in report["findings"] if f["rule_id"] == sod.RULE_SOD]
    assert {f["gateability"] for f in findings} == {"review-only"}
    assert {f["severity"] for f in findings} == {"low"}
    assert {f["provenance_class"] for f in findings} == {"detected"}


def test_subagent_is_its_own_holder(tmp_path):
    report = _scan(tmp_path, {
        ".claude/settings.json": _settings("Read"),
        ".claude/agents/shipper.md": ("---\nname: shipper\n"
                                      "tools: Edit(src/**), Bash(gh pr merge:*)\n---\nx\n")})
    assert _conflicts(report) == [("claude_code:shipper", "SOD-CHANGE-MERGE")]


def test_mcp_server_holder_is_inferred(tmp_path):
    report = _scan(tmp_path, {".mcp.json": json.dumps({"mcpServers": {"pay": {
        "command": "node", "tools": ["issue_refund", "approve_refund"]}}})})
    assert _conflicts(report) == [("mcp_server:pay", "SOD-REQUEST-APPROVE")]
    finding = next(f for f in report["findings"] if f["rule_id"] == sod.RULE_SOD)
    assert finding["provenance_class"] == "inferred"


def test_conflict_through_delegation_names_the_delegate(tmp_path):
    report = _scan(tmp_path, {"a.py": (
        "from agents import Agent\n"
        "approver = Agent(name='approver', tools=[approve_payment])\n"
        "drafter = Agent(name='drafter', tools=[create_payment], handoffs=[approver])\n")})
    (conflict,) = report["separation_of_duties"]["conflicts"]
    assert (conflict["holder"], conflict["via_delegation"]) == (
        "openai_agents:drafter", ["approver"])
    finding = next(f for f in report["findings"] if f["rule_id"] == sod.RULE_SOD)
    assert "through delegation to approver" in finding["message"]


def test_iac_audit_erasure(tmp_path):
    report = _scan(tmp_path, {"iam.tf": '''
resource "aws_iam_role" "r" {
  name = "agent-role"
}
resource "aws_iam_role_policy" "p" {
  name = "p"
  role = aws_iam_role.r.id
  statement {
    actions   = ["s3:PutObject", "cloudtrail:StopLogging"]
    resources = ["*"]
  }
}
'''})
    assert _conflicts(report) == [("aws_iam_role:agent-role", "SOD-ACT-ERASE-AUDIT")]
    finding = next(f for f in report["findings"] if f["rule_id"] == sod.RULE_SOD)
    assert finding["provenance_class"] == "repo-iac-observed"


def test_broad_grants_name_no_conflict(tmp_path):
    report = _scan(tmp_path, {".claude/settings.json": _settings("Bash", "Write(*)", "Edit")})
    assert _conflicts(report) == []


def test_rule_is_registered_lane_b_and_mapped():
    import os

    import safeai.rules

    path = os.path.join(os.path.dirname(safeai.rules.__file__), "base_rules.yaml")
    with open(path, encoding="utf-8") as handle:
        rules = {r["id"]: r for r in yaml.safe_load(handle)}
    assert rules[sod.RULE_SOD]["severity"] == "low"
    assert sod.RULE_SOD in LANE_B_RULES
    assert RULE_MAPPINGS[sod.RULE_SOD]


def test_sod_never_fails_a_gate(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.json").write_text(
        _settings("Edit(src/**)", "Bash(gh pr merge:*)"), encoding="utf-8")
    out = tmp_path / "r.json"
    rc = main(["scan", str(repo), "--json", str(out), "--fail-on", "medium", "--no-registry"])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert any(f["rule_id"] == sod.RULE_SOD for f in report["findings"])
    blocking = [f for f in report["findings"]
                if f["severity"] in ("medium", "high", "critical")]
    assert rc == (1 if blocking else 0)
    assert all(f["rule_id"] != sod.RULE_SOD for f in blocking)
