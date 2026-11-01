"""Static delegation graph and delegation change types (v2.11, plan 2.11-1)."""

import json

import pytest

from safeai.analysis.delegation import (
    DELEGATION_CHANGE_TYPES,
    build_delegation_graph,
    compute_delegation_changes,
)
from safeai.cmd.cli import main
from safeai.kya.contract import validate_manifest
from safeai.report.pr_comment import render_pr_comment

HEADER = '''from agents import Agent, function_tool, handoff


@function_tool
def lookup(x): ...


@function_tool
def refund(x): ...

'''


def _repo(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return str(tmp_path)


def _edges(graph):
    names = {n["id"]: n["name"] for n in graph["nodes"]}
    return sorted((names[e["from"]], names[e["to"]],
                   None if e["exceeds"] is None else tuple(e["exceeds"]))
                  for e in graph["edges"])


# --- graph --------------------------------------------------------------------


def test_openai_handoffs_with_wrapper_inline_agent_and_unresolved(tmp_path):
    root = _repo(tmp_path, {"a.py": HEADER + (
        'refunds = Agent(name="refunds", tools=[lookup, refund])\n'
        'triage = Agent(name="triage", tools=[lookup], handoffs=[\n'
        '    handoff(refunds), Agent(name="faq", tools=[]), make_agent(), unknown_var])\n')})
    graph = build_delegation_graph(root)
    assert _edges(graph) == [("triage", "faq", ()), ("triage", "refunds", ("refund",))]
    reasons = sorted(u["reason"] for u in graph["unresolved"])
    assert reasons == ["handoff target is built at run time",
                       "handoff target is not an agent bound in this file"]
    assert graph["counts"]["edges_exceeding_delegator"] == 1


def test_non_literal_handoffs_list_is_unresolved(tmp_path):
    root = _repo(tmp_path, {"a.py": HEADER + (
        'others = []\ntriage = Agent(name="triage", handoffs=others)\n')})
    graph = build_delegation_graph(root)
    assert graph["edges"] == []
    assert graph["unresolved"][0]["reason"] == "handoffs list is not a literal"


def test_depth_breadth_and_cycles(tmp_path):
    root = _repo(tmp_path, {"a.py": HEADER + (
        'c = Agent(name="c")\n'
        'b = Agent(name="b", handoffs=[c])\n'
        'a = Agent(name="a", handoffs=[b, c])\n')})
    counts = build_delegation_graph(root)["counts"]
    assert (counts["max_depth"], counts["max_breadth"]) == (2, 2)
    root = _repo(tmp_path / "cyc", {"a.py": HEADER + (
        'a = Agent(name="a")\nb = Agent(name="b", handoffs=[a])\n'
        'a = Agent(name="a", handoffs=[b])\n')})
    assert build_delegation_graph(root)["cycles"] is True


def test_crewai_delegation_and_hierarchical_manager(tmp_path):
    root = _repo(tmp_path, {"crew.py": (
        "from crewai import Agent, Crew, Process\n"
        'r = Agent(role="r", tools=[Search()], allow_delegation=True)\n'
        'w = Agent(role="w", tools=[Write()], allow_delegation=False)\n'
        "Crew(agents=[r, w])\n"
        "Crew(agents=[r, w], process=Process.hierarchical)\n")})
    edges = _edges(build_delegation_graph(root))
    assert ("r", "w", ("Write",)) in edges
    assert not any(src == "w" for src, _, _ in edges)
    assert ("manager", "r", ("Search",)) in edges and ("manager", "w", ("Write",)) in edges


def test_files_without_a_known_agent_import_are_ignored(tmp_path):
    root = _repo(tmp_path, {"a.py": "class Agent: ...\nx = Agent(name='x', handoffs=[y])\n",
                            "broken.py": "Agent(\n"})
    assert build_delegation_graph(root)["nodes"] == []


def test_claude_code_subagents_never_exceed_the_session(tmp_path):
    root = _repo(tmp_path, {
        ".claude/settings.json": json.dumps({"permissions": {"allow": ["Read"],
                                                            "deny": ["Bash"]}}),
        ".claude/agents/a.md": "---\nname: a\ntools: Read, Bash\n---\nx\n",
        ".claude/agents/b.md": "---\nname: b\n---\nx\n"})
    graph = build_delegation_graph(root)
    assert _edges(graph) == [("session", "a", None), ("session", "b", None)]
    nodes = {n["name"]: n for n in graph["nodes"]}
    assert nodes["session"]["authority"] == ["Read"]
    assert nodes["b"]["inherits"] is True and nodes["a"]["inherits"] is False


def test_excluded_paths_are_skipped(tmp_path):
    root = _repo(tmp_path, {"vendor/a.py": HEADER + 'a = Agent(name="a", handoffs=[a])\n'})
    assert build_delegation_graph(root, excluded_paths=["vendor"])["nodes"] == []


# --- changes ------------------------------------------------------------------


def _report(tmp_path, name, files):
    return {"delegation_graph": build_delegation_graph(_repo(tmp_path / name, files))}


def _types(before, after):
    return [(c["type"], c["subject"]) for c in compute_delegation_changes(after, before)["changes"]]


def test_change_types_are_review_only_on_the_delegation_dimension(tmp_path):
    before = _report(tmp_path, "b", {"a.py": HEADER + (
        'r = Agent(name="r", tools=[refund])\nt = Agent(name="t", handoffs=[])\n')})
    after = _report(tmp_path, "c", {"a.py": HEADER + (
        'r = Agent(name="r", tools=[refund])\nt = Agent(name="t", handoffs=[r])\n')})
    changes = compute_delegation_changes(after, before)["changes"]
    assert {c["type"] for c in changes} <= set(DELEGATION_CHANGE_TYPES)
    assert all(c["dimension"] == "delegation" and c["gateability"] == "review-only"
               for c in changes)
    assert _types(before, after) == [
        ("DELEGATE_ADDED", "openai_agents:t -> openai_agents:r"),
        ("DELEGATE_EXCEEDS_DELEGATOR", "openai_agents:t -> openai_agents:r: refund"),
        ("DELEGATION_DEPTH_INCREASED", "max_depth"),
    ]


def test_delegate_gaining_a_tool_is_an_exceeds_change_without_a_new_edge(tmp_path):
    base = 'r = Agent(name="r", tools=[{}])\nt = Agent(name="t", tools=[lookup], handoffs=[r])\n'
    before = _report(tmp_path, "b", {"a.py": HEADER + base.format("lookup")})
    after = _report(tmp_path, "c", {"a.py": HEADER + base.format("lookup, refund")})
    assert _types(before, after) == [
        ("DELEGATE_EXCEEDS_DELEGATOR", "openai_agents:t -> openai_agents:r: refund")]


def test_pre_v211_baseline_is_not_assessed(tmp_path):
    after = _report(tmp_path, "c", {"a.py": HEADER + 'a = Agent(name="a")\n'})
    result = compute_delegation_changes(after, {})
    assert result["baseline_available"] is False and result["changes"] == []


@pytest.mark.parametrize("baseline_kind", ["manifest", "json"])
def test_cli_baseline_pr_comment_and_no_gate(tmp_path, baseline_kind):
    base = _repo(tmp_path / "base", {"a.py": HEADER + (
        'r = Agent(name="r", tools=[refund])\nt = Agent(name="t")\n')})
    cur = _repo(tmp_path / "cur", {"a.py": HEADER + (
        'r = Agent(name="r", tools=[refund])\nt = Agent(name="t", handoffs=[r])\n')})
    baseline = str(tmp_path / f"b.{baseline_kind}.json")
    flag = "--manifest" if baseline_kind == "manifest" else "--json"
    assert main(["scan", base, flag, baseline, "--no-registry"]) in (0, 1)
    if baseline_kind == "manifest":
        with open(baseline, encoding="utf-8") as handle:
            manifest = json.load(handle)
        assert validate_manifest(manifest)[0] == []
        assert manifest["delegation_graph"]["counts"]["nodes"] == 2
    out = str(tmp_path / "r.json")
    rc = main(["scan", cur, "--baseline", baseline, "--json", out, "--no-registry",
               "--fail-on-authority-change", "material", "--fail-on-escalation", "medium"])
    with open(out, encoding="utf-8") as handle:
        report = json.load(handle)
    block = report["capability_diff"]["delegation_changes"]
    assert block["baseline_available"] is True
    assert "DELEGATE_ADDED" in block["counts"]
    assert rc == 0
    assert "Delegation changes" in render_pr_comment(report)


def test_secrets_in_claude_rules_never_reach_the_graph(tmp_path):
    secret = "supersecretvalue123"
    root = _repo(tmp_path, {
        ".claude/settings.json": json.dumps(
            {"permissions": {"allow": [f"Bash(API_KEY={secret} deploy)"]}}),
        ".claude/agents/a.md": f"---\nname: a\ntools: Read, Bash(TOKEN={secret} x)\n---\nx\n"})
    graph = build_delegation_graph(root)
    assert secret not in json.dumps(graph)
    assert graph["nodes"][0]["authority"]
