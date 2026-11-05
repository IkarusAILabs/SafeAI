"""Capability-level delegation comparison (v2.15, plan 2.15-4)."""

import os

from safeai.analysis.delegation import (
    attach_tool_capabilities,
    build_delegation_graph,
    compute_delegation_changes,
)

SOURCE = '''from agents import Agent, function_tool
from crewai.tools import BaseTool


@function_tool
def http_get(url): ...            # line 6


@function_tool
def fetch(url): ...               # line 10


class Runner(BaseTool):           # line 13
    name = "runner"

    def _run(self, cmd): ...      # line 16


@function_tool
def stub(x): ...                  # line 20


worker = Agent(name="worker", tools=[fetch, Runner(), stub])
boss = Agent(name="boss", tools=[http_get], handoffs=[worker])
'''


def _graph(tmp_path, findings):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "a.py").write_text(SOURCE, encoding="utf-8")
    graph = build_delegation_graph(str(tmp_path))
    return attach_tool_capabilities(graph, findings, str(tmp_path))


def _cap(line, name, file="a.py"):
    return {"rule_id": f"CAP_{name}", "file": file, "line": line}


def test_tools_get_capabilities_from_their_bodies(tmp_path):
    graph = _graph(tmp_path, [_cap(6, "http"), _cap(10, "http"), _cap(16, "shell"),
                              _cap(25, "multi_agent"), {"rule_id": "TOOL_X", "file": "a.py",
                                                        "line": 10}])
    caps = {n["name"]: n["tool_capabilities"] for n in graph["nodes"]}
    assert caps == {"boss": {"http_get": ["http"]},
                    "worker": {"Runner": ["shell"], "fetch": ["http"], "stub": []}}
    assert all("tool_ranges" not in n for n in graph["nodes"])
    (edge,) = graph["edges"]
    assert edge["exceeds"] == ["Runner", "fetch", "stub"]
    assert edge["exceeds_capability_check"] == {"covered": ["fetch"],
                                                "capabilities_gained": ["shell"]}
    assert graph["counts"]["edges_exceeding_delegator"] == 1


def test_absolute_finding_paths_are_matched(tmp_path):
    graph = _graph(tmp_path, [_cap(6, "http", os.path.join(str(tmp_path), "a.py")),
                              _cap(10, "http", os.path.join(str(tmp_path), "a.py"))])
    assert graph["edges"][0]["exceeds_capability_check"]["covered"] == ["fetch"]


def test_fully_covered_delegate_is_not_an_exceeds_change(tmp_path):
    before = _graph(tmp_path / "b", [])
    after = _graph(tmp_path / "c", [_cap(6, "http"), _cap(10, "http")])
    # Same edges; only the capability evidence differs.
    before_edges = {"delegation_graph": dict(before, edges=[])}
    changes = compute_delegation_changes({"delegation_graph": after}, before_edges)["changes"]
    exceeding = sorted(c["subject"].rsplit(": ", 1)[1] for c in changes
                       if c["type"] == "DELEGATE_EXCEEDS_DELEGATOR")
    assert exceeding == ["Runner", "stub"]


def test_without_findings_tool_names_decide(tmp_path):
    graph = _graph(tmp_path, [])
    (edge,) = graph["edges"]
    assert edge["exceeds_capability_check"]["covered"] == []
    assert graph["counts"]["edges_exceeding_delegator"] == 1
