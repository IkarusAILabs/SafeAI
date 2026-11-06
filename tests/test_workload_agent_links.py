"""Workload-to-agent links for SPIFFE identities (v2.15, plan 2.15-1)."""

import pytest

from safeai.iac.spiffe import _entrypoints
from safeai.kya.agent_identity import attach_identities, workload_links

ID_A = "spiffe://example.org/ns/agents/sa/a"


def _agent(agent_id, path, name="Agent"):
    return {"agent_id": agent_id, "name": name,
            "source_locations": [{"path": path, "line_start": 1, "line_end": 1}]}


def _block(*workloads):
    states, assignments = [], []
    for ref, hints, spiffe_id in workloads:
        states.append({"workload": ref, "agent_hints": dict(
            {"annotation": "", "entrypoints": [], "evidence": [{"file": "w.yaml", "line": 3}]},
            **hints)})
        assignments.append({"workload": ref, "spiffe_id": spiffe_id, "resolution": "resolved",
                            "registration": "reg", "evidence": [{"file": "spire.yaml",
                                                                 "line": 5}]})
    return {"workloads": states, "assignments": assignments}


@pytest.mark.parametrize(("container", "expected"), [
    ({"command": ["python", "/srv/app/bot.py"]}, ["/srv/app/bot.py"]),
    ({"command": ["sh", "-c", "python ./bot.py --port 80"]}, ["bot.py"]),
    ({"command": ["python"], "args": ["-m", "pkg.bot"]}, ["pkg/bot.py", "pkg/bot/__main__.py"]),
    ({"command": ["python", "-m", "$(MODULE)"]}, []),
    ({"args": ["serve"]}, []),
])
def test_entrypoints_from_command_and_args(container, expected):
    assert _entrypoints({"containers": [dict(container, name="app")]}) == expected


def test_entrypoint_links_the_one_agent_defined_in_that_file():
    agents = [_agent("a1", "agents/a.py"), _agent("b1", "agents/b.py")]
    block = _block(("Deployment/agents/a", {"entrypoints": ["/srv/agents/a.py"]}, ID_A))
    notes = attach_identities(agents, [], block)
    assert notes == []
    field = agents[0]["workload_identity"]
    assert field["state"] == "unknown" and "entrypoint" in field["unknown_reason"]
    assert [(i["id"], i["provenance_class"], i["link"]["type"]) for i in field["identifiers"]] \
        == [(ID_A, "repo-iac-observed", "workload-entrypoint")]
    assert agents[1]["workload_identity"]["identifiers"] == []


def test_annotation_is_a_declaration_and_corroborates():
    agents = [_agent("a1", "agents/a.py", name="support")]
    block = _block(("Deployment/agents/a", {"annotation": "support"}, ID_A))
    attach_identities(agents, [], block)
    field = agents[0]["workload_identity"]
    assert field["state"] == "corroborated"
    assert sorted(i["provenance_class"] for i in field["identifiers"]) == [
        "declared", "repo-iac-observed"]
    declared = next(i for i in field["identifiers"] if i["provenance_class"] == "declared")
    assert declared["evidence"] == [{"file": "w.yaml", "line": 3}]


@pytest.mark.parametrize(("agents", "hints"), [
    # two agents share the annotated name
    ([_agent("a1", "a.py", name="bot"), _agent("b1", "b.py", name="bot")], {"annotation": "bot"}),
    # the entrypoint matches two repository files
    ([_agent("a1", "main.py"), _agent("b1", "srv/main.py")], {"entrypoints": ["/srv/main.py"]}),
    # one file defines two agents
    ([_agent("a1", "pair.py"), _agent("b1", "pair.py")], {"entrypoints": ["pair.py"]}),
    # an annotation naming nobody does not fall back to the entrypoint
    ([_agent("a1", "a.py")], {"annotation": "ghost", "entrypoints": ["a.py"]}),
])
def test_ambiguous_evidence_links_nothing(agents, hints):
    assert workload_links(agents, _block(("Deployment/x/y", hints, ID_A))) == {}


def test_a_declared_identity_elsewhere_is_not_corroborated_by_an_entrypoint():
    agents = [_agent("a1", "a.py", name="bot")]
    declared = [{"agent": "bot", "id": "spiffe://example.org/other", "scheme": "spiffe",
                 "evidence": [{"file": ".safeai/config.yml", "line": 2}]}]
    attach_identities(agents, declared, _block(("Deployment/x/a", {"entrypoints": ["a.py"]},
                                                ID_A)))
    assert agents[0]["workload_identity"]["state"] == "declared"


def test_unissued_workload_adds_no_identifier():
    agents = [_agent("a1", "a.py")]
    block = _block(("Deployment/x/a", {"entrypoints": ["a.py"]}, ID_A))
    block["assignments"][0]["resolution"] = "unresolved"
    attach_identities(agents, [], block)
    assert agents[0]["workload_identity"]["identifiers"] == []


def test_annotation_naming_no_single_agent_is_reported():
    agents = [_agent("a1", "a.py", name="bot"), _agent("b1", "b.py", name="bot")]
    notes = attach_identities(agents, [], _block(
        ("Deployment/x/one", {"annotation": "ghost"}, ID_A),
        ("Deployment/x/two", {"annotation": "bot"}, ID_A)))
    assert notes == [
        ("Deployment/x/one: ai.safeai.dev/agent names 'ghost', which this scan did not "
         "report; no identity linked"),
        ("Deployment/x/two: ai.safeai.dev/agent names 'bot', which matches several agents "
         "(use the agent_id); no identity linked")]
