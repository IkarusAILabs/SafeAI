"""LangGraph and AutoGen delegation (v2.14, plan 2.14-2)."""

from safeai.analysis.delegation import (
    build_delegation_graph,
    compute_delegation_changes,
)
from safeai.analysis.sod import analyze_separation_of_duties


def _repo(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return str(tmp_path)


def _edges(graph):
    names = {n["id"]: n["name"] for n in graph["nodes"]}
    return sorted((names[e["from"]], names[e["to"]], e["kind"], tuple(e["exceeds"]))
                  for e in graph["edges"])


LANGGRAPH = ("from langgraph.prebuilt import create_react_agent as make\n"
             "from langgraph_supervisor import create_supervisor\n")


def test_supervisor_with_tools_aliases_and_a_compiled_member(tmp_path):
    root = _repo(tmp_path, {"g.py": LANGGRAPH + (
        'a = make("m", tools=[search], name="a")\n'
        'b = make("m", tools=[search, shell], name="b")\n'
        'inner = create_supervisor([a, b], model="m").compile(name="inner")\n'
        'outer = create_supervisor(agents=[inner], model="m", tools=[search],\n'
        '                          supervisor_name="outer")\n')})
    graph = build_delegation_graph(root)
    assert _edges(graph) == [
        ("outer", "supervisor", "supervisor", ()),
        ("supervisor", "a", "supervisor", ("search",)),
        ("supervisor", "b", "supervisor", ("search", "shell")),
    ]
    assert graph["counts"]["max_depth"] == 2
    assert {n["framework"] for n in graph["nodes"]} == {"langgraph"}


def test_swarm_handoff_tools_are_edges_not_authority(tmp_path):
    root = _repo(tmp_path, {"s.py": (
        "from langgraph.prebuilt import create_react_agent\n"
        "from langgraph_swarm import create_handoff_tool, create_swarm\n"
        'x = create_react_agent("m", tools=[create_handoff_tool(agent_name="y")], name="x")\n'
        'y = create_react_agent("m", tools=[pay, create_handoff_tool(agent_name=who)], '
        'name="y")\n'
        "create_swarm([x, y])\n")})
    graph = build_delegation_graph(root)
    assert _edges(graph) == [("x", "y", "handoff", ("pay",))]
    authority = {n["name"]: n["authority"] for n in graph["nodes"]}
    assert authority == {"x": [], "y": ["pay"]}
    assert [u["reason"] for u in graph["unresolved"]] == ["handoff target is built at run time"]


def test_autogen_handoffs_by_name_and_teams(tmp_path):
    root = _repo(tmp_path, {"t.py": (
        "from autogen_agentchat.agents import AssistantAgent\n"
        "from autogen_agentchat.base import Handoff\n"
        "from autogen_agentchat.teams import SelectorGroupChat, Swarm\n"
        'a = AssistantAgent("a", model_client=c, handoffs=[Handoff(target="b"), "ghost"])\n'
        'b = AssistantAgent(name="b", model_client=c, tools=[refund])\n'
        "Swarm([a, b])\n"
        "team = SelectorGroupChat([a, b], model_client=c)\n"
        "SelectorGroupChat(participants=members, model_client=c)\n")})
    graph = build_delegation_graph(root)
    assert _edges(graph) == [
        ("a", "b", "handoff", ("refund",)),
        ("team", "a", "group-chat-manager", ()),
        ("team", "b", "group-chat-manager", ("refund",)),
    ]
    reasons = sorted((u["target"], u["reason"]) for u in graph["unresolved"])
    assert reasons == [("ghost", "handoff target is not an agent named in this file"),
                       ("members", "team members are built at run time")]


def test_autogen_02_group_chat_uses_its_manager_name(tmp_path):
    root = _repo(tmp_path, {"c.py": (
        "from autogen import AssistantAgent, GroupChat, GroupChatManager\n"
        'p = AssistantAgent(name="p")\nq = AssistantAgent("q")\n'
        "chat = GroupChat(agents=[p, q], messages=[])\n"
        'GroupChatManager(groupchat=chat, name="boss")\n'
        "other = GroupChat(agents=[p], messages=[])\n")})
    edges = _edges(build_delegation_graph(root))
    assert edges == [("boss", "p", "group-chat-manager", ()),
                     ("boss", "q", "group-chat-manager", ()),
                     ("chat_manager", "p", "group-chat-manager", ())]


def test_plain_imports_and_unknown_modules_add_nothing(tmp_path):
    root = _repo(tmp_path, {"n.py": (
        "import autogen\nfrom mylib import create_supervisor, AssistantAgent\n"
        'a = autogen.AssistantAgent(name="a")\nb = AssistantAgent("b")\n'
        "create_supervisor([a, b])\n")})
    assert build_delegation_graph(root)["nodes"] == []


def test_new_supervisor_member_is_a_delegation_change(tmp_path):
    def graph(members):
        return build_delegation_graph(_repo(tmp_path / members, {"g.py": LANGGRAPH + (
            'a = make("m", tools=[t1], name="a")\nb = make("m", tools=[t2], name="b")\n'
            f'create_supervisor([{members}])\n')}))

    changes = compute_delegation_changes({"delegation_graph": graph("a, b")},
                                         {"delegation_graph": graph("a")})["changes"]
    assert sorted((c["type"], c["subject"]) for c in changes) == [
        ("DELEGATE_ADDED", "langgraph:supervisor -> langgraph:b"),
        ("DELEGATE_EXCEEDS_DELEGATOR", "langgraph:supervisor -> langgraph:b: t2"),
        ("DELEGATION_BREADTH_INCREASED", "langgraph:supervisor"),
    ]


def test_separation_of_duties_reaches_through_a_supervisor(tmp_path):
    graph = build_delegation_graph(_repo(tmp_path, {"g.py": LANGGRAPH + (
        'a = make("m", tools=[create_invoice], name="a")\n'
        'b = make("m", tools=[approve_invoice], name="b")\n'
        "create_supervisor([a, b])\n")}))
    _findings, summary = analyze_separation_of_duties({"delegation_graph": graph})
    conflicts = [(c["holder"], c["pair"], tuple(c["via_delegation"]))
                 for c in summary["conflicts"]]
    assert conflicts == [("langgraph:supervisor", "SOD-REQUEST-APPROVE", ("a", "b"))]
