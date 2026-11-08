"""AutoGen agents are named by their own name, not by the constructor."""

import pytest

from safeai.frameworks.autogen.parser import AutoGenParser


def _agents(source):
    result = AutoGenParser().parse("agents.py", source)
    return [(a["name"], a["name_resolved"], a["constructor"]) for a in result["agents"]]


@pytest.mark.parametrize(("source", "expected"), [
    (('from autogen_agentchat.agents import AssistantAgent\n'
      'a = AssistantAgent("triage", model_client=c)\n'),
     [("triage", True, "AssistantAgent")]),
    (('from autogen import AssistantAgent, UserProxyAgent\n'
      'a = AssistantAgent(name="coder", llm_config=False)\n'
      'u = UserProxyAgent(name="user")\n'),
     [("coder", True, "AssistantAgent"), ("user", True, "UserProxyAgent")]),
    ('import autogen\na = autogen.AssistantAgent(name="planner")\n',
     [("planner", True, "autogen.AssistantAgent")]),
])
def test_literal_names_are_used(source, expected):
    assert _agents(source) == expected


@pytest.mark.parametrize("call", [
    "AssistantAgent(name=choose())", "AssistantAgent(agent_name)", 'AssistantAgent("  ")',
    "AssistantAgent()",
])
def test_names_built_at_run_time_fall_back_to_the_constructor(call):
    source = f"from autogen import AssistantAgent\na = {call}\n"
    assert _agents(source) == [("AssistantAgent", False, "AssistantAgent")]
