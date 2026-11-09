"""AutoGen capabilities are attributed to the tool function that holds them.

Before, every AutoGen capability landed in ``unknown:unattributed``: the
parser saw ``subprocess.run`` but not that it sat in the body of a
function handed to an agent as a tool. A capability is now attributed to
a tool when the call conferring it is in the body of a function the file
registers with AutoGen; anything else stays unattributed.
"""

import textwrap

import pytest

from safeai.analysis.capabilities import is_file_call
from safeai.analysis.semantic import build_semantic_document
from safeai.engine.orchestrator import run_scan


def _surface(tmp_path, source):
    (tmp_path / "team.py").write_text(textwrap.dedent(source), encoding="utf-8")
    report = run_scan(str(tmp_path))
    return {e["tool_key"]: {c["name"]: c["access_mode"] for c in e["capabilities"]}
            for e in report["tool_surface"]}


AGENTCHAT = """
    import subprocess
    from autogen_agentchat.agents import AssistantAgent

    def read_ticket(ticket_id):
        with open(ticket_id, encoding="utf-8") as fh:
            return fh.read()

    def restart_service(name):
        return subprocess.run(["systemctl", "restart", name], check=False)

    triage = AssistantAgent("triage", model_client=None, tools=[read_ticket])
    operator = AssistantAgent("operator", model_client=None, tools=[restart_service])
"""


def test_agentchat_tools_hold_their_own_authority(tmp_path):
    surface = _surface(tmp_path, AGENTCHAT)
    assert surface["tool:read-ticket"] == {"filesystem_access": "read"}
    assert surface["tool:restart-service"] == {"shell_execution": "execute"}
    assert "unknown:unattributed" not in surface


def test_attributed_capabilities_carry_their_line(tmp_path):
    (tmp_path / "team.py").write_text(textwrap.dedent(AGENTCHAT), encoding="utf-8")
    report = run_scan(str(tmp_path))
    entry = next(e for e in report["tool_surface"] if e["tool_key"] == "tool:restart-service")
    assert entry["capabilities"][0]["evidence"] == [{"path": "team.py", "line": 10}]


@pytest.mark.parametrize("registration", [
    "tool = FunctionTool(restart_service, description='restart')",
    "register_function(restart_service, caller=a, executor=b, description='restart')",
])
def test_core_and_legacy_registration(tmp_path, registration):
    surface = _surface(tmp_path, f"""
        import subprocess
        from autogen_core.tools import FunctionTool
        from autogen import AssistantAgent, register_function

        def restart_service(name):
            return subprocess.run(["systemctl", "restart", name], check=False)

        a = AssistantAgent("a")
        b = AssistantAgent("b")
        {registration}
    """)
    assert surface["tool:restart-service"] == {"shell_execution": "execute"}


def test_decorated_tool(tmp_path):
    surface = _surface(tmp_path, """
        import subprocess
        from autogen import AssistantAgent, UserProxyAgent

        assistant = AssistantAgent("assistant")
        proxy = UserProxyAgent("proxy")

        @proxy.register_for_execution()
        @assistant.register_for_llm(description="restart")
        def restart_service(name):
            return subprocess.run(["systemctl", "restart", name], check=False)
    """)
    assert surface["tool:restart-service"] == {"shell_execution": "execute"}


def test_calls_outside_tools_stay_unattributed(tmp_path):
    surface = _surface(tmp_path, """
        import subprocess
        from autogen_agentchat.agents import AssistantAgent

        def helper(name):
            return subprocess.run(["ls", name], check=False)

        def lookup(order_id):
            return helper(order_id)

        subprocess.run(["make"], check=False)
        agent = AssistantAgent("agent", model_client=None, tools=[lookup])
    """)
    # A helper called from a tool is not followed: its authority, and the
    # module-level call's, are reported but not tied to a tool.
    assert surface == {"unknown:unattributed": {"shell_execution": "execute"}}


def test_model_client_is_not_file_access(tmp_path):
    surface = _surface(tmp_path, """
        from autogen_agentchat.agents import AssistantAgent
        from autogen_ext.models.openai import OpenAIChatCompletionClient

        model = OpenAIChatCompletionClient(model="gpt-4o")
        agent = AssistantAgent("agent", model_client=model)
    """)
    assert surface == {"unknown:unattributed": {"external_model_api": "read"}}


@pytest.mark.parametrize(("name", "expected"), [
    ("open", True), ("io.open", True), ("pathlib.path", True), ("os.remove", True),
    ("openaichatcompletionclient", False), ("urllib.request.urlopen", False),
    ("chatopenai", False), ("fh.read", False),
])
def test_is_file_call(name, expected):
    assert is_file_call(name) is expected


def test_semantic_calls_record_their_owner():
    doc = build_semantic_document("m.py", textwrap.dedent("""
        import os

        def f():
            def inner():
                os.system("a")
            os.getcwd()

        async def g():
            os.listdir()

        class C:
            def m(self):
                os.remove("x")

        os.getenv("Y")
    """))
    owners = {c["name"]: c.get("function") for c in doc.calls}
    assert owners == {"os.system": "f", "os.getcwd": "f", "os.listdir": "g",
                      "os.remove": "C.m", "os.getenv": None}
