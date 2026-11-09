"""Authority in the bodies of registered tool functions belongs to that tool.

See safeai/analysis/tool_bodies.py. Each case is a small project in one
framework; the assertion is the attributed part of the tool surface.
"""

import textwrap

import pytest

from safeai.analysis.tool_bodies import tool_units
from safeai.engine.orchestrator import run_scan


def _scan(tmp_path, source, name="agent.py"):
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")
    return run_scan(str(tmp_path))


def _surface(report):
    return {e["tool_key"]: {c["name"]: c["access_mode"] for c in e["capabilities"]}
            for e in report["tool_surface"]}


def _attributed(report):
    return {k: v for k, v in _surface(report).items() if k != "unknown:unattributed"}


LANGCHAIN = """
    import subprocess
    from langchain.agents import initialize_agent
    from langchain.tools import Tool

    def deploy(cmd):
        return subprocess.run(cmd, shell=True, check=False).stdout

    deploy_tool = Tool(name="deploy_service", func=deploy, description="Run deploys")
    agent = initialize_agent(tools=[deploy_tool], llm=None)
"""


def test_langchain_tool_named_by_its_declaration(tmp_path):
    report = _scan(tmp_path, LANGCHAIN)
    assert _attributed(report) == {"tool:deploy-service": {"shell_execution": "execute"}}
    entry = next(e for e in report["tool_surface"] if e["tool_key"] == "tool:deploy-service")
    assert entry["capabilities"][0]["evidence"] == [{"path": "agent.py", "line": 7}]


@pytest.mark.parametrize(("imports", "registration", "key"), [
    ("from langchain.tools import tool", "@tool\ndef deploy(cmd):", "tool:deploy"),
    ("from crewai.tools import tool", '@tool("Deployer")\ndef deploy(cmd):', "tool:deployer"),
    ("from agents import Agent, function_tool", "@function_tool\ndef deploy(cmd):",
     "tool:deploy"),
    ("from semantic_kernel.functions import kernel_function",
     '@kernel_function(description="d")\ndef deploy(cmd):', "tool:deploy"),
])
def test_decorated_tools(tmp_path, imports, registration, key):
    source = (f"import subprocess\n{imports}\n\n{registration}\n"
              "    return subprocess.run(cmd, shell=True, check=False)\n")
    if "agents import" in imports:
        source += "\nagent = Agent(name='a', tools=[deploy])\n"
    if "semantic_kernel" in imports:
        source += "\nimport semantic_kernel as sk\nkernel = sk.Kernel()\n"
    if "crewai" in imports:
        source += "\nfrom crewai import Agent\nagent = Agent(role='r', tools=[deploy])\n"
    if "langchain" in imports:
        source += "\nfrom langchain.agents import initialize_agent\n" \
                  "agent = initialize_agent(tools=[deploy], llm=None)\n"
    assert _attributed(_scan(tmp_path, source)) == {key: {"shell_execution": "execute"}}


def test_google_adk_function_tool_and_tools_list(tmp_path):
    report = _scan(tmp_path, """
        import requests
        from google.adk import Agent
        from google.adk.tools import FunctionTool

        def search(q):
            return requests.get("https://example.test", params={"q": q}).text

        def send_email(to, body):
            return requests.post("https://mail.example.test", json={"to": to}).status_code

        email_tool = FunctionTool(func=send_email)
        root_agent = Agent(name="research", model="gemini-2.0-flash",
                           tools=[search, email_tool])
    """)
    assert _attributed(report) == {"tool:search": {"external_apis": "read"},
                                   "tool:send-email": {"external_apis": "write"}}
    adk = next(m["data"] for m in report["agent_models"] if m["framework"] == "google_adk")
    assert {"search", "send_email"} <= set(adk["tools"])  # ADK lists tools as strings


def test_llamaindex_from_defaults_and_langgraph_toolnode(tmp_path):
    (tmp_path / "graph.py").write_text(textwrap.dedent("""
        import os
        from langgraph.graph import StateGraph
        from langgraph.prebuilt import ToolNode

        def purge(path):
            os.remove(path)

        graph = StateGraph(dict)
        graph.add_node("tools", ToolNode([purge]))
    """), encoding="utf-8")
    report = _scan(tmp_path, """
        from llama_index.core.agent import ReActAgent
        from llama_index.core.tools import FunctionTool

        def save(path, text):
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(text)

        tool = FunctionTool.from_defaults(fn=save, name="save_note")
        agent = ReActAgent(tools=[tool])
    """)
    assert _attributed(report) == {"tool:purge": {"filesystem_access": "mutate"},
                                   "tool:save-note": {"filesystem_access": "write"}}


def test_base_tool_subclass(tmp_path):
    report = _scan(tmp_path, """
        import subprocess
        from crewai import Agent
        from crewai.tools import BaseTool

        class Restarter(BaseTool):
            name: str = "restart_service"
            description: str = "Restart a service"

            def _run(self, service):
                return self._call(service)

            def _call(self, service):
                return subprocess.run(["systemctl", "restart", service], check=False)

        agent = Agent(role="ops", tools=[Restarter()])
    """)
    # Every method of a tool class is the tool's, helpers included.
    assert _attributed(report) == {"tool:restart-service": {"shell_execution": "execute"}}


def test_parser_copy_is_replaced_not_duplicated(tmp_path):
    report = _scan(tmp_path, """
        import subprocess
        from crewai import Agent
        from crewai.tools import Tool

        def run(cmd):
            return subprocess.run(cmd, shell=True, check=False)

        shared = Tool(name="run", func=run)
        agent = Agent(role="r", tools=[shared])
    """)
    surface = _surface(report)
    assert surface["tool:run"] == {"shell_execution": "execute"}
    assert "shell_execution" not in surface.get("unknown:unattributed", {})


def test_outside_tool_bodies_nothing_changes(tmp_path):
    report = _scan(tmp_path, """
        import subprocess
        from crewai import Agent
        from crewai.tools import Tool

        def helper(cmd):
            return subprocess.run(cmd, shell=True, check=False)

        def run(cmd):
            return helper(cmd).stdout.replace("a", "b")

        subprocess.run(["make"], check=False)
        tool = Tool(name="run", func=run)
        agent = Agent(role="r", tools=[tool], llm=None)
    """)
    surface = _surface(report)
    assert "tool:run" not in surface  # str.replace is not file access; helper not followed
    assert surface["unknown:unattributed"]["shell_execution"] == "execute"


def test_units():
    assert tool_units(textwrap.dedent("""
        from langchain.tools import Tool, StructuredTool

        def a(): ...
        def b(): ...
        def c(): ...

        t1 = Tool(name="first", func=a)
        t2 = StructuredTool.from_function(b)
        t3 = Tool(name="lam", func=lambda x: x)
        agent = Agent(tools=[c, t1, undefined])
    """)) == {"a": "first", "b": "b", "c": "c"}
    assert tool_units("def (:") == {}


def test_new_shell_tool_is_a_critical_escalation(tmp_path):
    """A subprocess call executes: the mode is explicit, so nothing caps the escalation."""
    from safeai.analysis.capability_diff import compute_capability_diff

    base, cur = tmp_path / "base", tmp_path / "cur"
    head = ("from langchain.agents import initialize_agent\n"
            "from langchain.tools import Tool\n\n"
            "def lookup(key):\n    return key\n\n")
    base.mkdir()
    (base / "agent.py").write_text(
        head + 'tools = [Tool(name="lookup", func=lookup)]\n'
        "agent = initialize_agent(tools=tools, llm=None)\n", encoding="utf-8")
    cur.mkdir()
    (cur / "agent.py").write_text(
        "import subprocess\n" + head
        + "def diagnose(cmd):\n    return subprocess.run(cmd, shell=True, check=False)\n\n"
        + 'tools = [Tool(name="lookup", func=lookup), Tool(name="diagnose", func=diagnose)]\n'
        + "agent = initialize_agent(tools=tools, llm=None)\n", encoding="utf-8")
    current = run_scan(str(cur))
    shell = next(c for e in current["tool_surface"] if e["tool_key"] == "tool:diagnose"
                 for c in e["capabilities"])
    assert (shell["access_mode"], shell["inferred"]) == ("execute", False)
    diff = compute_capability_diff(current, run_scan(str(base)))
    entry = next(t for t in diff["tools"] if t["tool_key"] == "tool:diagnose")
    assert (entry["status"], entry["change_class"]) == ("new", "HIGH_RISK_CHANGE")
    assert any(e["id"] == "ESC_SHELL_ADDED" and e["severity"] == "critical"
               for e in entry["escalations"])
