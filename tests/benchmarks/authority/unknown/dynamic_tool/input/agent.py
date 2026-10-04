"""Agent loading tool implementations dynamically (unresolvable statically)."""
import importlib

from langchain.agents import initialize_agent
from langchain.tools import Tool


def dynamic_tool(name: str, payload: str) -> str:
    """Import and invoke a tool module chosen at runtime."""
    module = importlib.import_module("tools." + name)
    return module.run(payload)


tool = Tool(name="dynamic_tool", func=dynamic_tool, description="Dynamic dispatch")
agent = initialize_agent(tools=[tool], llm=None)
