"""Ops agent: executes maintenance commands."""
import subprocess
from langchain.agents import initialize_agent
from langchain.tools import Tool


def maintain(cmd: str) -> str:
    """Execute a maintenance command."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


ops_tool = Tool(name="maintain", func=maintain, description="Run maintenance")
agent = initialize_agent(tools=[ops_tool], llm=None)
