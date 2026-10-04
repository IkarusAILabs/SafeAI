"""Ops agent, version 1: lookup plus shell tool."""
import subprocess

from langchain.agents import initialize_agent
from langchain.tools import Tool


def lookup(key: str) -> str:
    """Look up a value (read-only)."""
    return "value-for-" + key


def diagnose(cmd: str) -> str:
    """Run a diagnostic shell command."""
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=False
    ).stdout


lookup_tool = Tool(name="lookup", func=lookup, description="Look up values")
diagnose_tool = Tool(name="diagnose", func=diagnose, description="Run diagnostics")
agent = initialize_agent(tools=[lookup_tool, diagnose_tool], llm=None)
