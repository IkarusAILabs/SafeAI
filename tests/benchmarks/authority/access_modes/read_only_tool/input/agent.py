"""Read-only lookup agent."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def lookup(key: str) -> str:
    """Look up a value (read-only)."""
    return "value-for-" + key


lookup_tool = Tool(name="lookup", func=lookup, description="Look up values")
agent = initialize_agent(tools=[lookup_tool], llm=None)
