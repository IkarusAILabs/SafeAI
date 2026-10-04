"""Agent driving an MCP web server whose tool reaches an external resource."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def lookup(query: str) -> str:
    """Answer from the docs MCP server (server: web)."""
    return "see mcp server web for: " + query


web_tool = Tool(name="lookup", func=lookup, description="Look up docs")
agent = initialize_agent(tools=[web_tool], llm=None)
