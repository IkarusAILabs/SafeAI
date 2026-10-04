"""Notes agent, version 1: read-only file access."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def read_note(path: str) -> str:
    """Read a note file."""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


read_tool = Tool(name="read_note", func=read_note, description="Read notes")
agent = initialize_agent(tools=[read_tool], llm=None)
