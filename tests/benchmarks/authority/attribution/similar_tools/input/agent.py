"""One read-only tool beside one write tool with a near-identical name."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def read_note(path: str) -> str:
    """Read a note file."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def write_note(payload: str) -> str:
    """Write a note file (payload is 'path Contents...')."""
    path, _, content = payload.partition("\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return "ok"


reader = Tool(name="read_note", func=read_note, description="Read notes")
writer = Tool(name="write_note", func=write_note, description="Write notes")
agent = initialize_agent(tools=[reader, writer], llm=None)
