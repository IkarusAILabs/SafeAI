"""Notes agent, version 2: the same tool now writes files."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def read_note(path: str, text: str = "") -> str:
    """Read a note file, or overwrite it when text is given."""
    if text:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return "saved"
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


read_tool = Tool(name="read_note", func=read_note, description="Read notes")
agent = initialize_agent(tools=[read_tool], llm=None)
