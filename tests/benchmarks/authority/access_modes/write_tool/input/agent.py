"""Writer agent: writes files."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def save_note(path: str, text: str) -> str:
    """Save a note file."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return "saved"


save_tool = Tool(name="save_note", func=save_note, description="Save notes")
agent = initialize_agent(tools=[save_tool], llm=None)
