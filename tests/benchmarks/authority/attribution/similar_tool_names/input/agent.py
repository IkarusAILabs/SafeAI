"""Two similarly named tools with different filesystem authority."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def read_document(path: str) -> str:
    """Read an existing document without modifying it."""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def write_document(path: str, text: str) -> str:
    """Write or replace a document."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return "saved"


read_tool = Tool(
    name="document_reader",
    func=read_document,
    description="Read a document; does not modify files.",
)
write_tool = Tool(
    name="document_writer",
    func=write_document,
    description="Write or replace a document.",
)
agent = initialize_agent(tools=[read_tool, write_tool], llm=None)
