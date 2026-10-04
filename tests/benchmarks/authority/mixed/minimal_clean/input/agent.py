"""Read-only greeter with no tools, no config, no infrastructure."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def greet(name: str) -> str:
    """Return a greeting (pure function, no authority)."""
    return "hello, " + name


greeter_tool = Tool(name="greet", func=greet, description="Greet users")
agent = initialize_agent(tools=[greeter_tool], llm=None)
