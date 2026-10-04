"""Agent with a dynamically chosen helper (delegation target unknown)."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def dispatch(task: str) -> str:
    """Dispatch to a helper selected at runtime."""
    helper_name = "helper_" + task.split(":")[0]
    helper = globals().get(helper_name)
    if helper is None:
        raise ValueError("unknown helper")
    return helper(task)


dispatch_tool = Tool(name="dispatch", func=dispatch, description="Dispatch tasks")
agent = initialize_agent(tools=[dispatch_tool], llm=None)
