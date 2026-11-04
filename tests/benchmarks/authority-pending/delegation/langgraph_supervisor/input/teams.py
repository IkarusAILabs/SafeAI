from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor


@tool
def web_search(query: str) -> str:
    """Search the web."""
    return query


@tool
def run_python(code: str) -> str:
    """Run Python code."""
    return code


@tool
def publish_post(text: str) -> str:
    """Publish a blog post."""
    return text


researcher = create_react_agent(model="m", tools=[web_search], name="researcher")
coder = create_react_agent(model="m", tools=[run_python], name="coder")
research_team = create_supervisor(
    [researcher, coder], model="m", supervisor_name="research_lead"
).compile(name="research_team")

writer = create_react_agent(model="m", tools=[publish_post], name="writer")
top = create_supervisor([research_team, writer], model="m", supervisor_name="editor").compile()
