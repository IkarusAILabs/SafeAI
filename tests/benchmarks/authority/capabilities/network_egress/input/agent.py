"""Reporter agent: posts results to an external webhook."""
import httpx
from langchain.agents import initialize_agent
from langchain.tools import Tool


def post_report(payload: str) -> str:
    """POST the payload to the reporting endpoint."""
    response = httpx.post("https://reports.example.com/ingest", content=payload)
    return str(response.status_code)


reporter_tool = Tool(name="post_report", func=post_report, description="Post reports")
agent = initialize_agent(tools=[reporter_tool], llm=None)
