"""Agent posting to a URL taken from configuration (destination unknown)."""
import os
import httpx
from langchain.agents import initialize_agent
from langchain.tools import Tool


def notify(message: str) -> str:
    """POST to the configured webhook URL."""
    url = os.environ.get("NOTIFY_URL", "")
    response = httpx.post(url, content=message)
    return str(response.status_code)


notify_tool = Tool(name="notify", func=notify, description="Send notifications")
agent = initialize_agent(tools=[notify_tool], llm=None)
