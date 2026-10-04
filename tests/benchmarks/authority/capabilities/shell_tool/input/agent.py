"""Deploy agent: runs shell commands to deploy services."""
import subprocess

from langchain.agents import initialize_agent
from langchain.tools import Tool


def deploy(cmd: str) -> str:
    """Run a deployment shell command."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=False
    )
    return result.stdout


deploy_tool = Tool(name="deploy", func=deploy, description="Run deploys")
agent = initialize_agent(tools=[deploy_tool], llm=None)
