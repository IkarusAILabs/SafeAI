"""Two code agents, each bound to its own role via explicit config refs."""
import boto3
from langchain.agents import initialize_agent
from langchain.tools import Tool

s3 = boto3.client("s3")


def read_reports(prefix: str) -> list:
    """List report objects under a prefix."""
    return s3.list_objects_v2(Bucket="agent-bucket", Prefix=prefix).get("Contents", [])


reader = Tool(name="read_reports", func=read_reports, description="List reports")
agent = initialize_agent(tools=[reader], llm=None)
