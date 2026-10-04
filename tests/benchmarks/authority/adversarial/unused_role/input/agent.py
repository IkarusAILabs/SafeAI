"""Agent reading reports; idle-role exists but grants it nothing."""
import boto3
from langchain.agents import initialize_agent
from langchain.tools import Tool

s3 = boto3.client("s3")


def fetch_report(key: str) -> bytes:
    """Read a report object from the bucket."""
    return s3.get_object(Bucket="agent-bucket", Key=key)["Body"].read()


reader = Tool(name="fetch_report", func=fetch_report, description="Read reports")
agent = initialize_agent(tools=[reader], llm=None)
