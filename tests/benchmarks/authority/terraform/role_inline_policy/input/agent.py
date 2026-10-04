"""Reader agent using an S3-backed store (declared read capability)."""
import boto3
from langchain.agents import initialize_agent
from langchain.tools import Tool


def fetch_report(key: str) -> str:
    """Fetch a report object from the bucket."""
    s3 = boto3.client("s3")
    return s3.get_object(Bucket="agent-bucket", Key=key)["Body"].read().decode()


fetch_tool = Tool(name="fetch_report", func=fetch_report, description="Fetch reports")
agent = initialize_agent(tools=[fetch_tool], llm=None)
