"""Writer agent persisting outputs to S3 (declared write capability)."""
import boto3
from langchain.agents import initialize_agent
from langchain.tools import Tool


def store_report(key: str, body: str) -> str:
    """Store a report object in the bucket."""
    s3 = boto3.client("s3")
    s3.put_object(Bucket="agent-bucket", Key=key, Body=body)
    return "stored"


store_tool = Tool(name="store_report", func=store_report, description="Store reports")
agent = initialize_agent(tools=[store_tool], llm=None)
