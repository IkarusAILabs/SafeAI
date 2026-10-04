"""Two tools share the S3 capability with different access modes."""
import boto3
from langchain.agents import initialize_agent
from langchain.tools import Tool

s3 = boto3.client("s3")


def fetch_report(key: str) -> bytes:
    """Read a report object from the bucket."""
    return s3.get_object(Bucket="agent-bucket", Key=key)["Body"].read()


def publish_report(payload: str) -> str:
    """Write a report object to the bucket (payload is 'key Contents...')."""
    key, _, body = payload.partition("\n")
    s3.put_object(Bucket="agent-bucket", Key=key, Body=body.encode())
    return "ok"


reader = Tool(name="fetch_report", func=fetch_report, description="Read reports")
writer = Tool(name="publish_report", func=publish_report, description="Write reports")
agent = initialize_agent(tools=[reader, writer], llm=None)
