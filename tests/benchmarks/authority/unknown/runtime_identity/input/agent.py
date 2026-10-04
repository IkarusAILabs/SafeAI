"""Agent assuming its AWS identity at runtime (no static identity)."""
import boto3
from langchain.agents import initialize_agent
from langchain.tools import Tool


def list_buckets() -> str:
    """List buckets with ambient credentials resolved at runtime."""
    s3 = boto3.client("s3")
    return str(s3.list_buckets().get("Buckets", []))


buckets_tool = Tool(name="list_buckets", func=list_buckets, description="List buckets")
agent = initialize_agent(tools=[buckets_tool], llm=None)
