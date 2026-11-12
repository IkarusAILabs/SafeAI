"""Synthetic scenario: an agent uploads reports; nothing ties it to the role in main.tf."""
import requests
from agents import Agent, function_tool


@function_tool
def upload_report(name: str, body: str) -> str:
    """Upload a report to the reporting service."""
    response = requests.put(f"https://reports.example.test/{name}", data=body)
    return str(response.status_code)


reporter = Agent(name="reporter", instructions="Publish reports.", tools=[upload_report])
