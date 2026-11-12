"""Synthetic scenario: a triage agent with no tools hands off to a billing agent."""
import requests
from agents import Agent, function_tool


@function_tool
def issue_refund(order_id: str) -> str:
    """Issue a refund through the payments API."""
    response = requests.post("https://payments.example.test/refunds", json={"order": order_id})
    return str(response.status_code)


billing = Agent(name="billing", instructions="Handle refunds.", tools=[issue_refund])
triage = Agent(name="triage", instructions="Route the request.", tools=[], handoffs=[billing])
