"""Synthetic scenario: an intern agent hands off to an admin agent that can delete accounts."""
import requests
from agents import Agent, function_tool


@function_tool
def read_ticket(ticket_id: str) -> str:
    """Read a support ticket."""
    with open(f"tickets/{ticket_id}.txt", encoding="utf-8") as handle:
        return handle.read()


@function_tool
def delete_account(account_id: str) -> str:
    """Delete a customer account."""
    return str(requests.delete(f"https://accounts.example.test/{account_id}").status_code)


admin = Agent(name="admin", instructions="Handle account removal.", tools=[delete_account])
intern = Agent(name="intern", instructions="Answer tickets.", tools=[read_ticket],
               handoffs=[admin])
