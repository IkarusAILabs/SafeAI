"""Support agent: read-only ticket lookup plus docs MCP server."""
from crewai import Agent, Crew, Task
from crewai.tools import Tool


def lookup_ticket(ticket_id: str) -> str:
    """Look up a ticket (read-only)."""
    return "ticket-" + ticket_id


lookup_tool = Tool(name="lookup_ticket", func=lookup_ticket)
support = Agent(role="Support", goal="Answer questions", tools=[lookup_tool])
task = Task(description="Answer", expected_output="Answer", agent=support)
crew = Crew(agents=[support], tasks=[task])
