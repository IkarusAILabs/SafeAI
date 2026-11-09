"""Representative AutoGen (autogen-agentchat) project: a two-agent support team."""

import subprocess

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient


def read_ticket(ticket_id: str) -> str:
    """Read a support ticket from the local queue."""
    with open(f"tickets/{ticket_id}.txt", encoding="utf-8") as fh:
        return fh.read()


def restart_service(name: str) -> str:
    """Restart a service on the support host."""
    return subprocess.run(["systemctl", "restart", name], capture_output=True, text=True,
                          check=False).stdout


model = OpenAIChatCompletionClient(model="gpt-4o")
triage = AssistantAgent("triage", model_client=model, tools=[read_ticket],
                        system_message="Classify the ticket.")
operator = AssistantAgent("operator", model_client=model, tools=[restart_service],
                          system_message="Fix what triage escalates.")
team = RoundRobinGroupChat([triage, operator], max_turns=4)
