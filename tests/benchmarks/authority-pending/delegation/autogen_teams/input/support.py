from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.base import Handoff
from autogen_agentchat.teams import RoundRobinGroupChat, Swarm


def lookup_order(order_id: str) -> str:
    return order_id


def issue_refund(order_id: str) -> str:
    return order_id


triage = AssistantAgent("triage", model_client=None, tools=[lookup_order],
                        handoffs=["refunds", Handoff(target="user")])
refunds = AssistantAgent("refunds", model_client=None, tools=[issue_refund],
                         handoffs=["triage"])
support = Swarm([triage, refunds])

writer = AssistantAgent("writer", model_client=None)
critic = AssistantAgent("critic", model_client=None, tools=[lookup_order])
review = RoundRobinGroupChat([writer, critic])
