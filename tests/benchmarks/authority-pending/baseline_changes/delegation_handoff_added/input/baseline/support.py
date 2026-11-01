from agents import Agent, function_tool


@function_tool
def lookup_order(order_id: str) -> str:
    return order_id


@function_tool
def issue_refund(order_id: str) -> str:
    return order_id

refunds = Agent(name="refunds", tools=[lookup_order, issue_refund])
billing = Agent(name="billing", tools=[lookup_order])
triage = Agent(name="triage", tools=[lookup_order], handoffs=[billing])
