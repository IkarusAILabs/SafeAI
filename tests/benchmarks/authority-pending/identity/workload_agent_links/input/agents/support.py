from agents import Agent, function_tool


@function_tool
def lookup_order(order_id: str) -> str:
    return order_id


support = Agent(name="support-bot", instructions="Help customers.", tools=[lookup_order])
