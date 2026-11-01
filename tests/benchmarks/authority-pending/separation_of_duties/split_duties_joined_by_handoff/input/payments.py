from agents import Agent, function_tool


@function_tool
def create_payment(amount: int) -> str:
    return str(amount)


@function_tool
def approve_payment(payment_id: str) -> str:
    return payment_id


approver = Agent(name="approver", tools=[approve_payment])
drafter = Agent(name="drafter", tools=[create_payment], handoffs=[approver])
signer = Agent(name="signer", tools=[approve_payment])
requester = Agent(name="requester", tools=[create_payment])
