"""Synthetic scenario: a manager with read and write tools hands off to a read-only auditor."""
from agents import Agent, function_tool


@function_tool
def read_ledger(account: str) -> str:
    """Read a ledger file."""
    with open(f"ledger/{account}.csv", encoding="utf-8") as handle:
        return handle.read()


@function_tool
def write_ledger(account: str, row: str) -> str:
    """Append a row to a ledger file."""
    with open(f"ledger/{account}.csv", "a", encoding="utf-8") as handle:
        handle.write(row)
    return "ok"


auditor = Agent(name="auditor", instructions="Review the ledger.", tools=[read_ledger])
manager = Agent(name="manager", instructions="Keep the ledger.",
                tools=[read_ledger, write_ledger], handoffs=[auditor])
