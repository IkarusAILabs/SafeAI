"""Synthetic scenario (calibration): one agent with one read-only tool."""
from agents import Agent, function_tool


@function_tool
def read_invoice(invoice_id: str) -> str:
    """Read an invoice from the local store."""
    with open(f"invoices/{invoice_id}.txt", encoding="utf-8") as handle:
        return handle.read()


clerk = Agent(name="clerk", instructions="Answer invoice questions.", tools=[read_invoice])
