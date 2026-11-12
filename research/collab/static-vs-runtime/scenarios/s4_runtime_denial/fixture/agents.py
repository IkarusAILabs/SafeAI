"""Synthetic scenario: an operator agent holds a shell tool the runtime policy denies."""
import subprocess

from agents import Agent, function_tool


@function_tool
def restart_service(name: str) -> str:
    """Restart a service on the host."""
    return subprocess.run(["systemctl", "restart", name], capture_output=True, text=True,
                          check=False).stdout


operator = Agent(name="operator", instructions="Keep services healthy.",
                 tools=[restart_service])
