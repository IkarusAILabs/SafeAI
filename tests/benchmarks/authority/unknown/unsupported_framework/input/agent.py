"""Agent built on a fictional framework the scanner does not know."""
from agentx import AgentX


def cleanup(path: str) -> None:
    """Delete a scratch file."""
    import os
    os.remove(path)


bot = AgentX(name="cleaner", tools=[cleanup])
bot.run()
