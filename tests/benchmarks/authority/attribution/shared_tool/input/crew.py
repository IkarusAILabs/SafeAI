"""Two agents share one shell tool; the tool has a single implementation."""
import subprocess

from crewai import Agent, Crew, Task
from crewai.tools import Tool


def run(cmd: str) -> str:
    """Shared shell entrypoint used by both agents."""
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=False
    ).stdout


shared_tool = Tool(name="run", func=run)
releaser = Agent(role="Releaser", goal="Ship releases", tools=[shared_tool])
rollbacker = Agent(role="Rollbacker", goal="Revert releases", tools=[shared_tool])
task = Task(description="Release and be ready to revert", expected_output="done",
            agent=releaser)
crew = Crew(agents=[releaser, rollbacker], tasks=[task])