"""Three-level delegation: overseer -> manager -> worker tool."""
import subprocess

from crewai import Agent, Crew, Task
from crewai.tools import Tool


def run(cmd: str) -> str:
    """Leaf shell entrypoint."""
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=False
    ).stdout


shell_tool = Tool(name="run", func=run)
worker = Agent(role="Worker", goal="Run shell commands", tools=[shell_tool])
manager = Agent(role="Manager", goal="Supervise the worker", tools=[],
                allow_delegation=True)
overseer = Agent(role="Overseer", goal="Supervise managers", tools=[],
                 allow_delegation=True)
task = Task(description="Run supervised work", expected_output="output",
            agent=overseer)
crew = Crew(agents=[overseer, manager, worker], tasks=[task])