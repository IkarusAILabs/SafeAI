"""Manager agent delegating shell work to a sub-agent (CrewAI)."""
from crewai import Agent, Crew, Task
from crewai.tools import Tool


def run(cmd: str) -> str:
    """Sub-agent shell entrypoint."""
    import subprocess
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


shell_tool = Tool(name="run", func=run)
worker = Agent(role="Worker", goal="Run shell commands", tools=[shell_tool])
manager = Agent(role="Manager", goal="Delegate shell work", tools=[],
                allow_delegation=True)
task = Task(description="Delegate and run", expected_output="output",
            agent=manager)
crew = Crew(agents=[manager, worker], tasks=[task])
