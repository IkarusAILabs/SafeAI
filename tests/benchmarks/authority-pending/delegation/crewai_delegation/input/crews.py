from crewai import Agent, Crew, Process, Task
from crewai_tools import FileWriterTool, SerperDevTool

researcher = Agent(role="researcher", goal="g", backstory="b",
                   tools=[SerperDevTool()], allow_delegation=True)
writer = Agent(role="writer", goal="g", backstory="b",
               tools=[FileWriterTool()], allow_delegation=False)
brief = Task(description="Research and write", expected_output="a brief", agent=researcher)
research = Crew(agents=[researcher, writer], tasks=[brief], process=Process.sequential)

lead = Agent(role="lead", goal="g", backstory="b", tools=[])
ops = Crew(agents=[researcher, writer], tasks=[brief], process=Process.hierarchical,
           manager_agent=lead)
