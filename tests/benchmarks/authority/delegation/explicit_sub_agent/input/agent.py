"""Direct sub-agent creation with explicit delegation relationship."""
from crewai import Agent, Task
from langchain.agents import initialize_agent
from langchain.tools import Tool


def analysis_tool(data: str) -> str:
    """Perform data analysis."""
    return f"Analyzed: {data[:50]}..."


def processing_tool(item: str) -> str:
    """Process an item.""" 
    return f"Processed: {item}"


# Parent agent creates and manages child agents
parent_agent = Agent(
    role="Parent Agent",
    goal="Manage child agents and delegate work",
    backstory="I create and supervise specialized child agents",
    allow_delegation=True
)

# Child agent for analysis tasks
analyst_agent = Agent(
    role="Analyst Agent", 
    goal="Perform data analysis tasks",
    backstory="I specialize in analyzing data and providing insights",
    tools=[Tool(name="analysis", func=analysis_tool, description="Analyze data")]
)

# Child agent for processing tasks  
processor_agent = Agent(
    role="Processor Agent",
    goal="Process data items",
    backstory="I specialize in processing data through various transformations",
    tools=[Tool(name="process", func=processing_tool, description="Process items")]
)

# Tasks that will be delegated to child agents
analysis_task = Task(
    description="Analyze the provided dataset for trends and patterns",
    expected_output="Analysis report with key insights",
    agent=analyst_agent
)

processing_task = Task(
    description="Process each item in the input list according to specifications",
    expected_output="Processed items list",
    agent=processor_agent
)

# Parent delegates work to child agents