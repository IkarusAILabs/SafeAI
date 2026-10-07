"""LangChain agent delegation to a tool-calling subprocess agent."""
from langchain.agents import AgentExecutor, initialize_agent
from langchain.tools import Tool
from langchain.llms import OpenAI


def shell_tool(cmd: str) -> str:
    """Execute shell command."""
    import subprocess
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def read_file_tool(path: str) -> str:
    """Read file contents."""
    with open(path) as f:
        return f.read()


tools = [
    Tool(name="shell", func=shell_tool, description="Execute shell commands"),
    Tool(name="read_file", func=read_file_tool, description="Read file contents"),
]

base_agent = initialize_agent(tools=tools, llm=OpenAI(), agent="openai-functions", verbose=False)

# Delegate to subprocess agent
subprocess_agent = initialize_agent(tools=tools, llm=OpenAI(), agent="openai-functions", verbose=False)

# Framework delegation pattern
delegator = AgentExecutor.from_agent_and_toolkit(
    agent=base_agent,
    tools=[],
    verbose=False
)