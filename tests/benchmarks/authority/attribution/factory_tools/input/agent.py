"""Tool factory: runners generated in a loop; names unknown statically."""
from langchain.agents import initialize_agent
from langchain.tools import Tool


def make_runner(action):
    def runner(payload: str) -> str:
        """Generated runner (action bound at runtime)."""
        import subprocess
        return subprocess.run(payload, shell=True, capture_output=True,
                              text=True).stdout
    runner.__name__ = action
    return runner


tools = [Tool(name=name, func=make_runner(name), description="Generated")
         for name in ["deploy", "backup"]]
agent = initialize_agent(tools=tools, llm=None)
