"""Triage workflow: classify then answer, with a shell-capable tool node."""
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode
import subprocess


def classify(state):
    return {"label": "synthetic"}


def shell_run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


graph = StateGraph(dict)
graph.add_node("classify", classify)
graph.add_node("tools", ToolNode([shell_run]))
graph.add_edge("classify", "tools")
graph.add_edge("tools", END)
model = ChatOpenAI(model="synthetic-model")
compiled = graph.compile()
