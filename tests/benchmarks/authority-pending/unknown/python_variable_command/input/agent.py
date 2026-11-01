"""Dependency helper agent whose command is chosen at run time."""
import subprocess

from langgraph.graph import StateGraph


def manage_dependencies(command):
    subprocess.run(command, shell=True, check=True)
    return "ok"


graph = StateGraph(dict)
graph.add_node("deps", manage_dependencies)
compiled = graph.compile()
