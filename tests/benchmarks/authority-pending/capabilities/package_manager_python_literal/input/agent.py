"""Dependency helper agent: one tool installs a package, one runs anything."""
import subprocess

from langgraph.graph import StateGraph


def install_dependency(pkg):
    subprocess.run(["npm", "install", pkg], check=True)
    return "ok"


graph = StateGraph(dict)
graph.add_node("install", install_dependency)
compiled = graph.compile()
