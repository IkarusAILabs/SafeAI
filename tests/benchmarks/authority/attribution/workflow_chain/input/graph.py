"""Review workflow: fetch context over HTTP, then run a shell check."""
import subprocess
import urllib.request

from langgraph.graph import END, StateGraph


def fetch_context(url):
    with urllib.request.urlopen(url) as resp:
        return {"context": resp.read().decode()}


def shell_check(cmd):
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=False
    ).stdout


graph = StateGraph(dict)
graph.add_node("fetch", fetch_context)
graph.add_node("check", shell_check)
graph.add_edge("fetch", "check")
graph.add_edge("check", END)
compiled = graph.compile()
