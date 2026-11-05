import subprocess

import requests
from agents import Agent, function_tool


@function_tool
def http_get(url: str) -> str:
    return requests.get(url, timeout=10).text


@function_tool
def fetch_page(url: str) -> str:
    return requests.get(url, timeout=10).text


@function_tool
def run_report(name: str) -> str:
    return subprocess.run(["report", name], capture_output=True, text=True,
                          check=False).stdout


@function_tool
def lookup(order_id: str) -> str:
    ...


worker = Agent(name="worker", tools=[fetch_page, run_report, lookup])
triage = Agent(name="triage", tools=[http_get])
