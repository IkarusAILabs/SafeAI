"""LangGraph workflow delegation with conditional routing between nodes."""
from langgraph.graph import StateGraph, END
from typing import TypedDict, Annotated
import operator


class WorkflowState(TypedDict):
    task_type: str
    data: str
    result: Annotated[list, operator.add]


def analyze_node(state: WorkflowState) -> WorkflowState:
    """Analysis node that processes data."""
    return {
        "task_type": state["task_type"],
        "data": state["data"],
        "result": [f"Analyzed: {state['data'][:50]}..."]
    }


def process_node(state: WorkflowState) -> WorkflowState:
    """Processing node that transforms data."""
    return {
        "task_type": state["task_type"],
        "data": state["data"],
        "result": [f"Processed: {state['data']}"]
    }


def route_task(state: WorkflowState) -> str:
    """Route to appropriate node based on task type."""
    if state["task_type"] == "analyze":
        return "analyze"
    elif state["task_type"] == "process":
        return "process"
    else:
        return END


# Create workflow graph
workflow = StateGraph(WorkflowState)
workflow.add_node("analyze", analyze_node)
workflow.add_node("process", process_node)
workflow.add_conditional_edges(
    "start",
    route_task,
    {
        "analyze": "analyze",
        "process": "process"
    }
)
workflow.add_edge("analyze", END)
workflow.add_edge("process", END)
workflow.set_entry_point("start")

app = workflow.compile()