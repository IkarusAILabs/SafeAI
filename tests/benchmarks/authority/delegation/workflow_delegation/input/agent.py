"""Workflow orchestrator delegating to subprocess tasks using Prefect."""
import subprocess
from prefect import flow, task


@task
def execute_command(cmd: str) -> str:
    """Execute a shell command task."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@task  
def process_file(path: str) -> str:
    """Process a file task."""
    with open(path) as f:
        return f.read().upper()


@flow
def workflow_orchestrator(task_type: str, task_input: str) -> str:
    """Orchestrator flow that delegates to appropriate task."""
    if task_type == "shell":
        return execute_command(task_input)
    elif task_type == "process":
        return process_file(task_input)
    else:
        raise ValueError(f"Unknown task type: {task_type}")


# Expose as a tool
def delegate_task(task_type: str, task_input: str) -> str:
    """Tool interface for workflow delegation."""
    return workflow_orchestrator(task_type, task_input)