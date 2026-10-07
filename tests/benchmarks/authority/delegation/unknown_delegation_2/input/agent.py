"""Agent with plugin-based delegation where targets are loaded at runtime."""
import importlib
from typing import Protocol


class AgentPlugin(Protocol):
    def execute(self, task: str) -> str: ...


def load_plugin(plugin_name: str) -> AgentPlugin:
    """Dynamically load a plugin at runtime."""
    try:
        module = importlib.import_module(f"plugins.{plugin_name}")
        return module.Plugin()
    except ImportError:
        raise ValueError(f"Plugin {plugin_name} not found")


def delegate_task(plugin_name: str, task: str) -> str:
    """Delegate task to dynamically loaded plugin."""
    plugin = load_plugin(plugin_name)
    return plugin.execute(task)


# Example usage - the actual plugin is unknown at static analysis time
# delegate_task("unknown_plugin", "process_data")