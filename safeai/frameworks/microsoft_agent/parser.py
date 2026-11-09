"""Microsoft Agent Framework adapter.

Detects the Microsoft Agent / Azure AI Agents framework via dependency
metadata (``azure-ai-agents``, ``azure-ai-projects``), AST import
analysis (``azure.ai.agents``, ``microsoft.agent``), and YAML/JSON
config patterns. Extracts agents, workflows, tools, prompts, memory,
model references, and cloud model capabilities.
"""

import re

from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.analysis.semantic import (
    build_semantic_document,
    resolve_symbol,
    resolve_symbol_origin,
)
from safeai.frameworks import register_parser


@register_parser
class MicrosoftAgentFrameworkParser:
    name = "microsoft_agent_framework"
    # Shell, file and HTTP calls in registered tool functions are reported
    # as that tool's authority (safeai.analysis.tool_bodies).
    attributes_tool_bodies = True

    def detect(self, path, content, scan_ctx=None):
        deps = set()
        module_name = ""
        if scan_ctx:
            deps = scan_ctx.get("dependencies", set())
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        if "azure-ai-agents" in deps or "azure-ai-projects" in deps:
            low = content.lower()
            if path.endswith(".py") and ("azure" in low or "agentclient" in low or "microsoft.agent" in low):
                return True
            if path.endswith((".yaml", ".yml", ".json")) and ("azure" in low or "agent" in low):
                return True

        if path.endswith(".py"):
            doc = build_semantic_document(path, content, module_name=module_name)
            imports = list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]
            for imported in imports:
                if imported.startswith(("azure.ai.agents", "microsoft.agent")):
                    return True

        return "azure.ai.agents" in content or "agentclient" in content.lower()

    def parse(self, path, content, scan_ctx=None):
        agents = []
        workflows = []
        planners = []
        tools = []
        prompts = []
        memory = []
        models = []
        relationships = []
        capabilities = []

        if path.endswith(".py"):
            module_name = ""
            import_graph = None
            if scan_ctx:
                module_name = scan_ctx.get("module_by_file", {}).get(path, "")
                import_graph = scan_ctx.get("import_graph")
            doc = build_semantic_document(path, content, module_name=module_name)
            for call in doc.calls:
                resolved = resolve_symbol(doc, call["name"])
                origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
                lname = (resolved or call["name"]).lower()
                if "agent" in lname:
                    agents.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                if "run" in lname or "workflow" in lname:
                    workflows.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                    planners.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                if "tool" in lname or "function" in lname:
                    tools.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                if "prompt" in lname:
                    prompts.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                if "memory" in lname:
                    memory.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                    capabilities.append(make_capability("memory", "Memory", self.name, call["name"], confidence=0.8, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
                if "azure" in lname or "openai" in lname or "gpt" in lname:
                    models.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                    capabilities.append(make_capability("cloud_model", "Cloud", self.name, call["name"], confidence=0.85, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
        else:
            for line in content.splitlines():
                low = line.lower()
                if "agent" in low:
                    agents.append({"name": line.strip(), "evidence": line.strip()})
                if "tool" in low:
                    tools.append({"name": line.strip(), "evidence": line.strip()})
                if "model" in low:
                    models.append({"name": line.strip(), "evidence": line.strip()})

        if not agents:
            agents = [{"name": x, "evidence": x} for x in re.findall(r"Agent\(|agent", content)]

        for workflow in workflows:
            w_kwargs = workflow.get("kwargs", {})
            for rel_key in ["tool", "tools", "memory", "instructions", "model", "approval"]:
                if rel_key not in w_kwargs:
                    continue
                relationships.append({
                    "from": workflow.get("name"),
                    "to": str(w_kwargs.get(rel_key)),
                    "type": rel_key,
                    "framework": self.name,
                    "evidence": workflow.get("name"),
                })

        return {
            "framework": self.name,
            "agents": agents,
            "workflows": workflows,
            "planners": planners,
            "tools": tools,
            "prompts": prompts,
            "memory": memory,
            "models": models,
            "relationships": relationships,
            "capabilities": dedupe_capabilities(capabilities),
            "discovery_method": "ast+configuration+metadata+regex_fallback",
            "parser_confidence": 0.85,
            "detection_evidence": ["imports:azure.ai.agents", "ast:calls", "dependencies"],
        }
