"""OpenAI Agents SDK framework adapter.

Detects OpenAI Agents SDK via dependency metadata, AST import analysis
(``import agents``, ``import openai``), and regex fallback. Extracts
agents, tools, handoffs/workflows, prompts, memory, MCP references,
model references, and infers multi-agent, delegation, memory, and MCP
capabilities.
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
class OpenAIAgentsParser:
    name = "openai_agents"
    # Shell, file and HTTP calls in registered tool functions are reported
    # as that tool's authority (safeai.analysis.tool_bodies).
    attributes_tool_bodies = True

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        module_name = ""
        deps = set()
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            deps = scan_ctx.get("dependencies", set())
        if ("openai-agents" in deps or "openai" in deps) and ("Agent(" in content or "agents" in content.lower()):
            return True
        doc = build_semantic_document(path, content, module_name=module_name)
        for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
            if imported.startswith(("agents", "openai")) and "agent" in content.lower():
                return True
        low = content.lower()
        return "openai.agents" in low or "from agents import" in low or "import agents" in low

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        import_graph = None
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            import_graph = scan_ctx.get("import_graph")
        doc = build_semantic_document(path, content, module_name=module_name)

        agents = []
        tools = []
        workflows = []
        planners = []
        prompts = []
        memory = []
        mcp_assets = []
        models = []
        relationships = []
        capabilities = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()
            if lname.endswith("agent"):
                agents.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                capabilities.append(make_capability("multi_agent", "Multi-Agent", self.name, call["name"], confidence=0.75, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if "tool" in lname:
                tools.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
            if "handoff" in lname or "workflow" in lname:
                workflows.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                planners.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("delegation", "Delegation", self.name, call["name"], confidence=0.8, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if "prompt" in lname:
                prompts.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if "memory" in lname:
                memory.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("memory", "Memory", self.name, call["name"], confidence=0.85, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if "mcp" in lname:
                mcp_assets.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("mcp_integration", "MCP", self.name, call["name"], confidence=0.9, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if any(m in lname for m in ["gpt", "responses", "chat.completions"]):
                models.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("external_model_api", "External APIs", self.name, call["name"], confidence=0.85, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))

        for workflow in workflows:
            w_kwargs = workflow.get("kwargs", {})
            for rel_key in ["tools", "tool", "memory", "planner", "handoffs", "model"]:
                if rel_key not in w_kwargs:
                    continue
                relationships.append({
                    "from": workflow.get("name"),
                    "to": str(w_kwargs.get(rel_key)),
                    "type": rel_key,
                    "framework": self.name,
                    "evidence": workflow.get("name"),
                })

        if not agents:
            agents = [{"name": x, "evidence": x} for x in re.findall(r"\bAgent\(", content)]

        return {
            "framework": "openai_agents",
            "agents": agents,
            "workflows": workflows,
            "planners": planners,
            "tools": tools,
            "prompts": prompts,
            "memory": memory,
            "mcp_assets": mcp_assets,
            "models": models,
            "relationships": relationships,
            "capabilities": dedupe_capabilities(capabilities),
            "discovery_method": "ast+metadata+regex_fallback",
            "parser_confidence": 0.87,
            "detection_evidence": ["imports:openai/agents", "ast:calls"],
        }
