"""LangGraph framework adapter.

Detects LangGraph usage via AST import analysis (``import langgraph``)
and regex fallback (``StateGraph``, ``Graph(``). Extracts nodes
(function defs), edges, tools, models (ChatOpenAI, Bedrock, etc.),
memory/checkpointer references, and infers capabilities from call
expressions (shell, filesystem, model API calls).
"""

import re

from safeai.analysis import package_managers
from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.analysis.semantic import (
    build_semantic_document,
    resolve_symbol,
    resolve_symbol_origin,
)
from safeai.frameworks import register_parser


@register_parser
class LangGraphParser:
    name = "langgraph"
    # Shell, file and HTTP calls in registered tool functions are reported
    # as that tool's authority (safeai.analysis.tool_bodies).
    attributes_tool_bodies = True

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        module_name = ""
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        doc = build_semantic_document(path, content, module_name=module_name)
        for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
            if imported.startswith("langgraph"):
                return True
        # Conservative keyword signals requiring actual usage: import-based
        # detection is primary; the fallback requires a direct StateGraph
        # instantiation rather than a bare substring to avoid false positives
        # on unrelated uses (e.g. networkx.Graph).
        return re.search(r"\bStateGraph\s*\(", content) is not None

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        import_graph = None
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            import_graph = scan_ctx.get("import_graph")
        doc = build_semantic_document(path, content, module_name=module_name)

        nodes = list(doc.functions.keys())
        edges = []
        tools = []
        workflows = []
        planners = []
        prompts = []
        memory = []
        models = []
        relationships = []
        capabilities = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()
            if lname.endswith(("add_edge", "add_conditional_edges")):
                edges.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                workflows.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                planners.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if "bind_tools" in lname or lname.endswith("tool"):
                tools.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
            if "prompt" in lname:
                prompts.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if "memory" in lname or "checkpointer" in lname:
                memory.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("memory", "Memory", self.name, call["name"], confidence=0.85, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if any(m in lname for m in ["chatopenai", "azurechatopenai", "bedrock", "anthropic"]):
                models.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("external_model_api", "External APIs", self.name, call["name"], confidence=0.8, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))

            if any(s in lname for s in ["subprocess", "os.system", "popen"]):
                capabilities.append(make_capability("shell_execution", "Shell", self.name, call["name"], confidence=0.9, risk_weight=1.6, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
                package_manager = package_managers.call_capability(call, self.name, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}")
                if package_manager:
                    capabilities.append(package_manager)
            if any(s in lname for s in ["open", "pathlib", "os.remove", "os.write"]):
                capabilities.append(make_capability("filesystem_access", "Filesystem", self.name, call["name"], confidence=0.85, risk_weight=1.2, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))

        for workflow in workflows:
            w_kwargs = workflow.get("kwargs", {})
            for rel_key in ["source", "target", "tool", "tools", "memory", "model"]:
                if rel_key not in w_kwargs:
                    continue
                relationships.append({
                    "from": workflow.get("name"),
                    "to": str(w_kwargs.get(rel_key)),
                    "type": rel_key,
                    "framework": self.name,
                    "evidence": workflow.get("name"),
                })

        if not edges:
            edges = [{"name": x, "evidence": x} for x in re.findall(r"add_edge\(([^)]+)\)|add_conditional_edges\(([^)]+)\)", content)]
            edges = [{"name": a or b, "evidence": a or b} for a, b in edges if (a or b)]
        if not tools:
            regex_tools = re.findall(r"bind_tools\(([^)]+)\)|tool\(([^)]+)\)", content)
            tools = [{"name": a or b, "evidence": a or b} for a, b in regex_tools if (a or b)]
        if not models:
            models = [{"name": x, "evidence": x} for x in re.findall(r"ChatOpenAI|Bedrock|AzureChatOpenAI", content)]

        return {
            "framework": "langgraph",
            "nodes": nodes,
            "edges": edges,
            "workflows": workflows,
            "planners": planners,
            "tools": tools,
            "llms": models,
            "prompts": prompts,
            "memory": memory,
            "relationships": relationships,
            "capabilities": dedupe_capabilities(capabilities),
            "discovery_method": "ast+regex_fallback",
            "parser_confidence": 0.89,
            "detection_evidence": ["imports:langgraph", "ast:calls"],
        }
