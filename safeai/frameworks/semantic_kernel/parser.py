"""Semantic Kernel framework adapter.

Detects Semantic Kernel via dependency metadata (``semantic-kernel``
in requirements.txt), AST import analysis, and regex fallback.
Extracts kernel invocations, plugins/functions, prompts, memory,
skills, model references, and infers planner and model API capabilities.
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
class SemanticKernelParser:
    name = "semantic_kernel"
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
        if "semantic-kernel" in deps:
            return True
        doc = build_semantic_document(path, content, module_name=module_name)
        for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
            if imported.startswith("semantic_kernel"):
                return True
        return "semantic_kernel" in content

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        import_graph = None
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            import_graph = scan_ctx.get("import_graph")
        doc = build_semantic_document(path, content, module_name=module_name)

        agents = []
        workflows = []
        planners = []
        tools = []
        prompts = []
        memory = []
        skills = []
        models = []
        relationships = []
        capabilities = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()
            if "kernel" in lname and "invoke" in lname:
                workflows.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                planners.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("planner_kernel", "Planner", self.name, call["name"], confidence=0.8, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if "function" in lname or "plugin" in lname:
                tools.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
            if "prompt" in lname:
                prompts.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if "memory" in lname:
                memory.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("memory", "Memory", self.name, call["name"], confidence=0.9, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if "skill" in lname:
                skills.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if any(m in lname for m in ["openai", "azure", "anthropic", "bedrock"]):
                models.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("external_model_api", "External APIs", self.name, call["name"], confidence=0.85, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))

        for workflow in workflows:
            w_kwargs = workflow.get("kwargs", {})
            for rel_key in ["arguments", "memory", "function", "plugin", "tool"]:
                if rel_key not in w_kwargs:
                    continue
                relationships.append({
                    "from": workflow.get("name"),
                    "to": str(w_kwargs.get(rel_key)),
                    "type": rel_key,
                    "framework": self.name,
                    "evidence": workflow.get("name"),
                })

        if not skills:
            skills = [{"name": s, "evidence": s} for s in re.findall(r"skill", content, flags=re.IGNORECASE)]

        return {
            "framework": "semantic_kernel",
            "agents": agents,
            "workflows": workflows,
            "planners": planners,
            "tools": tools,
            "prompts": prompts,
            "memory": memory,
            "skills": skills,
            "models": models,
            "relationships": relationships,
            "capabilities": dedupe_capabilities(capabilities),
            "discovery_method": "ast+metadata+regex_fallback",
            "parser_confidence": 0.86,
            "detection_evidence": ["imports:semantic_kernel", "ast:calls"],
        }
