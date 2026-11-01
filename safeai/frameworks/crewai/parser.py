"""CrewAI framework adapter.

Detects CrewAI via AST import analysis and regex fallback. Extracts
agents, tasks, tools, prompts, memory, model references, and
derives capabilities (memory, shell, model API, delegation) from
resolved call expressions.
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
class CrewAIParser:
    name = "crewai"

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        module_name = ""
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        doc = build_semantic_document(path, content, module_name=module_name)
        for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
            if imported.startswith("crewai"):
                return True
        return "crewai" in content.lower()

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        import_graph = None
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            import_graph = scan_ctx.get("import_graph")
        doc = build_semantic_document(path, content, module_name=module_name)

        agents = []
        tasks = []
        workflows = []
        planners = []
        tools = []
        models = []
        prompts = []
        memory = []
        relationships = []
        capabilities = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()
            if lname.endswith("agent"):
                agents.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
            if lname.endswith("task"):
                tasks.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                workflows.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                planners.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if "tool" in lname:
                tools.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
            if "memory" in lname:
                memory.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("memory", "Memory", self.name, call["name"], confidence=0.85, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if any(m in lname for m in ["gpt", "chatopenai", "llm", "anthropic", "azure"]):
                models.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("external_model_api", "External APIs", self.name, call["name"], confidence=0.8, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if any(s in lname for s in ["subprocess", "os.system", "popen"]):
                capabilities.append(make_capability("shell_execution", "Shell", self.name, call["name"], confidence=0.9, risk_weight=1.6, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
                package_manager = package_managers.call_capability(call, self.name, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}")
                if package_manager:
                    capabilities.append(package_manager)

        if not agents or not tasks:
            for line in content.splitlines():
                if "Agent(" in line:
                    agents.append({"name": line.strip(), "evidence": line.strip()})
                if "Task(" in line:
                    item = {"name": line.strip(), "evidence": line.strip()}
                    tasks.append(item)
                    workflows.append(item)
                if "tools=" in line or "tool=" in line:
                    tools.append({"name": line.strip(), "evidence": line.strip()})

        if not prompts:
            prompts = [{"name": p, "evidence": p} for p in re.findall(r"prompt\s*=\s*['\"].+['\"]", content, flags=re.IGNORECASE)]

        for workflow in workflows:
            w_kwargs = workflow.get("kwargs", {})
            for rel_key in ["agent", "agents", "tools", "context", "memory", "expected_output"]:
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
            "framework": "crewai",
            "agents": agents,
            "tasks": tasks,
            "workflows": workflows,
            "planners": planners,
            "tools": tools,
            "models": models,
            "prompts": prompts,
            "memory": memory,
            "relationships": relationships,
            "capabilities": dedupe_capabilities(capabilities),
            "discovery_method": "ast+regex_fallback",
            "parser_confidence": 0.86,
            "detection_evidence": ["imports:crewai", "ast:calls"],
        }
