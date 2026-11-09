"""LangChain framework adapter.

Detects LangChain via dependency metadata (requirements.txt), AST
import analysis, and regex fallback. Extracts agents, chains,
Runnable sequences, tools, prompts, memory, model references,
external integrations (GitHub, Slack, SQL), and infers capabilities
(multi-agent delegation, planner chains, memory, model API).
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
class LangChainParser:
    name = "langchain"
    # Shell, file and HTTP calls in registered tool functions are reported
    # as that tool's authority (safeai.analysis.tool_bodies).
    attributes_tool_bodies = True

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        module_name = ""
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            deps = scan_ctx.get("dependencies", set())
            if "langchain" in deps and "import" in content:
                return True
        doc = build_semantic_document(path, content, module_name=module_name)
        for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
            if imported.startswith("langchain"):
                return True
        return "langchain" in content.lower()

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
        models = []
        integrations = []
        relationships = []
        capabilities = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()
            if "agentexecutor" in lname or "initialize_agent" in lname or lname.endswith("agent"):
                agents.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                capabilities.append(make_capability("multi_agent_or_delegation", "Delegation", self.name, call["name"], confidence=0.75, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if "chain" in lname or "runnable" in lname:
                workflows.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
                capabilities.append(make_capability("planner_chain", "Planner", self.name, call["name"], confidence=0.75, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
                planners.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if "tool" in lname:
                tools.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {}), "evidence": call["name"]})
            if "prompt" in lname:
                prompts.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
            if "memory" in lname:
                memory.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("memory", "Memory", self.name, call["name"], confidence=0.9, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if any(m in lname for m in ["chatopenai", "openai", "anthropic", "azurechatopenai"]):
                models.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})
                capabilities.append(make_capability("external_model_api", "External APIs", self.name, call["name"], confidence=0.85, resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}"))
            if any(i in lname for i in ["github", "slack", "smtp", "sql", "postgres", "mysql", "requests", "httpx"]):
                integrations.append({"name": call["name"], "line": call.get("line"), "evidence": call["name"]})

        for workflow in workflows:
            w_kwargs = workflow.get("kwargs", {})
            for rel_key in ["tools", "tool", "memory", "planner", "llm", "model"]:
                if rel_key not in w_kwargs:
                    continue
                relationships.append({
                    "from": workflow.get("name"),
                    "to": str(w_kwargs.get(rel_key)),
                    "type": rel_key,
                    "framework": self.name,
                    "evidence": workflow.get("name"),
                })

        if not tools:
            tools = [{"name": t, "evidence": t} for t in re.findall(r"\bTool\(|\btool\(", content)]
        if not prompts:
            prompts = [{"name": p, "evidence": p} for p in re.findall(r"PromptTemplate|ChatPromptTemplate", content)]

        return {
            "framework": "langchain",
            "agents": agents,
            "workflows": workflows,
            "planners": planners,
            "tools": tools,
            "prompts": prompts,
            "memory": memory,
            "models": models,
            "external_services": integrations,
            "relationships": relationships,
            "capabilities": dedupe_capabilities(capabilities),
            "discovery_method": "ast+metadata+regex_fallback",
            "parser_confidence": 0.88,
            "detection_evidence": ["imports:langchain", "ast:calls"],
        }
