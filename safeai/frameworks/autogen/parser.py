"""AutoGen framework adapter.

Detects Microsoft AutoGen usage via AST import analysis and regex fallback.
Extracts agents, tools, models, and capabilities from AutoGen configurations.
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
class AutoGenParser:
    name = "autogen"

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        module_name = ""
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        doc = build_semantic_document(path, content, module_name=module_name)
        for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
            if imported.startswith("autogen"):
                return True
        # Conservative keyword signals requiring actual usage, not a bare
        # substring: an agent class instantiation or a tool-registration
        # decorator/method. This avoids reporting modules that merely mention
        # "autogen" in a comment, docstring, or unrelated identifier.
        if re.search(r"\b(?:AssistantAgent|UserProxyAgent)\s*\(", content):
            return True
        return "register_for_llm" in content or "register_function" in content

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        import_graph = None
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            import_graph = scan_ctx.get("import_graph")
        doc = build_semantic_document(path, content, module_name=module_name)

        agents = []
        tools = []
        models = []
        capabilities = []
        relationships = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()

            if "assistantagent" in lname or "userproxyagent" in lname:
                agents.append({
                    "name": call["name"],
                    "line": call.get("line"),
                    "kwargs": call.get("kwargs", {}),
                    "evidence": call["name"],
                })

            if "register_for_llm" in lname or "register_function" in lname:
                tools.append({
                    "name": call["name"],
                    "line": call.get("line"),
                    "kwargs": call.get("kwargs", {}),
                    "evidence": call["name"],
                })

            if any(m in lname for m in ["openai", "azure", "bedrock", "anthropic"]):
                models.append({
                    "name": call["name"],
                    "line": call.get("line"),
                    "evidence": call["name"],
                })
                capabilities.append(make_capability(
                    "external_model_api", "External APIs", self.name, call["name"],
                    confidence=0.8,
                    resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
                ))

            if any(s in lname for s in ["subprocess", "os.system", "popen"]):
                capabilities.append(make_capability(
                    "shell_execution", "Shell", self.name, call["name"],
                    confidence=0.9, risk_weight=1.6,
                    resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
                ))
                package_manager = package_managers.call_capability(
                    call, self.name,
                    resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
                )
                if package_manager:
                    capabilities.append(package_manager)

            if any(s in lname for s in ["open", "pathlib", "os.remove", "os.write"]):
                capabilities.append(make_capability(
                    "filesystem_access", "Filesystem", self.name, call["name"],
                    confidence=0.85, risk_weight=1.2,
                    resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
                ))

        if not agents:
            agent_patterns = re.findall(r"AssistantAgent\(([^)]*)\)|UserProxyAgent\(([^)]*)\)", content)
            for a, b in agent_patterns:
                name = a or b
                if name:
                    agents.append({"name": name.strip(), "evidence": name.strip()})

        if not tools:
            tool_patterns = re.findall(r"register_for_llm\(([^)]+)\)|register_function\(([^)]+)\)", content)
            tools = [{"name": a or b, "evidence": a or b} for a, b in tool_patterns if (a or b)]

        # Only report AutoGen when we actually found an agent or a registered
        # tool. A module that imports the package but never instantiates an
        # agent should not be advertised as an AutoGen project.
        if not agents and not tools:
            return None

        return {
            "framework": "autogen",
            "agents": agents,
            "tools": tools,
            "llms": models,
            "capabilities": dedupe_capabilities(capabilities),
            "relationships": relationships,
            "discovery_method": "ast+regex_fallback",
            "parser_confidence": 0.85,
            "detection_evidence": ["imports:autogen", "ast:calls"],
        }
