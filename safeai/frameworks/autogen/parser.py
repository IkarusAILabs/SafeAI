"""AutoGen framework adapter.

Detects Microsoft AutoGen usage via AST import analysis and regex fallback.
Extracts agents, tools, models, and capabilities from AutoGen configurations.
"""

import re

from safeai.analysis import package_managers
from safeai.analysis.capabilities import (
    dedupe_capabilities,
    is_file_call,
    make_capability,
)
from safeai.analysis.semantic import (
    build_semantic_document,
    resolve_symbol,
    resolve_symbol_origin,
)
from safeai.analysis.tool_identity import make_tool_identity
from safeai.frameworks import register_parser

# Decorators that register the decorated function as a tool (AutoGen 0.2).
_REGISTERING_DECORATORS = ("register_for_llm", "register_for_execution")


def _agent_name(call):
    """The agent's own name: ``name=`` or the first positional argument.

    AutoGen 0.2 and AgentChat both take the name as the first parameter
    (``AssistantAgent("triage", ...)`` or ``AssistantAgent(name="triage")``).
    Only a string literal counts; a name built at run time returns None and
    the caller falls back to the constructor name, marked unresolved.
    """
    name = (call.get("kwargs") or {}).get("name")
    if not isinstance(name, str):
        args = call.get("args") or []
        name = args[0] if args else None
    if not isinstance(name, str):
        return None
    return name.strip() or None


def _refs(value):
    """Names referenced by a ``tools=[...]`` value or a single reference."""
    items = value if isinstance(value, list) else [value]
    return [item[1] for item in items
            if isinstance(item, tuple) and len(item) == 2 and item[0] == "ref"]


def _tool_functions(doc):
    """Functions this file hands to AutoGen as tools, in order of appearance.

    - ``AssistantAgent(..., tools=[f, g])`` (AgentChat),
    - ``FunctionTool(f, ...)`` (autogen_core),
    - ``register_function(f, ...)`` and functions decorated with
      ``register_for_llm`` / ``register_for_execution`` (AutoGen 0.2).

    Only names are collected; a capability is attributed to one of them
    when the call that confers it is inside that function's body.
    """
    names = []
    for call in doc.calls:
        short = call["name"].rsplit(".", 1)[-1]
        if short in ("AssistantAgent", "ConversableAgent"):
            names += _refs((call.get("kwargs") or {}).get("tools"))
        elif short in ("FunctionTool", "register_function") and call.get("args"):
            names += _refs(call["args"][0])
    for fn, info in doc.functions.items():
        if any(d.rsplit(".", 1)[-1] in _REGISTERING_DECORATORS
               for d in info.get("decorators") or []):
            names.append(fn)
    return list(dict.fromkeys(names))


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
        tool_functions = set(_tool_functions(doc))

        for call in doc.calls:
            # The tool that holds this call's authority, when the call is in
            # the body of a function registered as a tool; otherwise None
            # and the capability stays unattributed.
            owner = call.get("function")
            owned = ({"tool_identity": make_tool_identity("tool", owner, self.name,
                                                          source_path=path),
                      "line": call.get("line")}
                     if owner in tool_functions else {})
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()

            if "assistantagent" in lname or "userproxyagent" in lname:
                name = _agent_name(call)
                agents.append({
                    "name": name or call["name"],
                    "name_resolved": name is not None,
                    "constructor": call["name"],
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
                    **owned,
                ))

            if any(s in lname for s in ["subprocess", "os.system", "popen"]):
                capabilities.append(make_capability(
                    "shell_execution", "Shell", self.name, call["name"],
                    confidence=0.9, risk_weight=1.6,
                    resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
                    **owned,
                ))
                package_manager = package_managers.call_capability(
                    call, self.name,
                    resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
                    tool_identity=owned.get("tool_identity"),
                )
                if package_manager:
                    capabilities.append(package_manager)

            if is_file_call(lname):
                capabilities.append(make_capability(
                    "filesystem_access", "Filesystem", self.name, call["name"],
                    confidence=0.85, risk_weight=1.2,
                    resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
                    **owned,
                ))

        declared = {t["name"] for t in tools}
        for fn in _tool_functions(doc):
            if fn not in declared:
                tools.append({"name": fn, "line": (doc.functions.get(fn) or {}).get("line"),
                              "evidence": "tool_function"})

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
