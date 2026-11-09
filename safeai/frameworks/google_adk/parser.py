"""Google ADK (Agent Development Kit) framework adapter.

Detects Google ADK agent files via ``google-adk`` imports, ``Agent``
class usage, and ADK-specific patterns. Extracts agents, tools,
workflows, and model references.
"""

import re

from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.analysis.semantic import build_semantic_document, resolve_symbol
from safeai.frameworks import register_parser


@register_parser
class GoogleADKParser:
    name = "google_adk"
    # Shell, file and HTTP calls in registered tool functions are reported
    # as that tool's authority (safeai.analysis.tool_bodies).
    attributes_tool_bodies = True
    tool_entries_are_names = True  # this parser lists tools as name strings

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        if "google-adk" in content.lower() or "google_adk" in content.lower():
            return True
        doc = build_semantic_document(path, content, module_name="")
        for imported in list(doc.imports.values()) + list(doc.from_imports.values()):
            if "google" in imported and ("adk" in imported or "agent" in imported):
                return True
        return bool(re.search(r"from\s+google.*import.*Agent|import\s+google.*adk", content, re.IGNORECASE))

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        doc = build_semantic_document(path, content, module_name=module_name)

        result = {
            "framework": "google_adk",
            "agents": [],
            "tools": [],
            "workflows": [],
            "models": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "ast",
            "parser_confidence": 0.82,
            "detection_evidence": [],
        }

        caps = []

        # Agent definitions
        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            base = resolved.rsplit(".", 1)[-1] if "." in resolved else resolved

            if base == "Agent":
                agent_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if agent_name:
                    result["agents"].append(str(agent_name))
                    result["detection_evidence"].append(f"Agent: {agent_name}")

            if base in ("LlmAgent", "SequentialAgent", "ParallelAgent", "LoopAgent"):
                agent_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if agent_name:
                    result["agents"].append(str(agent_name))
                    result["workflows"].append({"type": base, "name": str(agent_name)})

            if base in ("FunctionTool", "Tool", "GoogleSearchTool", "VertexAISearchTool"):
                tool_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if tool_name:
                    result["tools"].append(str(tool_name))
                caps.append(make_capability(
                    "external_apis", "External APIs", "google_adk",
                    f"{base} call", confidence=0.8, source="ast",
                ))

            if base in ("Gemini", "ChatVertexAI", "VertexAI"):
                model_name = call.get("kwargs", {}).get("model") or (call.get("args") or [None])[0]
                result["models"].append(str(model_name or base))
                caps.append(make_capability(
                    "external_model_api", "External APIs", "google_adk",
                    f"{base} model call", confidence=0.8, source="ast",
                ))

        result["capabilities"] = dedupe_capabilities(caps)
        return result
