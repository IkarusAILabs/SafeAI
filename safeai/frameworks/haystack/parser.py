"""Haystack framework adapter.

Detects Haystack (deepset) agent files via ``haystack`` imports,
``Pipeline`` / ``Agent`` class usage. Extracts pipelines, agents,
tools, and model references.
"""


from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.analysis.semantic import build_semantic_document, resolve_symbol
from safeai.frameworks import register_parser


@register_parser
class HaystackParser:
    name = "haystack"
    # Shell, file and HTTP calls in registered tool functions are reported
    # as that tool's authority (safeai.analysis.tool_bodies).
    attributes_tool_bodies = True
    tool_entries_are_names = True  # this parser lists tools as name strings

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        if "haystack" in content.lower():
            return True
        doc = build_semantic_document(path, content, module_name="")
        for imported in list(doc.imports.values()) + list(doc.from_imports.values()):
            if "haystack" in imported:
                return True
        return False

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        doc = build_semantic_document(path, content, module_name=module_name)

        result = {
            "framework": "haystack",
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

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            base = resolved.rsplit(".", 1)[-1] if "." in resolved else resolved

            if base == "Pipeline":
                pipe_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                result["workflows"].append(str(pipe_name or "pipeline"))
                result["detection_evidence"].append(f"Pipeline: {pipe_name or 'unnamed'}")

            if base == "Agent":
                agent_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if agent_name:
                    result["agents"].append(str(agent_name))

            if base in ("Tool", "ComponentTool", "PipelineTool"):
                tool_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if tool_name:
                    result["tools"].append(str(tool_name))

            if base in ("OpenAIGenerator", "OpenAIChatGenerator", "AnthropicGenerator",
                        "HuggingFaceGenerator", "HuggingFaceChatGenerator"):
                model_name = call.get("kwargs", {}).get("model") or (call.get("args") or [None])[0]
                result["models"].append(str(model_name or base))
                caps.append(make_capability(
                    "external_model_api", "External APIs", "haystack",
                    f"{base} generator", confidence=0.8, source="ast",
                ))

            if base in ("Retriever", "DocumentStore", "EmbeddingRetriever"):
                caps.append(make_capability(
                    "rag", "RAG", "haystack",
                    f"{base} call", confidence=0.8, source="ast",
                ))

            if base in ("WebSearch", "SearchTool"):
                caps.append(make_capability(
                    "browser", "Browser", "haystack",
                    f"{base} call", confidence=0.8, source="ast",
                ))

        result["capabilities"] = dedupe_capabilities(caps)
        return result
