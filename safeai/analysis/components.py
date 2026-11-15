"""Component extractor — finds and categorizes reusable AI artifacts.

Scans the project tree for component-level artifacts that are separate
from framework-specific code. Each artifact type has its own detection
heuristics and structured extraction logic. The result is a list of
component dicts that downstream analyzers consume.

Component types discovered:
  - **skills**      — Semantic Kernel skill files, OpenAI skill configs, custom ``*.skill.*``
  - **prompts**     — ``.prompt`` / ``.prompt.*`` files, inline prompt templates in YAML/JSON
  - **tools**       — ``@tool``-decorated Python functions, tool defs in configs
  - **models**      — model constructor calls and config blocks (temperature, safety settings)
  - **workflows**   — workflow template YAML/JSON files
"""

import ast
import json
import re

import yaml

from safeai.analysis.semantic import _literal_value, _name_of, build_semantic_document
from safeai.kya.util import sha256_text

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_SKILL_FILE_RE = re.compile(r"\.skill\.(yaml|yml|json|py)$", re.IGNORECASE)
_SKILL_CONTENT_RE = re.compile(r"skill_type|semantic_kernel.*skill|Skill\(", re.IGNORECASE)

_PROMPT_FILE_RE = re.compile(
    r"\.prompt(\.|$)|\.prompt\.|^(system_)?prompt\.(md|txt)$", re.IGNORECASE
)
_PROMPT_CONTENT_RE = re.compile(r"system_prompt|user_prompt|prompt_template|PromptTemplate|SystemMessage|HumanMessage", re.IGNORECASE)

_WORKFLOW_FILE_RE = re.compile(r"workflow\.(yaml|yml|json)|\.workflow\.(yaml|yml|json)", re.IGNORECASE)
_WORKFLOW_CONTENT_RE = re.compile(r"steps|stages|pipeline|nodes|edges", re.IGNORECASE)

_MODEL_CONFIG_KEYS = {"model", "model_name", "model_id", "temperature", "top_p", "top_k", "max_tokens", "safety_settings", "content_filter", "system_instruction"}
_MODEL_NAME_RE = re.compile(
    r"gpt-|claude-|gemini-|llama-|mistral|deepseek|command-|titan|cohere"
    r"|ChatOpenAI|ChatAnthropic|ChatBedrock|AzureChatOpenAI|ChatGoogle|ChatMistral"
    r"|ChatVertexAI|ChatCohere|ChatHuggingFace|ChatAnyscale|ChatFireworks"
    r"|Gemini|VertexAI|VertexChat"
    r"|OpenAI|Anthropic|Bedrock|AzureOpenAI|GoogleGenerativeAI"
    r"|TextGeneration|Completion|ChatCompletion",
    re.IGNORECASE,
)

# Python decorator names that mark tool definitions.
_TOOL_DECORATOR_NAMES = {"tool", "Tool", "function_tool", "mcp_tool", "kernel_function", "skill_function"}

# Common framework tool-definition call names.
_TOOL_CALL_NAMES = {"Tool", "StructuredTool", "function_tool", "mcp_tool", "ToolDefinition", "tool"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_line_number(content, pattern):
    """Return the 1-based line number where *pattern* first appears."""
    m = re.search(pattern, content)
    if not m:
        return 1
    return content[: m.start()].count("\n") + 1


def _try_parse_yaml(content):
    try:
        return yaml.safe_load(content)
    except Exception:
        return None


def _try_parse_json(content):
    try:
        return json.loads(content)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Individual extractors (one per component type)
# ---------------------------------------------------------------------------

def _extract_skills(path, content):
    """Detect skill files or skill-referencing YAML/JSON configs."""
    comps = []
    fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    if _SKILL_FILE_RE.search(fname):
        kind = "skill_file"
        if fname.endswith((".yaml", ".yml")):
            data = _try_parse_yaml(content)
        elif fname.endswith(".json"):
            data = _try_parse_json(content)
        else:
            data = None
        comps.append({
            "type": "skill",
            "subtype": kind,
            "file": path,
            "data": data,
            "line": 1,
            "source": "filename",
        })
    elif _SKILL_CONTENT_RE.search(content):
        data = None
        if path.endswith((".yaml", ".yml")):
            data = _try_parse_yaml(content)
        elif path.endswith(".json"):
            data = _try_parse_json(content)
        comps.append({
            "type": "skill",
            "subtype": "skill_config",
            "file": path,
            "data": data,
            "line": _find_line_number(content, r"skill_type|semantic_kernel.*skill|Skill\("),
            "source": "content_pattern",
        })
    return comps


def _extract_prompt_files(path, content):
    """Detect standalone prompt files and inline prompt blocks in YAML/JSON."""
    comps = []
    fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    if _PROMPT_FILE_RE.search(fname):
        comps.append({
            "type": "prompt",
            "subtype": "prompt_file",
            "file": path,
            "data": content,
            "line": 1,
            "source": "filename",
        })
    elif _PROMPT_CONTENT_RE.search(content):
        data = None
        if path.endswith((".yaml", ".yml")):
            data = _try_parse_yaml(content)
        elif path.endswith(".json"):
            data = _try_parse_json(content)
        comps.append({
            "type": "prompt",
            "subtype": "prompt_template",
            "file": path,
            "data": data,
            "line": _find_line_number(content, r"system_prompt|user_prompt|prompt_template|PromptTemplate|SystemMessage|HumanMessage"),
            "source": "content_pattern",
        })
    return comps


def _extract_tool_definitions(path, content, semantic_doc=None):
    """Detect ``@tool``-decorated functions and ``Tool()`` constructor calls in Python."""
    if not path.endswith(".py"):
        return []

    if semantic_doc is None:
        module_name = ""
        try:
            tree = ast.parse(content)
            for node in tree.body:
                if isinstance(node, ast.ImportFrom):
                    module_name = node.module or ""
                    break
        except Exception:
            pass
        semantic_doc = build_semantic_document(path, content, module_name=module_name)

    comps = []

    # --- @tool decorators on functions/classes ---
    for fname, fdef in semantic_doc.functions.items():
        decorators = fdef.get("decorators", [])
        for dec in decorators:
            if dec in _TOOL_DECORATOR_NAMES or dec.endswith("_tool"):
                comps.append({
                    "type": "tool",
                    "subtype": "decorated_function",
                    "file": path,
                    "name": fname,
                    "line": fdef["line"],
                    "decorator": dec,
                    "source": "ast",
                })

    # --- Tool() / function_tool() calls ---
    for call in semantic_doc.calls:
        cname = call.get("name", "")
        base = cname.rsplit(".", 1)[-1] if "." in cname else cname
        if base in _TOOL_CALL_NAMES:
            name_kwarg = call.get("kwargs", {}).get("name")
            if name_kwarg is None and call.get("args"):
                name_kwarg = call["args"][0]
            comps.append({
                "type": "tool",
                "subtype": "constructor_call",
                "file": path,
                "name": name_kwarg or base,
                "line": call["line"],
                "call_name": cname,
                "source": "ast",
            })

    return comps


def _extract_model_configs(path, content):
    """Detect model configuration blocks and constructor calls."""
    comps = []

    # Config-file model blocks
    if path.endswith((".yaml", ".yml")):
        data = _try_parse_yaml(content)
    elif path.endswith(".json"):
        data = _try_parse_json(content)
    else:
        data = None

    if isinstance(data, dict):
        model_keys = {k.lower() for k in data}
        if _MODEL_CONFIG_KEYS & model_keys:
            comps.append({
                "type": "model_config",
                "subtype": "config_file",
                "file": path,
                "data": data,
                "provider": _provider_for_model(data.get("model", data.get("model_name", ""))),
                "line": 1,
                "source": "config_keys",
            })

    # Python model constructor calls
    if path.endswith(".py"):
        try:
            tree = ast.parse(content)
        except Exception:
            return comps

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            cname = _name_of(node.func) or ""
            base = cname.rsplit(".", 1)[-1] if "." in cname else cname
            if _MODEL_NAME_RE.search(base):
                kwargs = {}
                for kw in node.keywords:
                    if kw.arg:
                        kwargs[kw.arg] = _literal_value(kw.value)
                comps.append({
                    "type": "model_config",
                    "subtype": "constructor_call",
                    "file": path,
                    "name": base,
                    "line": node.lineno,
                    "call_name": cname,
                    "kwargs": kwargs,
                    "provider": _provider_for_model(base),
                    "source": "ast",
                })

    return comps


def _provider_for_model(value):
    """Infer a provider family for provider-specific static policies."""
    low = str(value or "").lower()
    if "vertex" in low or "gemini" in low or "google" in low:
        return "google"
    if "bedrock" in low or "titan" in low:
        return "bedrock"
    if "azure" in low:
        return "azure"
    if "anthropic" in low or "claude" in low:
        return "anthropic"
    if "openai" in low or "gpt" in low:
        return "openai"
    return "unknown"


def _extract_workflow_templates(path, content):
    """Detect workflow template files."""
    comps = []
    fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    if not (_WORKFLOW_FILE_RE.search(fname)):
        return comps

    if path.endswith((".yaml", ".yml")):
        data = _try_parse_yaml(content)
    elif path.endswith(".json"):
        data = _try_parse_json(content)
    else:
        data = None

    if isinstance(data, dict) and _WORKFLOW_CONTENT_RE.search(content):
        comps.append({
            "type": "workflow",
            "subtype": "template",
            "file": path,
            "data": data,
            "line": 1,
            "source": "filename",
        })
    return comps


# ---------------------------------------------------------------------------
# Content hashing
# ---------------------------------------------------------------------------

def _component_content_hash(content):
    """Return a truncated SHA-256 hash of file content for version tracking.

    The hash is deterministic: same content always produces the same hash.
    Truncated to 16 hex chars (64 bits) for compactness — collision risk is
    acceptable for local change detection, not cryptographic use.
    """
    if not content:
        return None
    return sha256_text(content)[:16]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_EXTRACTORS = [
    _extract_skills,
    _extract_prompt_files,
    _extract_tool_definitions,
    _extract_model_configs,
    _extract_workflow_templates,
]


def extract_components(files, file_cache, semantic_docs=None, diagnostics=None):
    """Scan all files and return a list of component dicts.

    Each dict has at least:
        type, subtype, file, source, content_hash

    Additional keys depend on the component type.
    """
    if semantic_docs is None:
        semantic_docs = {}

    components = []
    for path in files:
        content = file_cache.get(path, "")
        if not content:
            continue
        sem_doc = semantic_docs.get(path)
        chash = _component_content_hash(content)
        for extractor in _EXTRACTORS:
            try:
                if extractor is _extract_tool_definitions:
                    found = extractor(path, content, semantic_doc=sem_doc)
                else:
                    found = extractor(path, content)
                for comp in found:
                    comp["content_hash"] = chash
                components.extend(found)
            except Exception as exc:
                if diagnostics is not None:
                    diagnostics.append({
                        "file": path,
                        "stage": "component_extraction",
                        "kind": "extractor_error",
                        "extractor": extractor.__name__,
                        "error": str(exc),
                    })
                continue
    return components
