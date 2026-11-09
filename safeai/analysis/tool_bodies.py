"""Authority held in the bodies of Python functions registered as tools.

A framework parser knows *that* a file registers tools; this module finds
*which functions* are those tools and reports the shell, filesystem,
HTTP and package-manager calls in their bodies as capabilities of that
tool (``tool_identity``), each with its line.

Registration forms recognised, in a file a framework parser has already
detected (the forms are framework-neutral, so a parser only opts in):

- a decorator whose last name is one of :data:`TOOL_DECORATORS`
  (``@tool``, ``@tool("name")``, ``@function_tool``, ``@kernel_function``,
  ``@ai_function``, AutoGen's ``register_for_llm``);
- a tool constructor (:data:`TOOL_CONSTRUCTORS`) given the function as
  ``func=``, ``fn=``, ``function=``, ``coroutine=`` or its first positional
  argument; ``ToolNode([f, g])``;
- a module-level function listed in any call's ``tools=[...]``;
- a class whose base is ``BaseTool`` (every method is the tool's).

The tool is named by a literal ``name=`` (or a decorator's first string
argument) when there is one, otherwise by the function or class name.

Only direct calls in the tool's own body count. A helper the tool calls
is not followed, so its authority stays where the parser put it
(usually unattributed). Nothing is executed or imported.
"""

import ast

from safeai.analysis import package_managers
from safeai.analysis.capabilities import (
    dedupe_capabilities,
    is_file_call,
    make_capability,
)
from safeai.analysis.semantic import build_semantic_document, resolve_symbol
from safeai.analysis.tool_identity import make_tool_identity

TOOL_DECORATORS = frozenset({"tool", "function_tool", "kernel_function", "ai_function",
                             "register_for_llm", "register_for_execution"})
TOOL_CONSTRUCTORS = frozenset({"Tool", "StructuredTool", "FunctionTool", "from_function",
                               "from_defaults", "ToolNode"})
TOOL_BASES = frozenset({"BaseTool"})
_FUNCTION_KWARGS = ("func", "fn", "function", "coroutine")
_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)

_SHELL = ("subprocess", "os.system", "os.popen", "popen", "os.exec", "pty.spawn")
_HTTP = ("requests.", "httpx.", "urllib.request.urlopen", "urlopen", "aiohttp.")


_MUTATE_FILE = ("os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", ".unlink", ".rmdir")
_WRITE_FILE = (".write_text", ".write_bytes", ".mkdir", ".touch", "os.write", "shutil.copy",
               "shutil.move", ".rename")
_HTTP_MODES = {"get": "read", "head": "read", "options": "read", "post": "write", "put": "write",
               "patch": "write", "delete": "mutate"}


def _file_mode(name, call):
    """``mutate``, ``write`` or ``read`` for a file call, from its name and open mode."""
    if any(s in name for s in _MUTATE_FILE):
        return "mutate"
    if any(s in name for s in _WRITE_FILE):
        return "write"
    if _last(name) == "open":
        args = call.get("args") or []
        mode = (call.get("kwargs") or {}).get("mode", args[1] if len(args) > 1 else "r")
        if isinstance(mode, str) and any(ch in mode for ch in "wax+"):
            return "write"
    return "read"


def _http_mode(name):
    """The access mode an HTTP call's method implies, or ``None`` when it names none."""
    if name.endswith("urlopen"):
        return "read"
    return _HTTP_MODES.get(_last(name))


def _last(name):
    return str(name or "").rsplit(".", 1)[-1]


def _call_name(node):
    func = node.func if isinstance(node, ast.Call) else node
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _literal_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _kwarg(call, key):
    return next((kw.value for kw in call.keywords if kw.arg == key), None)


def _refs(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.List, ast.Tuple)):
        return [e.id for e in node.elts if isinstance(e, ast.Name)]
    return []


def tool_units(content):
    """``{unit: tool_name}``: functions and classes this source registers as tools.

    A unit is a module-level function name, or a class name whose every
    method belongs to the tool. Unparseable source has none.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return {}
    functions = {n.name for n in tree.body if isinstance(n, _FUNCTION_NODES)}
    units = {}

    def add(unit, name=None):
        if unit in functions or unit in classes:
            units.setdefault(unit, name or unit)

    classes = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and any(_last(_call_name(b)) in TOOL_BASES
                                                  for b in node.bases):
            classes.add(node.name)
            declared = next((_literal_str(s.value) for s in node.body
                             if isinstance(s, (ast.Assign, ast.AnnAssign)) and s.value is not None
                             and any(isinstance(t, ast.Name) and t.id == "name"
                                     for t in (s.targets if isinstance(s, ast.Assign)
                                               else [s.target]))), None)
            add(node.name, declared)

    for node in tree.body:
        if not isinstance(node, _FUNCTION_NODES):
            continue
        for dec in node.decorator_list:
            if _last(_call_name(dec)) not in TOOL_DECORATORS:
                continue
            name = None
            if isinstance(dec, ast.Call):
                name = _literal_str(_kwarg(dec, "name")) or (
                    _literal_str(dec.args[0]) if dec.args else None)
            add(node.name, name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        short = _last(_call_name(node))
        if short == "ToolNode" and node.args:
            for ref in _refs(node.args[0]):
                add(ref)
        elif short in TOOL_CONSTRUCTORS:
            target = next((_kwarg(node, k) for k in _FUNCTION_KWARGS
                           if _kwarg(node, k) is not None), None)
            if target is None and node.args:
                target = node.args[0]
            for ref in _refs(target) if isinstance(target, ast.Name) else []:
                add(ref, _literal_str(_kwarg(node, "name")))
        tools = _kwarg(node, "tools")
        if tools is not None:
            for ref in _refs(tools):
                if ref in functions:
                    add(ref)
    return units


def owning_tool(call, units):
    """The tool name owning a semantic-document call, or ``None``."""
    owner = call.get("function")
    if not owner:
        return None
    if owner in units:
        return units[owner]
    cls = owner.split(".", 1)[0]
    return units.get(cls) if "." in owner else None


def tool_body_capabilities(doc, units, framework, path):
    """Capabilities of the shell, file and HTTP calls in tool bodies."""
    caps = []
    for call in doc.calls:
        tool = owning_tool(call, units)
        if tool is None:
            continue
        name = (resolve_symbol(doc, call["name"]) or call["name"]).lower()
        identity = make_tool_identity("tool", tool, framework, source_path=path)
        common = {"tool_identity": identity, "line": call.get("line")}
        if any(s in name for s in _SHELL):
            caps.append(make_capability("shell_execution", "Shell", framework, call["name"],
                                        confidence=0.9, risk_weight=1.6, **common))
            pm = package_managers.call_capability(call, framework, tool_identity=identity)
            if pm:
                caps.append(pm)
        elif is_file_call(name) or any(s in name for s in _MUTATE_FILE + _WRITE_FILE):
            caps.append(make_capability("filesystem_access", "Filesystem", framework,
                                        call["name"], confidence=0.85, risk_weight=1.2,
                                        access_mode=_file_mode(name, call), **common))
        elif any(s in name for s in _HTTP):
            caps.append(make_capability("external_apis", "External APIs", framework,
                                        call["name"], confidence=0.85,
                                        access_mode=_http_mode(name), **common))
    return caps


def tool_records(units, doc):
    """Tool entries for a parser's ``tools`` list, one per registered unit."""
    return [{"name": name, "line": (doc.functions.get(unit) or doc.classes.get(unit) or {}).get("line"),
             "evidence": "tool_function"} for unit, name in units.items()]


#: Capabilities this module reports for tool bodies; a parser's own
#: unattributed copy of one is dropped when every call behind it is in a
#: tool body (it is now reported, attributed, from here).
BODY_CAPABILITIES = frozenset({"shell_execution", "filesystem_access", "package_manager",
                               "external_apis"})


def attach_tool_bodies(parsed, path, content, framework, as_names=False):
    """Add tool-body capabilities and tool entries to one parser result, in place."""
    units = tool_units(content)
    if not units:
        return parsed
    doc = build_semantic_document(path, content)
    unowned = {c["name"] for c in doc.calls if owning_tool(c, units) is None}
    kept = [c for c in parsed.get("capabilities") or []
            if c.get("tool_identity") or c.get("name") not in BODY_CAPABILITIES
            or c.get("evidence") in unowned]
    parsed["capabilities"] = dedupe_capabilities(
        kept + tool_body_capabilities(doc, units, framework, path))
    tools = parsed.setdefault("tools", [])
    as_strings = as_names or any(isinstance(t, str) for t in tools)
    known = {t if isinstance(t, str) else t.get("name") for t in tools if t}
    for record in tool_records(units, doc):
        if record["name"] not in known:
            tools.append(record["name"] if as_strings else record)
    return parsed
