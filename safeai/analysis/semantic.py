"""AST-based semantic document builder for Python source analysis.

Provides a lightweight semantic representation of Python files by
extracting imports, function/class definitions, variable assignments,
and call expressions from the AST. Used across all framework parsers
for symbol resolution and capability inference.
"""

import ast


class SemanticDocument:
    """Holds the extracted semantic structure for a single Python file.

    Attributes:
        path: Absolute path of the source file.
        module_name: Fully-qualified Python module name derived from the path.
        imports: Map of local name -> fully-qualified module for ``import X``.
        from_imports: Map of local name -> qualified symbol for ``from X import Y``.
        assignments: Map of variable name -> literal or symbolic value.
        functions: Map of function name -> {line, decorators}.
        classes: Map of class name -> {line, bases}.
        calls: List of call expressions with name, line, kwargs, and args.
    """

    def __init__(self, path, module_name):
        self.path = path
        self.module_name = module_name
        self.imports = {}
        self.from_imports = {}
        self.assignments = {}
        self.functions = {}
        self.classes = {}
        self.calls = []


def _name_of(node):
    """Extract a dotted name string from an AST expression node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    return None


def _literal_value(node):
    """Extract a compile-time literal value from an AST expression node.

    Returns the raw value for constants, a sentinel for f-strings,
    a ``(kind, name)`` tuple for references, or ``None`` when the
    value cannot be statically determined.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "<fstring>"
    if isinstance(node, ast.Name):
        return ("ref", node.id)
    if isinstance(node, ast.Attribute):
        return ("ref", _name_of(node))
    if isinstance(node, ast.Call):
        return ("call", _name_of(node.func))
    if isinstance(node, ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            kk = _literal_value(k)
            vv = _literal_value(v)
            if isinstance(kk, str):
                out[kk] = vv
        return out
    if isinstance(node, ast.List):
        return [_literal_value(i) for i in node.elts]
    return None


def _resolve_from_module(module, level, current_module, path=""):
    """Resolve a relative import to an absolute module name.

    ``level`` corresponds to the number of leading dots in a ``from ... import``.
    When ``path`` ends with ``__init__.py`` the level is reduced by one because
    a relative import from a package's ``__init__`` is resolved relative to the
    package itself, not one level deeper.
    """
    if level == 0:
        return module or ""
    parts = current_module.split(".") if current_module else []
    if path.endswith("__init__.py"):
        level = max(0, level - 1)
    keep = max(0, len(parts) - level)
    prefix = ".".join(parts[:keep])
    if module:
        return f"{prefix}.{module}" if prefix else module
    return prefix


def build_semantic_document(path, content, module_name=""):
    """Parse a Python source string and produce a SemanticDocument.

    Walks the AST twice: once for top-level definitions (imports,
    functions, classes, assignments) and once for all call expressions
    so that nested calls are captured regardless of depth.
    """
    doc = SemanticDocument(path=path, module_name=module_name)
    try:
        tree = ast.parse(content)
    except Exception:
        return doc

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                doc.imports[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_from_module(node.module, node.level, module_name, path)
            for alias in node.names:
                local = alias.asname or alias.name
                doc.from_imports[local] = f"{base}.{alias.name}" if base else alias.name
        elif isinstance(node, ast.Assign):
            value = _literal_value(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    doc.assignments[target.id] = value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            doc.assignments[node.target.id] = _literal_value(node.value)
        elif isinstance(node, ast.FunctionDef):
            doc.functions[node.name] = {
                "line": node.lineno,
                "decorators": [_name_of(d) for d in node.decorator_list if _name_of(d)],
            }
        elif isinstance(node, ast.ClassDef):
            doc.classes[node.name] = {
                "line": node.lineno,
                "bases": [_name_of(b) for b in node.bases if _name_of(b)],
            }

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _name_of(node.func)
            if not call_name:
                continue
            kwargs = {}
            for kw in node.keywords:
                if kw.arg:
                    kwargs[kw.arg] = _literal_value(kw.value)
            doc.calls.append({
                "name": call_name,
                "line": node.lineno,
                "kwargs": kwargs,
                "args": [_literal_value(a) for a in node.args],
            })
    return doc


def resolve_symbol(doc, symbol):
    """Resolve a local symbol name to its fully-qualified form using the document's import tables.

    Follows ``from X import Y as Z``, ``import X.Y``, and simple variable-to-variable
    aliasing (via assignment tracking).
    """
    if symbol in doc.from_imports:
        return doc.from_imports[symbol]
    first = symbol.split(".")[0]
    if first in doc.imports:
        suffix = symbol[len(first):]
        return f"{doc.imports[first]}{suffix}"
    if symbol in doc.assignments and isinstance(doc.assignments[symbol], tuple):
        kind, value = doc.assignments[symbol]
        if kind == "ref" and isinstance(value, str):
            return resolve_symbol(doc, value)
    return symbol


def resolve_symbol_origin(doc, symbol, import_graph=None):
    """Resolve a symbol to its defining module and file path.

    Uses the project-level import graph to locate where the symbol
    is originally defined. Falls back to returning the resolved name
    with ``None`` file/module when the graph is unavailable or the
    symbol is not found.
    """
    resolved = resolve_symbol(doc, symbol)
    if not import_graph:
        return {
            "qualified_name": resolved,
            "file": None,
            "module": None,
            "symbol": resolved,
        }

    match = import_graph.resolve_symbol(resolved)
    if not match:
        return {
            "qualified_name": resolved,
            "file": None,
            "module": None,
            "symbol": resolved,
        }
    match["qualified_name"] = resolved
    return match
