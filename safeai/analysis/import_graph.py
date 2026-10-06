"""Project-wide import dependency graph for Python modules.

Builds a bi-directional mapping between module names and file paths,
tracks import edges, and indexes symbols (functions, classes, and
re-exports) for cross-file resolution. Used by framework parsers
to determine where a symbol originates.
"""

import os


def module_name_from_path(root, path):
    """Convert a file path relative to the project root into a dotted module name.

    ``__init__.py`` files map to their parent package name.
    """
    rel = os.path.relpath(path, root)
    rel = rel.replace("\\", "/")
    rel = rel.removesuffix(".py")
    rel = rel.removesuffix("/__init__")
    return rel.replace("/", ".")


class ImportGraph:
    """Tracks module-to-file mappings, import edges, and symbol definitions.

    Attributes:
        module_to_file: Dotted module name -> absolute file path.
        file_to_module: Absolute file path -> dotted module name.
        edges: File path -> set of imported module names.
        symbol_index: File path -> {symbol name -> kind}, where kind
            is ``"function"``, ``"class"``, or ``{"kind": "reexport", "target": ...}``.
    """

    def __init__(self):
        self.module_to_file = {}
        self.file_to_module = {}
        self.edges = {}
        self.symbol_index = {}

    def add_module(self, module_name, path):
        self.module_to_file[module_name] = path
        self.file_to_module[path] = module_name

    def add_import(self, file_path, imported_module):
        self.edges.setdefault(file_path, set()).add(imported_module)

    def add_symbol(self, file_path, symbol_name, kind):
        self.symbol_index.setdefault(file_path, {})[symbol_name] = kind

    def resolve_module(self, module_name):
        return self.module_to_file.get(module_name)

    def resolve_symbol(self, qualified_name, _visited=None):
        """Map a fully-qualified symbol to its defining module and file.

        Tries progressively shorter module prefixes (e.g. ``a.b.c.Var`` ->
        check module ``a.b.c``, then ``a.b``, then ``a``). Follows re-export
        chains when a symbol is re-exported through ``__init__.py``.
        Returns a dict with keys ``module``, ``file``, and ``symbol``, or ``None``.
        """
        if _visited is None:
            _visited = set()
        if qualified_name in _visited:
            return None
        _visited.add(qualified_name)

        parts = qualified_name.split(".")
        for i in range(len(parts), 0, -1):
            module = ".".join(parts[:i])
            path = self.module_to_file.get(module)
            if not path:
                continue
            symbol = ".".join(parts[i:])
            if symbol and path in self.symbol_index:
                direct = symbol.split(".")[0]
                target = self.symbol_index[path].get(direct)
                if isinstance(target, dict) and target.get("kind") == "reexport":
                    return self.resolve_symbol(target.get("target"), _visited)
            return {
                "module": module,
                "file": path,
                "symbol": symbol,
            }
        return None


def build_import_graph(root, files, semantic_docs):
    """Construct an ImportGraph from the project's file list and semantic documents."""
    graph = ImportGraph()
    for path in files:
        if not path.endswith(".py"):
            continue
        module_name = module_name_from_path(root, path)
        graph.add_module(module_name, path)

    for path, doc in semantic_docs.items():
        if not path.endswith(".py"):
            continue
        for target in doc.imports.values():
            graph.add_import(path, target)
        for target in doc.from_imports.values():
            module = target.rsplit(".", 1)[0] if "." in target else target
            graph.add_import(path, module)
        for fn in doc.functions:
            graph.add_symbol(path, fn, "function")
        for cls in doc.classes:
            graph.add_symbol(path, cls, "class")
        for name, target in doc.from_imports.items():
            graph.add_symbol(path, name, {"kind": "reexport", "target": target})
    return graph
