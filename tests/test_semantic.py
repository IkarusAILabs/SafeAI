from safeai.analysis.import_graph import build_import_graph
from safeai.analysis.semantic import (
    build_semantic_document,
    resolve_symbol,
    resolve_symbol_origin,
)


def test_semantic_resolution_and_alias():
    content = """
import subprocess as sp
from mypkg.tools import run_shell as runner

def call_a():
    return sp.run("ls")

def call_b():
    return runner("pwd")
"""
    doc = build_semantic_document("a.py", content, module_name="app.main")
    assert resolve_symbol(doc, "sp.run") == "subprocess.run"
    assert resolve_symbol(doc, "runner") == "mypkg.tools.run_shell"


def test_resolve_symbol_origin_uses_import_graph(tmp_path):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("from b import do_it\n\ndo_it()\n")
    b.write_text("def do_it():\n    return 1\n")

    doc_a = build_semantic_document(str(a), a.read_text(), module_name="a")
    doc_b = build_semantic_document(str(b), b.read_text(), module_name="b")
    graph = build_import_graph(str(tmp_path), [str(a), str(b)], {str(a): doc_a, str(b): doc_b})

    origin = resolve_symbol_origin(doc_a, "do_it", import_graph=graph)
    assert origin["file"].endswith("b.py")


def test_init_reexport_from_same_named_submodule(tmp_path):
    init = tmp_path / "scraper" / "__init__.py"
    sub = tmp_path / "scraper" / "scraper.py"
    init.parent.mkdir()
    init.write_text("from .scraper import Scraper\n")
    sub.write_text("class Scraper:\n    pass\n")

    doc = build_semantic_document(str(init), init.read_text(), module_name="scraper")
    assert resolve_symbol(doc, "Scraper") == "scraper.scraper.Scraper"


def test_resolve_symbol_handles_cycle_gracefully(tmp_path):
    init = tmp_path / "pkg" / "__init__.py"
    init.parent.mkdir()
    init.write_text("from .core import Core\n")

    doc = build_semantic_document(str(init), init.read_text(), module_name="pkg")
    graph = build_import_graph(
        str(tmp_path),
        [str(init)],
        {str(init): doc},
    )

    origin = resolve_symbol_origin(doc, "Core", import_graph=graph)
    assert origin["file"].endswith("__init__.py")
