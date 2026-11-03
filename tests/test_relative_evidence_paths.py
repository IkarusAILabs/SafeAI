"""Manifests and reports carry repository-relative paths, never the scanning machine's."""

import json
import shutil
from pathlib import Path

import pytest

from safeai.cmd.cli import main

BENCH = Path(__file__).resolve().parent / "benchmarks"
FIXTURES = [
    BENCH / "authority" / "mixed" / "full_stack" / "input",
    BENCH / "authority-pending" / "delegation" / "claude_code_subagents" / "input",
]
#: Fields that state the scan root on purpose (local JSON report only).
ALLOWED = {"scanner_metadata.scan_root"}


def _absolute_fields(node, markers, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _absolute_fields(value, markers, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for value in node:
            yield from _absolute_fields(value, markers, f"{path}[]")
    elif isinstance(node, str) and any(marker in node for marker in markers):
        yield path


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    for fixture in FIXTURES:
        shutil.copytree(fixture, root, dirs_exist_ok=True)
    return root


def _scan(repo, out, *extra):
    paths = {"manifest": out / "m.json", "report": out / "r.json"}
    main(["scan", str(repo), "--no-registry", "--manifest", str(paths["manifest"]),
          "--json", str(paths["report"]), "--sarif", str(out / "r.sarif"), *extra])
    return {k: json.loads(v.read_text(encoding="utf-8")) for k, v in paths.items()}


def test_no_absolute_paths_in_manifest_or_report(repo, tmp_path):
    docs = _scan(repo, tmp_path)
    markers = {str(tmp_path), str(tmp_path).replace("\\", "/")}
    assert sorted(_absolute_fields(docs["manifest"], markers)) == []
    assert set(_absolute_fields(docs["report"], markers)) <= ALLOWED


def test_tool_surface_evidence_names_repository_files(repo, tmp_path):
    manifest = _scan(repo, tmp_path)["manifest"]
    paths = {ref["path"] for tool in manifest["tool_surface"]
             for capability in tool["capabilities"] for ref in capability["evidence"]}
    assert ".mcp.json" in paths
    assert all(not Path(p).is_absolute() for p in paths if p)


def test_rescan_against_own_manifest_reports_no_component_change(repo, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    baseline = _scan(repo, first)
    assert baseline["manifest"]["components"], "fixture must declare a component"
    diff = _scan(repo, second, "--baseline", str(first / "m.json"))["report"]["component_diff"]
    assert (diff["added"], diff["removed"], diff["changed"]) == ([], [], [])
