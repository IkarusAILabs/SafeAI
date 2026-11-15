"""A scan says whether it analysed everything it collected (G-2).

Before this, a file that could not be read was dropped with a debug log,
a failing analyser plugin with a warning log, and a scan that read
nothing exited 0 with no findings. None of that was in the report, so
"no findings" and "not analysed" looked the same.
"""

import json

import pytest

from safeai.cmd.cli import main
from safeai.kya.assurance import (
    COMPLETE,
    INCOMPLETE,
    NOTHING_ANALYSED,
    build_analysis_completeness,
)


def _scan(project, tmp_path, *extra):
    """(exit code, JSON report, SARIF) of a scan."""
    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "out.sarif"
    argv = ["scan", str(project), "--no-registry",
            "--json", str(report_path), "--sarif", str(sarif_path), *extra]
    try:
        rc = main(argv)
    except SystemExit as exc:
        rc = exc.code
    report = json.loads(report_path.read_text(encoding="utf-8"))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    return rc, report, sarif


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "notes.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def _add_unreadable(root):
    # Not valid UTF-8, so the source loader cannot read it.
    (root / "broken.py").write_bytes(b"VALUE = '\xff\xfe\xfa'\n")


def _break_parser(monkeypatch):
    from safeai.frameworks.langgraph.parser import LangGraphParser

    def boom(self, path, content, scan_ctx=None):
        raise RuntimeError("parser failed")

    monkeypatch.setattr(LangGraphParser, "detect", boom)


# --- the record ---------------------------------------------------------------

def test_complete_scan_is_recorded_as_complete(project, tmp_path):
    rc, report, sarif = _scan(project, tmp_path)
    assert rc == 0
    expected = {"status": COMPLETE, "files_collected": 1, "files_read": 1, "failures": []}
    assert report["analysis_completeness"] == expected
    assert report["assurance_boundary"]["analysis_completeness"] == expected
    assert sarif["runs"][0]["properties"]["analysisCompleteness"] == expected


def test_unreadable_file_is_recorded(project, tmp_path):
    _add_unreadable(project)
    rc, report, sarif = _scan(project, tmp_path)
    completeness = report["analysis_completeness"]
    assert completeness["status"] == INCOMPLETE
    assert completeness["files_collected"] == 2
    assert completeness["files_read"] == 1
    assert completeness["failures"] == [
        {"file": "broken.py", "stage": "source_read", "component": ""}
    ]
    assert sarif["runs"][0]["properties"]["analysisCompleteness"]["status"] == INCOMPLETE
    notes = report["assurance_boundary"]["coverage_notes"]
    assert "1 file could not be read and was not analysed: broken.py" in notes
    # Without the flag the exit code is unchanged.
    assert rc == 0


def test_parser_failure_is_recorded(project, tmp_path, monkeypatch):
    _break_parser(monkeypatch)
    rc, report, _ = _scan(project, tmp_path)
    completeness = report["analysis_completeness"]
    assert completeness["status"] == INCOMPLETE
    assert {"file": "notes.py", "stage": "framework_parsing"}.items() <= \
        completeness["failures"][0].items()
    assert rc == 0


def test_empty_scan_root_is_nothing_analysed(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    rc, report, _ = _scan(root, tmp_path)
    assert report["analysis_completeness"]["status"] == NOTHING_ANALYSED
    assert any("nothing was analysed" in note
               for note in report["assurance_boundary"]["coverage_notes"])
    assert rc == 0


def test_only_unreadable_files_is_nothing_analysed(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    _add_unreadable(root)
    _, report, _ = _scan(root, tmp_path)
    assert report["analysis_completeness"]["status"] == NOTHING_ANALYSED


def test_record_carries_no_error_text():
    # Error text can hold host paths; the record must be the same on any
    # machine. The text stays in ``diagnostics``.
    report = {
        "files_scanned": 2,
        "diagnostics": [{"file": "a.py", "stage": "framework_parsing", "kind": "parse_error",
                         "parser": "P", "error": "C:\\Users\\someone\\a.py: boom"}],
    }
    completeness = build_analysis_completeness(report)
    assert completeness["failures"] == [
        {"file": "a.py", "stage": "framework_parsing", "component": "P"}
    ]
    assert "someone" not in json.dumps(completeness)


def test_failing_analyser_plugin_is_incomplete():
    report = {
        "files_scanned": 1,
        "diagnostics": [{"file": None, "stage": "analysis", "kind": "analyzer_error",
                         "analyzer": "third_party", "error": "ValueError: x"}],
    }
    completeness = build_analysis_completeness(report)
    assert completeness["status"] == INCOMPLETE
    assert completeness["failures"] == [
        {"file": "", "stage": "analysis", "component": "third_party"}
    ]


def test_unparseable_configuration_finding_is_incomplete():
    report = {
        "files_scanned": 1,
        "findings": [{"rule_id": "CC_SETTINGS_UNPARSEABLE", "file": ".claude/settings.json"}],
    }
    assert build_analysis_completeness(report)["status"] == INCOMPLETE


# --- the gate -----------------------------------------------------------------

def test_strict_analysis_passes_a_complete_scan(project, tmp_path):
    rc, _, _ = _scan(project, tmp_path, "--strict-analysis")
    assert rc == 0


def test_strict_analysis_refuses_an_unreadable_file(project, tmp_path, capsys):
    _add_unreadable(project)
    rc, _, _ = _scan(project, tmp_path, "--strict-analysis")
    assert rc == 2
    err = capsys.readouterr().err
    assert "--strict-analysis: analysis is incomplete" in err
    assert "1 of 2 collected files read" in err
    assert "broken.py (source_read)" in err


def test_strict_analysis_refuses_a_parser_failure(project, tmp_path, monkeypatch):
    _break_parser(monkeypatch)
    rc, _, _ = _scan(project, tmp_path, "--strict-analysis")
    assert rc == 2


def test_strict_analysis_refuses_an_empty_scan_root(tmp_path, capsys):
    root = tmp_path / "empty"
    root.mkdir()
    rc, _, _ = _scan(root, tmp_path, "--strict-analysis")
    assert rc == 2
    assert "analysis is nothing_analysed" in capsys.readouterr().err


def test_strict_analysis_takes_precedence_over_findings(tmp_path):
    # Findings at the threshold (exit 1) and an incomplete analysis: 2.
    root = tmp_path / "proj"
    root.mkdir()
    (root / "agent.py").write_text(
        "import subprocess\n"
        "from langgraph.graph import StateGraph\n"
        "def run(cmd):\n"
        "    graph = StateGraph(dict)\n"
        "    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    rc, _, _ = _scan(root, tmp_path)
    assert rc == 1
    _add_unreadable(root)
    rc, _, _ = _scan(root, tmp_path, "--strict-analysis")
    assert rc == 2
