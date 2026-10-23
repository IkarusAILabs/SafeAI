"""Tests for v2.4 authority/material-change classification + gate (WS2)."""

import json
import os

from safeai.analysis.capability_diff import (
    CHANGE_CLASSES,
    CHANGE_TYPES,
    authority_for,
    authority_gate_tripped,
    authority_unknown,
    change_class_for,
    change_types_for,
)
from safeai.cmd.cli import main


class TestChangeClass:
    def test_vocabulary_is_stable(self):
        assert CHANGE_CLASSES == (
            "NO_CHANGE",
            "LOW_CHANGE",
            "MATERIAL_CHANGE",
            "HIGH_RISK_CHANGE",
            "UNKNOWN",
        )

    def test_unchanged(self):
        assert change_class_for("unchanged", [], [], []) == "NO_CHANGE"

    def test_reduced_is_low(self):
        assert change_class_for("reduced", [], [], []) == "LOW_CHANGE"
        assert change_class_for("removed", [], [], []) == "LOW_CHANGE"

    def test_new_tool_is_material(self):
        added = [{"name": "http", "inferred": False}]
        assert change_class_for("new", [], [], added) == "MATERIAL_CHANGE"

    def test_critical_escalation_is_high_risk(self):
        escs = [{"id": "ESC_X", "severity": "critical"}]
        assert change_class_for("escalated", escs, [], []) == "HIGH_RISK_CHANGE"
        assert change_class_for("new", escs, [], []) == "HIGH_RISK_CHANGE"

    def test_access_widening_is_material(self):
        changes = [{"capability": "db", "before": "read", "after": "write",
                    "inferred": False}]
        assert change_class_for("escalated", [], changes, []) == "MATERIAL_CHANGE"

    def test_high_escalation_without_structure_is_material(self):
        escs = [{"id": "ESC_Y", "severity": "high"}]
        assert change_class_for("escalated", escs, [], []) == "MATERIAL_CHANGE"

    def test_unknown_status(self):
        assert change_class_for("unknown", [], [], []) == "UNKNOWN"
        assert change_class_for(None, [], [], []) == "UNKNOWN"

    def test_escalated_without_signals_is_low(self):
        assert change_class_for("escalated", [], [], []) == "LOW_CHANGE"


class TestChangeTypes:
    def test_vocabulary_is_stable(self):
        assert "AUTHORITY_ADDED" in CHANGE_TYPES
        assert "UNKNOWN_CHANGE" in CHANGE_TYPES
        # Absent by design: no per-tool signal exists yet.
        assert "INFRASTRUCTURE_AUTHORITY_CHANGED" not in CHANGE_TYPES
        assert "CREDENTIAL_SCOPE_EXPANDED" not in CHANGE_TYPES
        assert "PROMPT_OR_DEFINITION_CHANGED" not in CHANGE_TYPES

    def test_escalation_ids_map(self):
        assert change_types_for("new", [{"id": "ESC_MCP_SERVER_ADDED"}]) == [
            "AUTHORITY_ADDED"]
        assert change_types_for("escalated", [{"id": "ESC_MCP_READ_TO_MUTATE"}]) == [
            "AUTHORITY_ESCALATED"]
        assert change_types_for("new", [{"id": "ESC_NEW_EXTERNAL_DESTINATION"}]) == [
            "AUTHORITY_ADDED", "DESTINATION_ADDED"]
        assert change_types_for("new", [{"id": "ESC_APPROVAL_GATE_REMOVED"}]) == [
            "APPROVAL_REMOVED", "AUTHORITY_ADDED"]
        assert change_types_for("new", [{"id": "ESC_MEMORY_SCOPE_EXPANDED"}]) == [
            "AUTHORITY_ADDED", "DATA_REACH_EXPANDED"]
        assert change_types_for("new", [{"id": "ESC_AUTONOMY_INCREASED"}]) == [
            "AUTHORITY_ADDED", "AUTONOMY_INCREASED"]
        assert change_types_for(
            "new", [{"id": "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT"}]) == [
            "AUTHORITY_ADDED", "DELEGATION_ADDED"]

    def test_structural_fallback(self):
        assert change_types_for("new", []) == ["AUTHORITY_ADDED"]
        assert change_types_for("reduced", []) == ["AUTHORITY_REDUCED"]
        assert change_types_for("removed", []) == ["AUTHORITY_REMOVED"]
        assert change_types_for("unknown", []) == ["UNKNOWN_CHANGE"]
        assert change_types_for("unchanged", []) == []

    def test_unmapped_escalation_contributes_nothing(self):
        assert change_types_for("unchanged", [{"id": "ESC_FUTURE_X"}]) == []

    def test_severity_never_creates_type(self):
        assert change_types_for(
            "unchanged", [{"id": "ESC_FUTURE_X", "severity": "critical"}]) == []

    def test_sorted_and_deduped(self):
        types = change_types_for("new", [
            {"id": "ESC_MCP_SERVER_ADDED"},
            {"id": "ESC_WRITE_TOOL_ADDED"},
        ])
        assert types == ["AUTHORITY_ADDED"]


class TestAuthorityBlock:
    def test_capabilities_carry_provenance(self):
        caps = [
            {"name": "shell", "access_mode": "execute", "inferred": False},
            {"name": "http", "access_mode": "read", "inferred": True},
        ]
        auth = authority_for(caps, [])
        by_name = {c["name"]: c for c in auth["capabilities"]}
        assert by_name["shell"]["provenance_class"] == "detected"
        assert by_name["http"]["provenance_class"] == "inferred"

    def test_dimensions_from_escalations(self):
        escs = [
            {"id": "ESC_APPROVAL_GATE_REMOVED"},
            {"id": "ESC_AUTONOMY_INCREASED"},
            {"id": "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT"},
            {"id": "ESC_NEW_EXTERNAL_DESTINATION"},
        ]
        auth = authority_for([], escs)
        assert auth["approval"] == {"state": "removed", "provenance_class": "detected"}
        assert auth["autonomy"] == {"state": "increased", "provenance_class": "detected"}
        assert auth["delegation"] == {"state": "present", "provenance_class": "detected"}

    def test_unobserved_dimensions_are_unknown(self):
        auth = authority_for([], [])
        assert auth["approval"]["state"] == "unknown"
        assert auth["credential"] == {"state": "unknown", "provenance_class": "unknown"}
        assert auth["identity"] == {"state": "unknown", "provenance_class": "unknown"}
        assert auth["destinations"] == {"values": [], "provenance_class": "unknown"}

    def test_destinations_from_caps(self):
        caps = [{"name": "s3", "access_mode": "write", "inferred": False}]
        auth = authority_for(caps, [])
        assert auth["destinations"]["values"] == ["s3"]
        assert auth["destinations"]["provenance_class"] == "detected"

    def test_unknown_block(self):
        auth = authority_unknown()
        assert auth["capabilities"] == []
        for dim in ("approval", "autonomy", "delegation", "credential", "identity"):
            assert auth[dim]["state"] == "unknown"

    def test_attached_to_entries(self):
        import tempfile
        from pathlib import Path

        from safeai.engine.scan import run_scan

        tmp = Path(tempfile.mkdtemp())
        write = TestFailOnAuthorityChange._write
        write(tmp / "before", ["lookup"])
        write(tmp / "after", ["lookup", "writer"])
        baseline = run_scan(str(tmp / "before"))
        current = run_scan(str(tmp / "after"), baseline_report=baseline)
        added = next(t for t in current["capability_diff"]["tools"]
                     if t["tool_key"] == "mcp_server:writer")
        assert "authority" in added
        assert added["authority"]["identity"]["state"] == "unknown"


class TestAuthorityGateTripped:
    def _tool(self, cls, inferred_only=False):
        return {"tool_key": "t", "change_class": cls, "inferred_only": inferred_only}

    def test_material_trips_material(self):
        assert authority_gate_tripped([self._tool("MATERIAL_CHANGE")], "material") is True

    def test_material_does_not_trip_high_risk(self):
        assert authority_gate_tripped([self._tool("MATERIAL_CHANGE")], "high-risk") is False

    def test_high_risk_trips_both(self):
        tools = [self._tool("HIGH_RISK_CHANGE")]
        assert authority_gate_tripped(tools, "material") is True
        assert authority_gate_tripped(tools, "high-risk") is True

    def test_inferred_only_never_trips(self):
        tools = [self._tool("HIGH_RISK_CHANGE", inferred_only=True)]
        assert authority_gate_tripped(tools, "material") is False
        assert authority_gate_tripped(tools, "high-risk") is False

    def test_unknown_never_trips(self):
        assert authority_gate_tripped([self._tool("UNKNOWN")], "material") is False

    def test_low_and_no_change_never_trip(self):
        tools = [self._tool("LOW_CHANGE"), self._tool("NO_CHANGE")]
        assert authority_gate_tripped(tools, "material") is False

    def test_empty_tools(self):
        assert authority_gate_tripped([], "material") is False


class TestChangeClassCounts:
    def test_counts_and_highest(self):
        from safeai.analysis.capability_diff import compute_capability_diff

        def tool(key, caps):
            return {
                "tool_key": key,
                "tool": {"kind": "tool", "name": key, "framework": None},
                "capabilities": [
                    {"name": c, "access_mode": "read", "evidence": [],
                     "confidence": 1.0, "inferred": False}
                    for c in caps
                ],
                "access_summary": "read",
            }

        current = {"tool_surface": [
            tool("tool:a", ["shell", "http"]),
            tool("tool:b", ["fs"]),
        ]}
        baseline = {"tool_surface": [tool("tool:a", ["shell"]), tool("tool:b", ["fs"])]}
        diff = compute_capability_diff(current, baseline)
        assert diff["counts"]["by_change_class"]["MATERIAL_CHANGE"] >= 1
        assert diff["highest_change_class"] in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")


class TestFailOnAuthorityChange:
    @staticmethod
    def _write(root, servers):
        payload = {"mcpServers": {
            name: {"command": "node", "args": ["server.js"],
                   "tools": [{"name": f"{name}_tool", "description": f"{name} read tool"}]}
            for name in servers
        }}
        root.mkdir(parents=True, exist_ok=True)
        (root / ".mcp.json").write_text(json.dumps(payload), encoding="utf-8")
        (root / "agent.py").write_text(
            "from langgraph.graph import StateGraph\n\n"
            "def build():\n    return StateGraph(dict)\n",
            encoding="utf-8",
        )
        return str(root)

    def test_new_server_is_material_change(self, tmp_path):
        from safeai.engine.scan import run_scan

        before = self._write(tmp_path / "before", ["lookup"])
        after = self._write(tmp_path / "after", ["lookup", "writer"])
        baseline = run_scan(before)
        current = run_scan(after, baseline_report=baseline)
        diff = current["capability_diff"]
        added = next(t for t in diff["tools"] if t["tool_key"] == "mcp_server:writer")
        assert added["status"] == "new"
        assert added["change_class"] in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")
        assert "AUTHORITY_ADDED" in added["change_types"]
        assert diff["highest_change_class"] in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")

    def test_new_server_fails_gate(self, tmp_path):
        before = self._write(tmp_path / "before", ["lookup"])
        after = self._write(tmp_path / "after", ["lookup", "writer"])
        baseline_json = str(tmp_path / "baseline.json")
        main(["scan", before, "--json", baseline_json, "--no-registry",
              "--sarif", str(tmp_path / "b.sarif")])
        plain = main(["scan", after, "--baseline", baseline_json, "--no-registry",
                      "--sarif", str(tmp_path / "p.sarif"),
                      "--fail-on", "critical"])
        gated = main(["scan", after, "--baseline", baseline_json, "--no-registry",
                      "--sarif", str(tmp_path / "g.sarif"),
                      "--fail-on", "critical",
                      "--fail-on-authority-change", "material"])
        assert gated == 1
        assert plain == 0

    def test_identical_scan_passes(self, tmp_path):
        before = self._write(tmp_path / "before", ["lookup"])
        baseline_json = str(tmp_path / "baseline.json")
        main(["scan", before, "--json", baseline_json, "--no-registry",
              "--sarif", str(tmp_path / "b.sarif")])
        rc = main(["scan", before, "--baseline", baseline_json, "--no-registry",
                   "--sarif", str(tmp_path / "m.sarif"),
                   "--fail-on", "critical",
                   "--fail-on-authority-change", "material"])
        assert rc == 0

    def test_requires_baseline(self, kya_project, tmp_path, capsys):
        with __import__("pytest").raises(SystemExit):
            main(["scan", kya_project["root"],
                  "--sarif", os.path.join(str(tmp_path), "r.sarif"),
                  "--no-registry", "--fail-on-authority-change", "material"])
        assert "--fail-on-authority-change requires --baseline" in capsys.readouterr().err


class TestActionWiring:
    @staticmethod
    def _driver():
        import importlib.util
        import os as _os

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = _os.path.join(repo_root, "scripts", "safeai-action.py")
        spec = importlib.util.spec_from_file_location("safeai_action", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_argv_includes_flag(self):
        import sys

        build_scan_argv = self._driver().build_scan_argv
        argv = build_scan_argv(".", "critical", "r.sarif",
                               fail_on_authority_change="material")
        assert "--fail-on-authority-change" in argv
        assert "material" in argv
        assert argv[0] == sys.executable

    def test_argv_omits_flag_by_default(self):
        build_scan_argv = self._driver().build_scan_argv
        argv = build_scan_argv(".", "critical", "r.sarif")
        assert "--fail-on-authority-change" not in argv


class TestDiffDependentGatesAreNeverSilent:
    """A gate that cannot fire must say so (issue #197, check 4)."""

    @staticmethod
    def _project(tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "writer": {"command": "node", "args": ["server.js"],
                       "tools": [{"name": "delete_record",
                                  "description": "delete a record"}]}}}),
            encoding="utf-8")
        (project / "agent.py").write_text(
            "from langgraph.graph import StateGraph\n\n"
            "def build():\n    return StateGraph(dict)\n",
            encoding="utf-8")
        return project

    @staticmethod
    def _legacy_baseline(tmp_path):
        legacy = tmp_path / "legacy.json"
        legacy.write_text(json.dumps({"findings": []}), encoding="utf-8")
        return legacy

    def test_gate_warns_when_baseline_cannot_produce_a_diff(self, tmp_path, capsys):
        project = self._project(tmp_path)
        legacy = self._legacy_baseline(tmp_path)
        rc = main(["scan", str(project), "--baseline", str(legacy), "--no-registry",
                   "--sarif", str(tmp_path / "o.sarif"),
                   "--fail-on-authority-change", "material"])
        # Exit semantics are unchanged: the gate simply cannot fire.
        assert rc == 0
        err = capsys.readouterr().err
        assert "neither 'tool_surface' nor 'normalized_capabilities'" in err
        assert "--fail-on-authority-change cannot fail this run" in err

    def test_no_warning_for_a_diff_capable_baseline(self, tmp_path, capsys):
        project = self._project(tmp_path)
        baseline = tmp_path / "baseline.json"
        main(["scan", str(project), "--json", str(baseline), "--no-registry",
              "--sarif", str(tmp_path / "b.sarif")])
        capsys.readouterr()
        main(["scan", str(project), "--baseline", str(baseline), "--no-registry",
              "--sarif", str(tmp_path / "p.sarif"),
              "--fail-on-authority-change", "material"])
        assert "cannot fail this run" not in capsys.readouterr().err

    def test_unknown_authority_block_is_named(self, tmp_path, capsys):
        project = self._project(tmp_path)
        legacy = self._legacy_baseline(tmp_path)
        rc = main(["scan", str(project), "--baseline", str(legacy), "--no-registry",
                   "--sarif", str(tmp_path / "o.sarif"),
                   "--unknown-authority", "block"])
        assert rc == 0
        assert "--unknown-authority block cannot fail this run" in capsys.readouterr().err

    def test_unknown_authority_review_is_not_named(self, tmp_path, capsys):
        project = self._project(tmp_path)
        legacy = self._legacy_baseline(tmp_path)
        main(["scan", str(project), "--baseline", str(legacy), "--no-registry",
              "--sarif", str(tmp_path / "o.sarif"),
              "--unknown-authority", "review"])
        assert "--unknown-authority" not in capsys.readouterr().err

    def test_all_three_gates_are_named_together(self, tmp_path, capsys):
        project = self._project(tmp_path)
        legacy = self._legacy_baseline(tmp_path)
        main(["scan", str(project), "--baseline", str(legacy), "--no-registry",
              "--sarif", str(tmp_path / "o.sarif"),
              "--fail-on-authority-change", "material",
              "--fail-on-escalation", "high",
              "--unknown-authority", "block"])
        err = capsys.readouterr().err
        assert ("--fail-on-authority-change and --fail-on-escalation and "
                "--unknown-authority block cannot fail this run") in err

    def test_no_warning_when_no_diff_gate_was_requested(self, tmp_path, capsys):
        project = self._project(tmp_path)
        legacy = self._legacy_baseline(tmp_path)
        main(["scan", str(project), "--baseline", str(legacy), "--no-registry",
              "--sarif", str(tmp_path / "o.sarif")])
        assert "cannot fail this run" not in capsys.readouterr().err
