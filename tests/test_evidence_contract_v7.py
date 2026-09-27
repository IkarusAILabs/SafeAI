"""Tests for v2.4 evidence hardening: provenance class + gateability (WS3)."""

import json
import sqlite3

from safeai.kya import REGISTRY_SCHEMA_VERSION
from safeai.kya.contract import validate_manifest
from safeai.kya.enrich import (
    GATEABILITY_VALUES,
    PROVENANCE_CLASSES,
    gateability_for,
    normalize_findings,
    provenance_class_for,
)


def _finding(**overrides):
    base = {
        "rule_id": "CAP_shell",
        "severity": "high",
        "message": "shell use",
        "file": "agent.py",
        "line": 3,
        "evidence": "subprocess.run",
    }
    base.update(overrides)
    return base


class TestProvenanceClass:
    def test_structured_code_evidence_is_detected(self):
        assert provenance_class_for(_finding(), "capability", False) == "detected"

    def test_config_declaration_is_declared(self):
        finding = _finding(rule_id="MCP_AUTH_MISSING", evidence="auth: none")
        assert provenance_class_for(finding, "mcp", False) == "declared"

    def test_regex_fallback_is_inferred(self):
        finding = _finding(regex_fallback=True)
        assert provenance_class_for(finding, "capability", True) == "inferred"

    def test_missing_evidence_is_unknown(self):
        finding = _finding(evidence="", message="", file=None)
        assert provenance_class_for(finding, "capability", False) == "unknown"
    def test_vocabulary_is_stable(self):
        assert PROVENANCE_CLASSES == ("declared", "detected", "inferred",
                                      "unknown", "repo-iac-observed")


class TestGateability:
    def test_detected_is_deterministic(self):
        assert gateability_for(_finding(), "detected") == "deterministic"

    def test_declared_is_deterministic(self):
        assert gateability_for(_finding(), "declared") == "deterministic"

    def test_inferred_is_review_only(self):
        assert gateability_for(_finding(), "inferred") == "review-only"

    def test_unknown_is_review_only(self):
        assert gateability_for(_finding(), "unknown") == "review-only"

    def test_repo_iac_observed_is_review_only(self):
        assert gateability_for(_finding(), "repo-iac-observed") == "review-only"

    def test_vocabulary_is_stable(self):
        assert GATEABILITY_VALUES == ("deterministic", "review-only")


class TestNormalizeFindings:
    def test_fields_attached(self):
        findings = normalize_findings([_finding()])
        assert findings[0]["provenance_class"] == "detected"
        assert findings[0]["gateability"] == "deterministic"

    def test_heuristic_gets_review_only(self):
        findings = normalize_findings([_finding(regex_fallback=True)])
        assert findings[0]["provenance_class"] == "inferred"
        assert findings[0]["gateability"] == "review-only"

    def test_explicit_values_preserved(self):
        findings = normalize_findings([
            _finding(provenance_class="declared", gateability="deterministic")
        ])
        assert findings[0]["provenance_class"] == "declared"
        assert findings[0]["gateability"] == "deterministic"


class TestManifestCarriesFields:
    def test_finding_entry(self):
        from safeai.kya.manifest import _finding_entry

        entry = _finding_entry(_finding(
            fingerprint="fp1", provenance_class="inferred", gateability="review-only"))
        assert entry["provenance_class"] == "inferred"
        assert entry["gateability"] == "review-only"

    def test_finding_entry_defaults(self):
        from safeai.kya.manifest import _finding_entry

        entry = _finding_entry(_finding(fingerprint="fp1"))
        assert entry["provenance_class"] == "unknown"
        assert entry["gateability"] == "review-only"


class TestContractEnums:
    def _doc(self, **finding_overrides):
        finding = {
            "rule_id": "CAP_shell", "severity": "high",
            "provenance_class": "detected", "gateability": "deterministic",
        }
        finding.update(finding_overrides)
        return {
            "schema_version": "1.2",
            "manifest_type": "safeai.kya",
            "safeai": {"version": "2.4.0"},
            "project": {"project_id": "p"},
            "agents": [],
            "findings": [finding],
            "summary": {"policy_decision": {"outcome": "pass"}},
            "assurance_boundary": {},
            "limitations": ["static only"],
        }

    def test_valid_enums_pass(self):
        errors, _ = validate_manifest(self._doc())
        assert errors == []

    def test_bad_provenance_class_rejected(self):
        errors, _ = validate_manifest(self._doc(provenance_class="maybe"))
        assert any("provenance_class" in e for e in errors)

    def test_bad_gateability_rejected(self):
        errors, _ = validate_manifest(self._doc(gateability="sometimes"))
        assert any("gateability" in e for e in errors)

    def test_absent_fields_still_valid(self):
        doc = self._doc()
        del doc["findings"][0]["provenance_class"]
        del doc["findings"][0]["gateability"]
        errors, _ = validate_manifest(doc)
        assert errors == []


class TestManifestEvidence:
    def _report(self, **overrides):
        report = {
            "files_scanned": 1,
            "counts": {},
            "detected_frameworks": [],
            "findings": [],
            "normalized_capabilities": [],
            "trust_score": {"overall_ai_risk_score": 50, "categories": {}},
            "capability_diff": {
                "tools": [{
                    "tool_key": "tool:x", "status": "new",
                    "change_class": "MATERIAL_CHANGE",
                    "change_types": ["AUTHORITY_ADDED"],
                    "inferred_only": False, "escalations": [],
                }],
                "counts": {"by_change_class": {"MATERIAL_CHANGE": 1}},
            },
            "exception_evaluations": [{
                "exception_id": "E1", "target_type": "finding",
                "target_id": "CAP_shell", "state": "active",
                "risk_owner": "o@example.com", "expires_at": None,
            }],
        }
        report.update(overrides)
        return report

    def _manifest(self, report):
        from safeai.kya.manifest import build_manifest

        return build_manifest(
            report,
            project={"project_id": "p", "source_root": "."},
            scan_meta={"scan_id": "s", "completed_at": "2026-01-01T00:00:00Z"},
            safeai_meta={"version": "2.4.0"},
            agents=[],
        )

    def test_authority_changes_carried(self):
        manifest = self._manifest(self._report())
        assert manifest["authority_changes"] == [{
            "tool_key": "tool:x", "status": "new",
            "change_class": "MATERIAL_CHANGE",
            "change_types": ["AUTHORITY_ADDED"],
            "inferred_only": False,
        }]
        assert manifest["summary"]["authority_change_counts"] == {"MATERIAL_CHANGE": 1}

    def test_exceptions_carried(self):
        manifest = self._manifest(self._report())
        assert manifest["exception_evaluations"] == [{
            "exception_id": "E1", "target_type": "finding",
            "target_id": "CAP_shell", "state": "active",
            "risk_owner": "o@example.com", "expires_at": None,
        }]

    def test_empty_by_default(self):
        manifest = self._manifest(self._report(
            capability_diff={}, exception_evaluations=[]))
        assert manifest["authority_changes"] == []
        assert manifest["exception_evaluations"] == []
        assert manifest["summary"]["authority_change_counts"] == {}

    def test_manifest_validates(self):
        manifest = self._manifest(self._report())
        doc = dict(manifest)
        doc.update({
            "schema_version": "1.2",
            "manifest_type": "safeai.kya",
            "project": {"project_id": "p"},
            "summary": {"policy_decision": {"outcome": "pass"}},
            "assurance_boundary": {},
            "limitations": ["static only"],
        })
        errors, _ = validate_manifest(doc)
        assert errors == []

    def test_bad_change_class_rejected(self):
        from safeai.kya.contract import validate_manifest as validate

        doc = self._manifest(self._report())
        doc["authority_changes"] = [{"tool_key": "t", "change_class": "SPICY"}]
        base = dict(doc)
        base.update({
            "schema_version": "1.2", "manifest_type": "safeai.kya",
            "project": {"project_id": "p"},
            "summary": {"policy_decision": {"outcome": "pass"}},
            "assurance_boundary": {}, "limitations": ["x"],
        })
        errors, _ = validate(base)
        assert any("change_class" in e for e in errors)

    def test_bad_exception_state_rejected(self):
        from safeai.kya.contract import validate_manifest as validate

        doc = self._manifest(self._report(exception_evaluations=[{
            "exception_id": "E1", "state": "vibing",
        }]))
        base = dict(doc)
        base.update({
            "schema_version": "1.2", "manifest_type": "safeai.kya",
            "project": {"project_id": "p"},
            "summary": {"policy_decision": {"outcome": "pass"}},
            "assurance_boundary": {}, "limitations": ["x"],
        })
        errors, _ = validate(base)
        assert any("exception_evaluations" in e for e in errors)


class TestMigrationV7:
    def test_version_is_7(self):
        assert REGISTRY_SCHEMA_VERSION == 7

    def test_migration_adds_columns(self, tmp_path):
        from safeai.kya.registry import _MIGRATIONS
        from safeai.kya.registry.connection import connect, migrate

        db_path = str(tmp_path / "reg.db")
        conn = sqlite3.connect(db_path)
        conn.executescript(_MIGRATIONS[1])
        conn.execute(
            "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (1, ?)",
            ("2024-01-01T00:00:00Z",),
        )
        conn.commit()
        conn.close()

        conn = connect(db_path)
        try:
            assert migrate(conn) == 7
            cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_findings)")}
            assert "provenance_class" in cols
            assert "gateability" in cols
        finally:
            conn.close()

    def test_persist_round_trip(self, tmp_path):
        from safeai.kya.registry.connection import connect, migrate
        from safeai.kya.registry.persist import persist_scan

        db_path = str(tmp_path / "reg.db")
        conn = connect(db_path)
        try:
            migrate(conn)
            manifest = {
                "schema_version": "1.2",
                "project": {"project_id": "p1"},
                "scan": {"scan_id": "s1"},
                "safeai": {"version": "2.4.0"},
                "summary": {"policy_decision": {"outcome": "pass"}},
                "findings": [{
                    "fingerprint": "fp1", "rule_id": "CAP_shell",
                    "severity": "high", "status": "new",
                    "provenance_class": "detected",
                    "gateability": "deterministic",
                    "location": {"path": "a.py", "line_start": 1},
                }],
            }
            persist_scan(conn, manifest)
            row = conn.execute(
                "SELECT provenance_class, gateability FROM scan_findings "
                "WHERE scan_id = 's1'").fetchone()
            assert tuple(row) == ("detected", "deterministic")
        finally:
            conn.close()


class TestDeterminism:
    def test_double_scan_stable_digest(self, tmp_path):
        from safeai.engine.scan import run_scan
        from safeai.kya.manifest import build_manifest, serialize_manifest

        fixture = tmp_path / "proj"
        fixture.mkdir()
        (fixture / "agent.py").write_text(
            "import subprocess\nsubprocess.run(['ls'])\n", encoding="utf-8")

        def _digest():
            report = run_scan(str(fixture))
            manifest = build_manifest(
                report,
                project={"project_id": "p", "source_root": str(fixture)},
                scan_meta={"scan_id": "s", "completed_at": "2026-01-01T00:00:00Z"},
                safeai_meta={"version": "2.4.0"},
                agents=[],
            )
            manifest.pop("generated_at", None)
            return serialize_manifest(manifest)

        assert _digest() == _digest()

    def test_finding_json_serializes(self):
        findings = normalize_findings([_finding()])
        json.dumps(findings[0], sort_keys=True, default=str)
