"""Tests for Manifest Contract v1 (schemas/safeai-manifest/v1.0.0.json).

Proves: generated manifests validate; minimal + full manifests validate;
invalid manifests fail with field-level diagnostics; old manifests still
validate; unknown fields are ignored; serialization is byte-identical.
"""

import copy
import json
import os

from safeai.cmd.cli import main
from safeai.cmd.manifest_cli import run_manifest_command
from safeai.kya import MANIFEST_SCHEMA_VERSION
from safeai.kya.contract import (
    CONTRACT_NAME,
    CONTRACT_VERSION,
    CORRELATION_VERDICTS,
    validate_manifest,
)
from safeai.kya.manifest import serialize_manifest


class _Args:
    def __init__(self, manifest_command, file):
        self.manifest_command = manifest_command
        self.file = file


def _scan_manifest(project_root, tmp_path):
    manifest_path = os.path.join(str(tmp_path), "safeai-manifest.json")
    rc = main(["scan", project_root, "--manifest", manifest_path,
               "--sarif", os.path.join(str(tmp_path), "r.sarif"),
               "--no-registry"])
    assert rc in (0, 1)
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh), manifest_path


def test_generated_manifest_validates(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    errors, _ = validate_manifest(manifest)
    assert errors == []
    assert manifest["contract"]["name"] == CONTRACT_NAME
    assert manifest["contract"]["version"] == CONTRACT_VERSION


def test_minimal_manifest_validates(tmp_path):
    minimal = {
        "schema_version": "1.2",
        "manifest_type": "safeai.kya",
        "safeai": {"version": "2.2.0"},
        "project": {"project_id": "local-demo"},
        "agents": [],
        "findings": [],
        "summary": {"policy_decision": {"outcome": "pass"}},
        "assurance_boundary": {},
        "limitations": ["static analysis only"],
    }
    errors, _ = validate_manifest(minimal)
    assert errors == []


def test_representative_manifest_validates(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    assert manifest["agents"], "fixture should yield agents"
    assert manifest["findings"], "fixture should yield findings"
    errors, _ = validate_manifest(manifest)
    assert errors == []


def test_invalid_manifest_actionable_diagnostics():
    bad = {
        "schema_version": "9.9",
        "manifest_type": "something.else",
        "safeai": {},
        "project": {"project_id": ""},
        "agents": [{"name": "no-id"}],
        "findings": [{"rule_id": "", "severity": "extreme"}],
        "summary": {"policy_decision": {"outcome": "maybe"}},
        "limitations": [],
    }
    errors, _ = validate_manifest(bad)
    text = "\n".join(errors)
    assert "$.schema_version" in text
    assert "$.manifest_type" in text
    assert "$.safeai.version" in text
    assert "$.project.project_id" in text
    assert "$.agents[0].agent_id" in text
    assert "$.findings[0].severity" in text
    assert "$.summary.policy_decision.outcome" in text
    assert "$.assurance_boundary" in text
    assert "$.limitations" in text


def test_old_manifest_without_contract_still_validates(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    old = copy.deepcopy(manifest)
    old.pop("contract", None)
    old.pop("integrity", None)
    old["schema_version"] = "1.0"
    errors, warnings = validate_manifest(old)
    assert errors == []
    assert any("1.0" in w for w in warnings)


def test_unknown_fields_ignored(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    manifest["future_section"] = {"anything": [1, 2, 3]}
    manifest["findings"][0]["future_key"] = "x"
    errors, _ = validate_manifest(manifest)
    assert errors == []


def test_serialization_byte_identical(kya_project, tmp_path):
    m1, _ = _scan_manifest(kya_project["root"], tmp_path)
    m2, _ = _scan_manifest(kya_project["root"], tmp_path)
    for volatile in ("generated_at",):
        m1.pop(volatile, None)
        m2.pop(volatile, None)
    for key in ("scan_id", "started_at", "completed_at"):
        m1["scan"].pop(key, None)
        m2["scan"].pop(key, None)
    assert serialize_manifest(m1) == serialize_manifest(m2)


def test_schema_file_exists_and_matches_contract():
    path = os.path.join("schemas", "safeai-manifest", "v1.0.0.json")
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    assert schema["properties"]["contract"]["properties"]["name"]["const"] == CONTRACT_NAME
    assert schema["properties"]["schema_version"]["enum"] == ["1.0", "1.1", "1.2"]
    required = {"schema_version", "manifest_type", "safeai", "project",
                "agents", "findings", "summary", "assurance_boundary",
                "limitations"}
    assert required.issubset(set(schema["required"]))


def test_cli_validate_command(kya_project, tmp_path, capsys):
    _, path = _scan_manifest(kya_project["root"], tmp_path)
    rc = run_manifest_command(_Args("validate", path))
    assert rc == 0
    assert "valid:" in capsys.readouterr().out


def test_cli_validate_rejects_bad_file(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "1.2"}), encoding="utf-8")
    rc = run_manifest_command(_Args("validate", str(bad)))
    assert rc == 1
    out = capsys.readouterr().out
    assert "invalid:" in out
    assert "$.project" in out


def test_legacy_schema_version_constant_unchanged():
    assert MANIFEST_SCHEMA_VERSION == "1.2"


def test_schema_provenance_enum_includes_iac():
    path = os.path.join("schemas", "safeai-manifest", "v1.0.0.json")
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    finding_props = schema["properties"]["findings"]["items"]["properties"]
    assert "repo-iac-observed" in finding_props["provenance_class"]["enum"]
    assert "iac_correlations" in schema["properties"]
    verdict_enum = (schema["properties"]["iac_correlations"]["properties"]
                    ["verdicts"]["items"]["properties"]["verdict"]["enum"])
    assert set(verdict_enum) == set(CORRELATION_VERDICTS)


def _minimal_manifest():
    return {
        "schema_version": "1.2",
        "manifest_type": "safeai.kya",
        "contract": {"name": CONTRACT_NAME, "version": CONTRACT_VERSION},
        "safeai": {"version": "2.5.0"},
        "project": {"project_id": "p"},
        "agents": [],
        "findings": [{
            "rule_id": "IAC_EXCESS_AUTHORITY",
            "severity": "medium",
            "provenance_class": "repo-iac-observed",
            "gateability": "review-only",
        }],
        "summary": {"policy_decision": {"outcome": "warn"}},
        "assurance_boundary": {},
        "limitations": ["static analysis only"],
        "iac_correlations": {
            "schema_version": 2,
            "lane": "B",
            "identities": [{"kind": "aws_iam_role", "name": "agent-role"}],
            "agent_identity_links": [{
                "agent": "<repo>",
                "identity": {"kind": "aws_iam_role",
                             "name": "agent-role"},
                "link_type": "explicit-config-reference",
            }],
            "grants": [{
                "identity": {"kind": "aws_iam_role", "name": "agent-role"},
                "actions": {"values": ["s3:*"], "resolution": "resolved"},
                "resources": {"values": ["*"], "resolution": "resolved"},
                "source": "terraform", "source_file": "main.tf", "line": 10,
            }],
            "grant_bindings": [{
                "identity": {"kind": "aws_iam_role", "name": "agent-role"},
                "binding_kind": "attachment", "binding_name": "a",
                "role": "policy:wide",
            }],
            "verdicts": [{
                "agent_ref": "<repo>",
                "identity_ref": {"kind": "aws_iam_role",
                                 "name": "agent-role"},
                "domain": "aws:s3",
                "verdict": "EXCESS_AUTHORITY",
                "declared_evidence_refs": ["tool:x"],
                "grant_evidence_refs": ["main.tf:10"],
                "link_evidence_refs": ["config.yaml:3"],
                "resolution": "resolved",
            }],
        },
    }


def test_iac_block_and_provenance_validate():
    errors, _ = validate_manifest(_minimal_manifest())
    assert errors == []


def test_iac_bad_verdict_rejected():
    bad = copy.deepcopy(_minimal_manifest())
    bad["iac_correlations"]["verdicts"][0]["verdict"] = "MAYBE"
    errors, _ = validate_manifest(bad)
    assert any("verdict" in e for e in errors)


def test_iac_verdict_without_evidence_rejected():
    bad = copy.deepcopy(_minimal_manifest())
    bad["iac_correlations"]["verdicts"][0]["declared_evidence_refs"] = []
    bad["iac_correlations"]["verdicts"][0]["grant_evidence_refs"] = []
    errors, _ = validate_manifest(bad)
    assert any("evidence" in e for e in errors)


def test_iac_lane_must_be_b():
    bad = copy.deepcopy(_minimal_manifest())
    bad["iac_correlations"]["lane"] = "A"
    errors, _ = validate_manifest(bad)
    assert any("lane" in e for e in errors)


def test_scan_with_terraform_emits_valid_iac_manifest(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "main.tf").write_text(
        'resource "aws_iam_role" "agent_role" {\n'
        '  name = "agent-role"\n'
        '}\n'
        'resource "aws_iam_policy" "p" {\n'
        '  name = "p"\n'
        '  statement {\n'
        '    actions = ["s3:GetObject"]\n'
        '    resources = ["*"]\n'
        '  }\n'
        '}\n'
        'resource "aws_iam_role_policy_attachment" "a" {\n'
        '  role       = aws_iam_role.agent_role.name\n'
        '  policy_arn = aws_iam_policy.p.arn\n'
        '}\n',
        encoding="utf-8",
    )
    manifest, _ = _scan_manifest(str(root), tmp_path)
    assert manifest["iac_correlations"]["counts"]["grants"] == 1
    assert manifest["iac_correlations"]["schema_version"] == 2
    assert manifest["iac_correlations"]["lane"] == "B"
    assert manifest["summary"]["iac_grant_count"] == 1
    errors, _ = validate_manifest(manifest)
    assert errors == []
