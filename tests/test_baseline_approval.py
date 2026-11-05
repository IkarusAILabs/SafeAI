"""Approval of the baseline manifest (v2.15, plan 2.15-3)."""

import json
from pathlib import Path

import jsonschema
import pytest

from safeai.cmd.cli import main

ROOT = Path(__file__).resolve().parents[1]
SERVER = {"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp"]}}}


@pytest.fixture
def baseline(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".mcp.json").write_text(json.dumps(SERVER), encoding="utf-8")
    path = tmp_path / "baseline.json"
    assert main(["scan", str(repo), "--no-registry", "--manifest", str(path),
                 "--sarif", str(tmp_path / "b.sarif")]) == 0
    return repo, path


def _scan(tmp_path, repo, baseline_path, *extra):
    manifest = tmp_path / "m.json"
    rc = main(["scan", str(repo), "--no-registry", "--baseline", str(baseline_path),
               "--manifest", str(manifest), "--sarif", str(tmp_path / "c.sarif"), *extra])
    return rc, json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else None


def test_unrecorded_baseline_fails_only_with_require_approval(tmp_path, baseline):
    repo, path = baseline
    rc, manifest = _scan(tmp_path, repo, path)
    assert rc == 0 and manifest["baseline_approval"]["state"] == "unrecorded"
    rc, _ = _scan(tmp_path, repo, path, "--require-approval")
    assert rc == 1


def test_approved_baseline_passes_and_validates(tmp_path, baseline, capsys):
    repo, path = baseline
    assert main(["manifest", "approve", str(path), "--by", "lead@example.org",
                 "--owner", "dev@example.org", "--at", "2026-11-01"]) == 0
    assert "approved:" in capsys.readouterr().out
    record = json.loads((tmp_path / "baseline.json.approval.json").read_text(encoding="utf-8"))
    assert record["approval_type"] == "safeai-baseline-approval/v1"
    rc, manifest = _scan(tmp_path, repo, path, "--require-approval")
    assert rc == 0
    section = manifest["baseline_approval"]
    assert section["state"] == "approved"
    assert section["approval"]["approved_by"] == "lead@example.org"
    assert section["approved_payload_sha256"] == section["baseline_payload_sha256"]
    schema = json.loads((ROOT / "schemas/safeai-manifest/v1.3.0.json").read_text(encoding="utf-8"))
    assert list(jsonschema.Draft202012Validator(schema).iter_errors(manifest)) == []


def test_self_approval_and_a_changed_baseline_are_not_approved(tmp_path, baseline):
    repo, path = baseline
    main(["manifest", "approve", str(path), "--by", "Dev@example.org",
          "--owner", "dev@example.org", "--at", "2026-11-01"])
    rc, _manifest = _scan(tmp_path, repo, path, "--require-approval")
    assert rc == 1
    _rc, manifest = _scan(tmp_path, repo, path)
    assert manifest["baseline_approval"]["state"] == "self-approved"

    other = tmp_path / "other.approval.json"
    main(["manifest", "approve", str(path), "--by", "lead@example.org", "-o", str(other)])
    edited = json.loads(path.read_text(encoding="utf-8"))
    edited["project"]["name"] = "renamed"
    from safeai.kya.integrity import stamp_integrity
    path.write_text(json.dumps(stamp_integrity(edited)), encoding="utf-8")
    _rc, manifest = _scan(tmp_path, repo, path, "--baseline-approval", str(other))
    assert manifest["baseline_approval"]["state"] == "digest-mismatch"


def test_tampered_baseline_is_unverifiable_and_cannot_be_approved(tmp_path, baseline, capsys):
    repo, path = baseline
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["project"]["name"] = "tampered"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert main(["manifest", "approve", str(path), "--by", "lead@example.org"]) == 1
    assert "only a manifest whose integrity digest verifies" in capsys.readouterr().out
    _rc, manifest = _scan(tmp_path, repo, path)
    assert manifest["baseline_approval"]["state"] == "unverifiable"


@pytest.mark.parametrize("record", [
    {"approval_type": "something-else"},
    {"approval_type": "safeai-baseline-approval/v1", "manifest": {"payload_sha256": "x"},
     "approval": {"approved_by": "a", "approved_at": "2026-11-01"}},
    {"approval_type": "safeai-baseline-approval/v1", "manifest": {"payload_sha256": "0" * 64},
     "approval": {"approved_by": "a", "approved_at": "2999-01-01"}},
])
def test_malformed_record_is_a_usage_error(tmp_path, baseline, record):
    repo, path = baseline
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(SystemExit):
        _scan(tmp_path, repo, path, "--baseline-approval", str(bad))


def test_baseline_approval_option_requires_a_baseline(tmp_path, baseline):
    repo, path = baseline
    with pytest.raises(SystemExit):
        main(["scan", str(repo), "--no-registry", "--sarif", str(tmp_path / "x.sarif"),
              "--baseline-approval", str(path)])


def test_no_baseline_means_no_section(tmp_path, baseline):
    repo, _path = baseline
    out = tmp_path / "n.json"
    main(["scan", str(repo), "--no-registry", "--manifest", str(out), "--sarif",
          str(tmp_path / "n.sarif")])
    assert json.loads(out.read_text(encoding="utf-8"))["baseline_approval"] is None
