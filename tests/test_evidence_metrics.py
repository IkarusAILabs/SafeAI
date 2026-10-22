"""Tests for authority evidence metrics (v2.7, ROADMAP Layer 2 / P0).

Proves: counts and rates are correct on known inputs; empty denominators
report insufficient_evidence (never 0/1); unknown is counted, never
reinterpreted; output is deterministic; the block reaches the manifest
summary and the JSON report; and it never changes the exit code.
"""

import json
import os

from safeai.analysis.evidence_metrics import (
    AUTHORITY_DIMENSIONS,
    compute_evidence_metrics,
    summary_lines,
)
from safeai.analysis.tool_identity import UNATTRIBUTED_KEY
from safeai.cmd.cli import main
from safeai.kya.contract import PROVENANCE_CLASSES, validate_manifest
from safeai.report.security_brief import build_coverage

_REF = [{"path": "agent.py", "line": 3}]

_SURFACE = [
    {"tool_key": "tool:send_email", "capabilities": [
        {"name": "email", "access_mode": "write", "inferred": False, "evidence": _REF},
        {"name": "http", "access_mode": "read", "inferred": True, "evidence": _REF},
    ]},
    {"tool_key": UNATTRIBUTED_KEY, "capabilities": [
        {"name": "shell", "access_mode": "execute", "inferred": False, "evidence": _REF},
        {"name": "filesystem", "access_mode": "read", "inferred": False, "evidence": []},
    ]},
]

_FINDINGS = [
    {"rule_id": "CAP_shell", "provenance_class": "detected"},
    {"rule_id": "CAP_http", "provenance_class": "inferred"},
    {"rule_id": "IAC_X", "provenance_class": "repo-iac-observed"},
    {"rule_id": "X", "provenance_class": "unknown"},
    {"rule_id": "Y"},                              # missing -> unknown
    {"rule_id": "Z", "provenance_class": "bogus"},  # out of contract -> unknown
]


def _rate(metrics, name):
    return metrics["rates"][name]


def test_statement_counts_and_rates():
    metrics = compute_evidence_metrics(_SURFACE, _FINDINGS)
    assert metrics["authority_statements"] == {
        "total": 4, "evidence_backed": 1, "inferred": 1,
        "unattributed": 2, "with_evidence_refs": 3,
    }
    assert _rate(metrics, "evidence_backed_authority_rate")["value"] == 0.25
    assert _rate(metrics, "inferred_authority_rate")["value"] == 0.25
    assert _rate(metrics, "unattributed_authority_rate")["value"] == 0.5
    assert _rate(metrics, "evidence_completeness")["value"] == 0.75
    backed = _rate(metrics, "evidence_backed_authority_rate")
    assert (backed["numerator"], backed["denominator"], backed["status"]) == (1, 4, "measured")


def test_finding_provenance_counts_unknown_never_reinterpreted():
    metrics = compute_evidence_metrics(_SURFACE, _FINDINGS)
    provenance = metrics["finding_provenance"]
    assert set(provenance) == set(PROVENANCE_CLASSES)
    assert provenance["unknown"] == 3
    assert provenance["detected"] == 1
    assert provenance["inferred"] == 1
    assert provenance["repo-iac-observed"] == 1
    assert provenance["declared"] == 0
    assert _rate(metrics, "unknown_finding_rate")["value"] == 0.5


def test_empty_inputs_are_insufficient_evidence_not_zero():
    metrics = compute_evidence_metrics([], [])
    for name, entry in metrics["rates"].items():
        assert entry["status"] == "insufficient_evidence", name
        assert entry["value"] is None, name
        assert entry["reason"], name


def test_dimensions_absent_without_baseline():
    metrics = compute_evidence_metrics(_SURFACE, _FINDINGS, capability_diff=None)
    assert metrics["authority_dimensions"] is None
    entry = _rate(metrics, "unknown_authority_dimension_rate")
    assert entry["status"] == "insufficient_evidence"
    assert "baseline" in entry["reason"]


def test_dimensions_counted_from_diff_authority():
    known = {"provenance_class": "detected", "state": "present"}
    unknown = {"provenance_class": "unknown", "state": "unknown"}
    authority = {dim: dict(unknown) for dim in AUTHORITY_DIMENSIONS}
    authority["destinations"] = dict(known)
    authority["approval"] = dict(known)
    diff = {
        "tools": [
            {"tool_key": "tool:a", "authority": authority},
            {"tool_key": "tool:b", "authority": {}},  # every dimension missing
            {"tool_key": "tool:c"},                   # no authority block: skipped
        ],
        # The unattributed tool travels separately in the diff; it counts.
        "unattributed": {"tool_key": UNATTRIBUTED_KEY, "authority": dict(authority)},
    }
    metrics = compute_evidence_metrics(_SURFACE, _FINDINGS, diff)
    dims = metrics["authority_dimensions"]
    assert dims["destinations"] == {"total": 3, "unknown": 1}
    assert dims["identity"] == {"total": 3, "unknown": 3}
    entry = _rate(metrics, "unknown_authority_dimension_rate")
    assert (entry["numerator"], entry["denominator"]) == (17, 21)


def test_deterministic_and_declares_what_it_does_not_measure():
    first = compute_evidence_metrics(_SURFACE, _FINDINGS)
    second = compute_evidence_metrics(list(_SURFACE), list(_FINDINGS))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert {m["metric"] for m in first["not_measured"]} == {"false_attribution_rate"}


def test_summary_lines():
    lines = summary_lines(compute_evidence_metrics(_SURFACE, _FINDINGS))
    assert lines[0] == "Evidence-backed authority: 25% (1/4)"
    assert "Unattributed authority: 50% (2/4)" in lines
    assert summary_lines(compute_evidence_metrics([], [])) == [
        "Evidence-backed authority: insufficient evidence",
        "Inferred authority: insufficient evidence",
        "Unattributed authority: insufficient evidence",
    ]
    assert summary_lines(None) == []


def test_brief_coverage_includes_metrics():
    report = {"evidence_metrics": compute_evidence_metrics(_SURFACE, _FINDINGS)}
    assert "Evidence-backed authority: 25% (1/4)" in build_coverage(report)
    assert not any("authority:" in line for line in build_coverage({}))


def _scan(root, tmp_path, *extra):
    manifest_path = os.path.join(str(tmp_path), "m.json")
    json_path = os.path.join(str(tmp_path), "r.json")
    rc = main(["scan", root, "--manifest", manifest_path, "--json", json_path,
               "--sarif", os.path.join(str(tmp_path), "r.sarif"),
               "--no-registry", *extra])
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    with open(json_path, encoding="utf-8") as fh:
        report = json.load(fh)
    return rc, manifest, report, json_path


def test_scan_emits_metrics_in_manifest_and_report(kya_project, tmp_path):
    rc, manifest, report, _ = _scan(kya_project["root"], tmp_path)
    assert rc in (0, 1)
    metrics = manifest["summary"]["evidence_metrics"]
    assert report["evidence_metrics"] == metrics
    assert metrics["metrics_version"] == 1
    assert metrics["authority_statements"]["total"] >= 1
    assert sum(metrics["finding_provenance"].values()) == len(manifest["findings"])
    errors, _ = validate_manifest(manifest)
    assert errors == []


def test_metrics_recomputable_from_manifest_alone(kya_project, tmp_path):
    _, manifest, _, _ = _scan(kya_project["root"], tmp_path)
    recomputed = compute_evidence_metrics(manifest["tool_surface"], manifest["findings"])
    emitted = manifest["summary"]["evidence_metrics"]
    for key in ("authority_statements", "finding_provenance"):
        assert recomputed[key] == emitted[key]


def test_baseline_scan_measures_dimensions_and_exit_code_unchanged(kya_project, tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    _, _, _, baseline_json = _scan(kya_project["root"], base_dir)
    kya_project["write_version"](kya_project["v2"])
    cur_dir = tmp_path / "cur"
    cur_dir.mkdir()
    rc, manifest, _, _ = _scan(kya_project["root"], cur_dir, "--baseline", baseline_json)
    metrics = manifest["summary"]["evidence_metrics"]
    assert metrics["authority_dimensions"] is not None
    entry = metrics["rates"]["unknown_authority_dimension_rate"]
    assert entry["status"] == "measured"
    # identity is unobservable statically: always counted as unknown.
    assert metrics["authority_dimensions"]["identity"]["unknown"] == \
        metrics["authority_dimensions"]["identity"]["total"]
    assert rc in (0, 1)
