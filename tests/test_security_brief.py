"""Unit tests for the security_brief reporting layer.

Proves the contract: deterministic transformation, no fabricated
actions, every action mapped to evidence, unknown stays unknown, IaC
never becomes runtime proof, no secret material, clean empty renders,
and baseline/non-baseline parity.
"""

import json

from safeai.report.security_brief import (
    build_actions,
    build_highlights,
    build_security_brief,
)


def _finding(**overrides):
    finding = {
        "rule_id": "CAP_shell",
        "severity": "high",
        "file": "a.py",
        "line": 1,
        "message": "Shell execution detected",
        "evidence": "subprocess.run",
        "remediation": "Restrict shell commands",
        "fingerprint": "f" * 64,
        "provenance_class": "detected",
        "gateability": "deterministic",
        "confidence_label": "high",
    }
    finding.update(overrides)
    return finding


def _report(**overrides):
    report = {
        "files_scanned": 3,
        "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "detected_frameworks": ["langchain"],
        "normalized_capabilities": [{"name": "shell_execution"}],
        "trust_score": {"overall_ai_risk_score": 62,
                        "categories": {"Capability": 40}},
        "findings": [_finding()],
        "tool_surface": [{
            "tool_key": "tool:shell-run",
            "kind": "tool",
            "framework": "langchain",
            "access_summary": "execute",
            "capabilities": [{"name": "shell_execution",
                              "access_mode": "execute",
                              "evidence": [{"path": "a.py", "line": 1}]}],
        }],
        "kya_agents": [{"agent_id": "agent-1"}],
        "policy_decision": {"outcome": "warn", "reasons": ["review shell usage"],
                            "matches": []},
        "assurance_boundary": {
            "summary": "Static evidence only.",
            "verified_statically": ["declared tools"],
            "not_verifiable_statically": ["runtime identity"],
            "coverage_notes": [],
            "inferred_value_count": 0,
        },
    }
    report.update(overrides)
    return report


def test_identical_input_produces_identical_brief():
    first = build_security_brief(_report())
    second = build_security_brief(_report())
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_no_fabricated_actions_on_empty_report():
    brief = build_security_brief({})
    assert brief["actions"] == []
    assert brief["uncertainty"] == []
    assert brief["changes"] == {"available": False, "summary": [],
                                "escalations": []}
    assert brief["authority"]["available"] is False
    assert brief["posture"]["agent_count"] == 0
    assert brief["value"]["actionable_review_items"] == 0


def test_every_action_maps_to_evidence():
    report = _report(
        capability_diff={
            "tools": [{
                "tool_key": "tool:shell-run",
                "status": "escalated",
                "change_class": "HIGH_RISK_CHANGE",
                "escalations": [{
                    "id": "ESC_SHELL_ADDED", "severity": "critical",
                    "summary": "Shell added",
                    "remediation": {
                        "why_it_matters": "Shell enables arbitrary commands.",
                        "recommended_actions": ["Remove shell access."],
                        "review_questions": ["Is shell access intended?"],
                        "limitations": ["Static evidence only."],
                    },
                }],
            }],
        },
        iac_correlations={
            "schema_version": 2,
            "lane": "B",
            "grants": [{
                "identity": {"kind": "aws_iam_role", "name": "agent-role"},
                "actions": {"values": ["s3:*"], "resolution": "resolved"},
                "resources": {"values": ["*"], "resolution": "resolved"},
                "source": "terraform", "source_file": "main.tf", "line": 10,
            }],
            "verdicts": [{
                "agent_ref": "<repo>",
                "identity_ref": {"kind": "aws_iam_role",
                                 "name": "agent-role"},
                "domain": "aws:s3",
                "verdict": "EXCESS_AUTHORITY",
                "declared_evidence_refs": ["tool:shell-run"],
                "grant_evidence_refs": ["main.tf:10"],
                "link_evidence_refs": ["config.yaml:3"],
                "resolution": "resolved",
                "reason": "Grant exceeds requirement.",
            }],
        },
        policy_decision={
            "outcome": "review-required",
            "reasons": ["prompt changed"],
            "matches": [{"policy_id": "PROMPT_FLOOR", "lane": "B",
                         "message": "Review the prompt change."}],
        },
    )
    brief = build_security_brief(report)
    assert brief["actions"], "expected actions from escalation, lane-B, and verdict"
    for action in brief["actions"]:
        assert action["reference"], "every action needs a stable reference"
        assert action["evidence_refs"], \
            f"action {action['reference']} must cite evidence"
        assert action["reason"], "every action needs a reason"
        assert action["remediation"], "every action needs remediation"
        assert action["limitations"], "every action states its limitations"
        assert action["priority"] in ("high", "medium", "low")
    references = {a["reference"] for a in brief["actions"]}
    assert any(r.startswith("escalation:") for r in references)
    assert "policy:PROMPT_FLOOR" in references
    assert any(r.startswith("iac:") for r in references)


def test_unknown_evidence_remains_unknown():
    report = _report(findings=[_finding(provenance_class="unknown",
                                        gateability="review-only")])
    brief = build_security_brief(report)
    assert brief["evidence"]["unknown"] == 1
    assert brief["evidence"]["detected"] == 0
    kinds = [u["kind"] for u in brief["uncertainty"]]
    assert "unknown-evidence" in kinds
    blob = json.dumps(brief).lower()
    assert "no unknown" not in blob
    assert "all evidence verified" not in blob


def test_iac_never_becomes_runtime_proof():
    report = _report(iac_correlations={
        "schema_version": 2,
        "lane": "B",
        "grants": [],
        "verdicts": [{
            "agent_ref": "<repo>",
            "identity_ref": {"kind": "aws_iam_role", "name": "agent-role"},
            "domain": "aws:s3",
            "verdict": "MATCH",
            "declared_evidence_refs": ["tool:x"],
            "grant_evidence_refs": ["main.tf:10"],
            "link_evidence_refs": ["config.yaml:3"],
            "resolution": "resolved",
            "reason": "Grant covers requirement.",
        }],
    })
    brief = build_security_brief(report)
    blob = json.dumps(brief).lower()
    for phrase in ("deployed permission", "runtime permission granted",
                   "proof of deployed", "verified runtime", "certified safe"):
        assert phrase not in blob, f"runtime claim leaked: {phrase}"
    assert brief["authority"]["match"] == 1


def test_no_secret_material_in_refs():
    report = _report(findings=[_finding(
        message="Credential AKIAIOSFODNN7EXAMPLE referenced",
        evidence="os.environ['AWS_KEY']",
    )])
    brief = build_security_brief(report)
    for action in brief["actions"]:
        for ref in action["evidence_refs"]:
            assert "\n" not in ref, "evidence refs must be single-line identifiers"
            assert len(ref) < 200, "evidence refs must be identifiers, not content"
    for item in brief["uncertainty"]:
        assert "\n" not in item["evidence_ref"]


def test_baseline_and_non_baseline_reports():
    without = build_security_brief(_report())
    assert without["changes"]["available"] is False
    assert without["changes"]["escalations"] == []
    with_diff = build_security_brief(_report(capability_diff={
        "baseline_available": True,
        "counts": {"added": 1, "removed": 0, "changed": 0, "escalations": 0},
        "tools": [],
    }))
    assert with_diff["changes"]["available"] is True
    assert any("new tool" in line for line in with_diff["changes"]["summary"])


def test_value_metrics_are_descriptive_counts():
    brief = build_security_brief(_report())
    value = brief["value"]
    assert value["agents_discovered"] == 1
    assert value["capabilities_inventoried"] == 1
    assert value["escalations_identified"] == 0
    assert value["authority_relationships_identified"] == 0
    assert value["unresolved_identity_links"] == 0
    assert value["unknown_conclusions"] == 0
    assert value["actionable_review_items"] == len(brief["actions"])


def test_highlights_trace_to_tool_surface():
    brief_report = _report()
    highlights = build_highlights(brief_report)
    assert highlights, "expected highlight from shell capability"
    for highlight in highlights:
        assert "tool:shell-run" in highlight["text"]
        assert highlight["evidence_ref"] == "a.py:1"


def test_risk_band_reuses_documented_bands():
    assert build_security_brief(_report())["posture"]["risk_band"] == "high"
    assert build_security_brief(
        _report(trust_score={"overall_ai_risk_score": None}))["posture"]["risk_band"] == "unknown"
    assert build_security_brief(
        _report(trust_score={"overall_ai_risk_score": 10}))["posture"]["risk_band"] == "low"


def test_build_actions_deterministic_order():
    first = build_actions(_report())
    second = build_actions(_report())
    assert [(a["priority"], a["reference"]) for a in first] == \
           [(a["priority"], a["reference"]) for a in second]
