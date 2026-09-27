"""Architectural invariants: the lane model and domain vocabulary, pinned.

Each test maps to one invariant: authority removal, UNKNOWN handling,
inferred-only gating, determinism, severity/class separation, vocabulary
separation, exception evidence, scope honesty, baseline honesty, output
caps, the static-only boundary, and (13-16) the v2.5 IaC evidence
discipline: IaC never gates, verdicts cite evidence, links default
unverified, and review-only findings stay Lane B.
"""

import json

from safeai.analysis.capability_diff import (
    authority_gate_tripped,
    change_class_for,
    compute_capability_diff,
)
from safeai.analysis.iac_correlation import correlate_iac_authority
from safeai.kya import policy as kya_policy
from safeai.kya.enrich import gateability_for
from safeai.kya.exceptions import evaluate_exceptions


def _finding(rule="CAP_shell", severity="high", status="new"):
    return {
        "rule_id": rule, "severity": severity, "status": status,
        "fingerprint": "f" * 64, "file": "src/agent.py",
    }


def _report(findings):
    return {
        "findings": findings,
        "normalized_capabilities": [],
        "detected_frameworks": [],
        "mcp_assets": [],
        "agent_models": [],
    }


def _allow_all_policy():
    return {"version": "1", "default_action": "allow", "policies": []}


def test_1_removal_never_high_risk():
    critical = [{"id": "ESC_X", "severity": "critical"}]
    assert change_class_for("removed", critical, [], []) == "LOW_CHANGE"
    assert change_class_for("reduced", critical, [], []) == "LOW_CHANGE"


def test_2_unknown_never_fails_authority_gate():
    tools = [{"tool_key": "t", "change_class": "UNKNOWN"}]
    assert authority_gate_tripped(tools, "material") is False
    assert authority_gate_tripped(tools, "high-risk") is False


def test_3_inferred_only_never_fails_lane_a_gate():
    tools = [{"tool_key": "t", "change_class": "HIGH_RISK_CHANGE",
              "inferred_only": True}]
    assert authority_gate_tripped(tools, "material") is False
    assert authority_gate_tripped(tools, "high-risk") is False


def test_4_deterministic_output():
    from safeai.report.pr_comment import render_pr_comment

    report = {
        "findings": [],
        "capability_diff": {
            "schema_version": 2, "baseline_available": True,
            "baseline_tool_attribution": True, "tools": [],
            "unattributed": None, "counts": {}, "highest_escalation": None,
            "legacy": {},
        },
        "tool_surface": [], "kya_agents": [],
    }
    assert render_pr_comment(report) == render_pr_comment(report)


def test_5_severity_alone_does_not_change_classification():
    high = [{"id": "ESC_Y", "severity": "high"}]
    medium = [{"id": "ESC_Y", "severity": "medium"}]
    assert (change_class_for("escalated", high, [], [])
            == change_class_for("escalated", medium, [], [])
            == "MATERIAL_CHANGE")


def test_6_policy_dsl_and_manifest_vocabularies_separate():
    from safeai.kya.contract import POLICY_OUTCOMES

    assert set(kya_policy.ACTIONS) == {"allow", "warn", "require_review", "deny"}
    assert set(kya_policy.ACTION_OUTCOME) == set(kya_policy.ACTIONS)
    assert set(kya_policy.ACTION_OUTCOME.values()) <= set(POLICY_OUTCOMES)
    decision = kya_policy.evaluate_policy(_allow_all_policy(), _report([]))
    assert decision["outcome"] in POLICY_OUTCOMES
    assert decision["action"] in kya_policy.ACTIONS


def test_7_active_exception_leaves_explicit_evidence():
    from safeai.kya.manifest import build_manifest

    report = {
        "files_scanned": 1, "counts": {}, "detected_frameworks": [],
        "findings": [], "normalized_capabilities": [],
        "trust_score": {"overall_ai_risk_score": 50, "categories": {}},
        "exception_evaluations": [{
            "exception_id": "E1", "target_type": "finding",
            "target_id": "CAP_shell", "state": "active",
            "risk_owner": "o@example.com", "expires_at": None,
        }],
    }
    manifest = build_manifest(
        report, project={"project_id": "p", "source_root": "."},
        scan_meta={"scan_id": "s", "completed_at": "2026-01-01T00:00:00Z"},
        safeai_meta={"version": "2.4.0"}, agents=[],
    )
    assert manifest["exception_evaluations"][0]["state"] == "active"
    # The policy decision is untouched by exceptions: no silent PASS rewrite.
    decision = kya_policy.evaluate_policy(_allow_all_policy(), _report([]))
    assert decision["outcome"] == "pass"


def test_8_expired_exception_cannot_suppress_risk():
    entry = {
        "exception_id": "E1", "target_type": "finding",
        "target_id": "CAP_shell", "expired": True, "expires_at": "2000-01-31",
        "risk_owner": "o", "scope": {},
        "compensating_controls": [], "review_trigger": [],
    }
    finding = _finding()
    evaluations = evaluate_exceptions([entry], [finding], [])
    assert evaluations[0]["state"] == "expired"
    assert finding.get("status") != "suppressed"


def test_9_scope_mismatch_never_activates():
    entry = {
        "exception_id": "E1", "target_type": "finding",
        "target_id": "CAP_shell", "expired": False,
        "risk_owner": "o",
        "scope": {"repository": "acme/other", "commit_range": None},
        "compensating_controls": [], "review_trigger": [],
    }
    evaluations = evaluate_exceptions(
        [entry], [_finding()], [], project_identities={"acme/agent"})
    assert evaluations[0]["state"] == "scope-mismatch"


def test_10_pre_attribution_baselines_do_not_fabricate_new():
    def tool(key, caps):
        return {
            "tool_key": key,
            "tool": {"kind": "tool", "name": key, "framework": None},
            "capabilities": [
                {"name": c, "access_mode": "read", "evidence": [],
                 "confidence": 1.0, "inferred": False} for c in caps
            ],
            "access_summary": "read",
        }

    current = {"tool_surface": [tool("tool:a", ["shell"])]}
    baseline = {}  # pre-tool-attribution: no tool_surface key at all
    diff = compute_capability_diff(current, baseline)
    for entry in diff["tools"]:
        assert entry["status"] == "unknown"
        assert entry["change_class"] == "UNKNOWN"


def test_11_pr_comment_deterministic_and_capped():
    from safeai.report.pr_comment import MAX_LINES, render_pr_comment

    findings = [{
        "rule_id": "DATAFLOW_shell", "severity": "high", "status": "new",
        "message": "flow", "file": f"f{i}.py", "line": i,
        "evidence": f"source:v{i}@L1 -> sink:shell@L2",
    } for i in range(30)]
    tools = [{
        "tool_key": f"tool:{i}",
        "tool": {"kind": "tool", "name": str(i), "framework": None},
        "status": "escalated",
        "access_summary": {"before": "read", "after": "write"},
        "capabilities_added": [], "capabilities_removed": [],
        "access_mode_changes": [],
        "escalations": [{
            "id": "ESC_X", "severity": "high", "summary": "Widened",
            "before": "read", "after": "write",
            "evidence": [{"path": "a.py", "line": 1}],
            "confidence": "high", "inferred": False,
        }],
    } for i in range(10)]
    report = {
        "findings": findings,
        "capability_diff": {
            "schema_version": 2, "baseline_available": True,
            "baseline_tool_attribution": True, "tools": tools,
            "unattributed": None,
            "counts": {"tools_unchanged": 0}, "highest_escalation": "high",
            "legacy": {},
        },
        "tool_surface": [], "kya_agents": [],
    }
    first = render_pr_comment(report)
    assert render_pr_comment(report) == first
    assert len(first.splitlines()) <= MAX_LINES


def test_12_static_evidence_never_claims_runtime_proof():
    from safeai.kya.manifest import build_manifest

    report = {
        "files_scanned": 1, "counts": {}, "detected_frameworks": [],
        "findings": [], "normalized_capabilities": [],
        "trust_score": {"overall_ai_risk_score": 50, "categories": {}},
        "capability_diff": {
            "tools": [{
                "tool_key": "tool:x", "status": "new",
                "change_class": "HIGH_RISK_CHANGE",
                "change_types": ["AUTHORITY_ADDED"],
                "inferred_only": False, "escalations": [],
            }],
            "counts": {"by_change_class": {"HIGH_RISK_CHANGE": 1}},
        },
    }
    manifest = build_manifest(
        report, project={"project_id": "p", "source_root": "."},
        scan_meta={"scan_id": "s", "completed_at": "2026-01-01T00:00:00Z"},
        safeai_meta={"version": "2.4.0"}, agents=[],
    )
    assert manifest["assurance_boundary"]
    assert manifest["limitations"]
    boundary = manifest["assurance_boundary"]
    assert boundary.get("not_verifiable_statically"), \
        "assurance boundary must name what static analysis cannot verify"
    blob = json.dumps(manifest, default=str).lower()
    # The boundary disclaims runtime proof explicitly (negation present).
    assert "do not verify deployed runtime" in blob
    # No affirmative runtime-safety claim anywhere in portable evidence.
    for phrase in ("certified safe", "guaranteed secure", "is compliant",
                   "proof of deployed", "verified runtime permission"):
        assert phrase not in blob


def _iac_grant(name="agent-s3-access", actions=("s3:GetObject",),
               resources=("*",), res="resolved"):
    return {
        "identity": {"kind": "aws_iam_role", "name": name, "namespace": ""},
        "actions": {"values": list(actions), "resolution": res, "notes": []},
        "resources": {"values": list(resources), "resolution": res,
                      "notes": []},
        "scope": "", "source": "terraform", "source_file": "main.tf",
        "line": 10, "provenance": "repo-iac-observed", "fidelity": [],
        "family": "cloud",
    }


def _iac_report(tool_caps=()):
    return {
        "tool_surface": [
            {"tool_key": f"tool:{name}",
             "capabilities": [{"name": cap, "access_mode": "read"}]}
            for name, cap in tool_caps
        ],
        "findings": [],
    }


def _iac_graph(grants=(), links=()):
    return {"identities": [], "grants": list(grants),
            "grant_bindings": [], "agent_links": list(links), "meta": {}}


def test_13_iac_evidence_never_gates():
    # repo-iac-observed provenance maps to review-only gateability, and
    # every finding the correlator emits is pre-set review-only.
    assert gateability_for({}, "repo-iac-observed") == "review-only"
    findings, _ = correlate_iac_authority(
        _iac_report(tool_caps=[("x", "s3")]), _iac_graph(
            grants=[_iac_grant()]))
    assert findings, "UNVERIFIED_LINK finding expected"
    for finding in findings:
        assert finding["gateability"] == "review-only"
        assert finding["provenance_class"] == "repo-iac-observed"
        assert kya_policy.lane_of_finding(finding) == "B"
    # IaC verdicts never touch the authority gate: no tool changes, no trip.
    assert authority_gate_tripped([], "material") is False


def test_14_verdicts_cite_evidence_or_are_unknown():
    _, summary = correlate_iac_authority(
        _iac_report(tool_caps=[("x", "s3")]),
        _iac_graph(grants=[_iac_grant()]))
    assert summary["verdicts"], "expected an UNVERIFIED_LINK verdict"
    for item in summary["verdicts"]:
        if item["verdict"] == "UNKNOWN":
            continue
        refs = (item.get("declared_evidence_refs") or []) + \
               (item.get("grant_evidence_refs") or [])
        assert refs, "non-UNKNOWN verdicts must cite evidence refs"


def test_15_agent_identity_links_default_unverified():
    # Grants + declared requirement with no static link: UNVERIFIED_LINK,
    # never MATCH. MATCH requires an evidenced Agent-to-Identity edge.
    _, summary = correlate_iac_authority(
        _iac_report(tool_caps=[("x", "s3")]),
        _iac_graph(grants=[_iac_grant()]))
    assert [v["verdict"] for v in summary["verdicts"]] == ["UNVERIFIED_LINK"]


def test_16_review_only_findings_stay_lane_b():
    iac_finding = {
        "rule_id": "IAC_EXCESS_AUTHORITY", "severity": "medium",
        "gateability": "review-only",
        "provenance_class": "repo-iac-observed",
    }
    assert kya_policy.lane_of_finding(iac_finding) == "B"
    # Severity does not promote it: medium severity, review-only
    # gateability, Lane B — three separate dimensions, never blended.
    assert iac_finding["severity"] == "medium"
    assert iac_finding["gateability"] == "review-only"
