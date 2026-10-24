"""Tests for governable UNKNOWN authority (WS2, v2.4.x).

Default behavior is unchanged (UNKNOWN never fails alone); an explicit
``authority.unknown`` policy (or --unknown-authority flag) governs it
through the canonical outcome vocabulary and lanes.
"""
import os

import pytest

from safeai.cmd.cli import main
from safeai.kya.policy import PolicyError, evaluate_policy, load_policy


def _report(findings=None, unknown_tools=()):
    tools = [
        {"tool_key": key, "change_class": "UNKNOWN", "inferred_only": False,
         "escalations": []}
        for key in unknown_tools
    ]
    return {
        "findings": findings or [],
        "normalized_capabilities": [],
        "detected_frameworks": [],
        "mcp_assets": [],
        "agent_models": [],
        "capability_diff": {"tools": tools},
    }


def _finding(rule="CAP_shell", severity="high", status="new"):
    return {"rule_id": rule, "severity": severity, "status": status,
            "fingerprint": "f" * 64, "file": "src/agent.py"}


def _policy_doc(unknown=None, default_action="warn"):
    doc = {"version": "1", "default_action": default_action, "policies": []}
    if unknown:
        doc["authority"] = {"unknown": unknown}
    return doc


class TestUnknownPolicy:
    def test_unknown_default_policy_unchanged(self):
        decision = evaluate_policy(
            _policy_doc(), _report([_finding()], unknown_tools=["tool:x"]))
        assert decision["outcome"] == "warn"
        assert decision["lanes"] == {"A": 0, "B": 0}

    def test_unknown_allow_is_pass(self):
        decision = evaluate_policy(
            _policy_doc("allow", default_action="allow"),
            _report(unknown_tools=["tool:x"]))
        assert decision["outcome"] == "pass"
        assert decision["lane"] == "A"

    def test_unknown_require_review(self):
        decision = evaluate_policy(
            _policy_doc("require_review"), _report(unknown_tools=["tool:x"]))
        assert decision["outcome"] == "review-required"
        assert decision["lane"] == "B"
        assert decision["lanes"] == {"A": 0, "B": 1}
        assert "could not be attributed" in decision["reasons"][0]

    def test_unknown_deny_blocks_lane_a(self):
        decision = evaluate_policy(
            _policy_doc("deny"), _report(unknown_tools=["tool:x"]))
        assert decision["outcome"] == "block"
        assert decision["action"] == "deny"
        assert decision["lane"] == "A"

    def test_known_unchanged_authority_unaffected(self):
        report = _report()
        report["capability_diff"]["tools"] = [
            {"tool_key": "tool:a", "change_class": "NO_CHANGE",
             "inferred_only": False, "escalations": []}
        ]
        decision = evaluate_policy(_policy_doc("deny"), report)
        assert decision["outcome"] == "warn"
        assert decision["matches"] == []

    def test_known_material_change_unaffected(self):
        report = _report()
        report["capability_diff"]["tools"] = [
            {"tool_key": "tool:a", "change_class": "MATERIAL_CHANGE",
             "inferred_only": False, "escalations": []}
        ]
        decision = evaluate_policy(_policy_doc("deny"), report)
        assert decision["outcome"] == "warn"

    def test_legacy_baseline_marks_unknown(self):
        from safeai.analysis.capability_diff import compute_capability_diff

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
        diff = compute_capability_diff(current, {})  # v1.3: no tool_surface
        assert diff["tools"][0]["change_class"] == "UNKNOWN"
        report = _report()
        report["capability_diff"] = diff
        decision = evaluate_policy(_policy_doc("require_review"), report)
        assert decision["outcome"] == "review-required"

    def test_suppressed_findings_do_not_interfere(self):
        decision = evaluate_policy(
            _policy_doc("deny"),
            _report([_finding(status="suppressed")], unknown_tools=["tool:x"]))
        assert decision["outcome"] == "block"

    def test_gate_ignores_unknown(self):
        from safeai.analysis.capability_diff import authority_gate_tripped

        tools = [{"tool_key": "t", "change_class": "UNKNOWN"}]
        assert authority_gate_tripped(tools, "material") is False

    def test_invalid_authority_value_rejected(self, tmp_path):
        path = os.path.join(str(tmp_path), "policy.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("policies: []\nauthority:\n  unknown: obliterate\n")
        with pytest.raises(PolicyError):
            load_policy(path)

    def test_authority_section_loaded(self, tmp_path):
        path = os.path.join(str(tmp_path), "policy.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("policies: []\nauthority:\n  unknown: require_review\n")
        policy = load_policy(path)
        assert policy["authority"] == {"unknown": "require_review"}


class TestUnknownIsDiffDependent:
    """The authority:unknown match needs a capability diff to act on.

    ``evaluate_policy`` builds the match from
    ``capability_diff["tools"]`` filtered on ``change_class == "UNKNOWN"``.
    When the baseline carries neither ``tool_surface`` nor
    ``normalized_capabilities`` no diff is computed at all, so ``deny``
    has nothing to match and the run passes. That is the same blind spot
    ``--fail-on-authority-change`` / ``--fail-on-escalation`` have, which
    is why ``scan`` now warns about it.
    """

    @staticmethod
    def _no_diff_report():
        report = _report()
        del report["capability_diff"]
        return report

    def test_deny_cannot_fire_without_a_capability_diff(self):
        decision = evaluate_policy(_policy_doc("deny"), self._no_diff_report())
        assert decision["outcome"] != "block"
        assert not any(m["policy_id"] == "authority:unknown"
                       for m in decision["matches"])

    def test_deny_fires_once_a_diff_exists(self):
        report = _report(unknown_tools=["tool:x"])
        decision = evaluate_policy(_policy_doc("deny"), report)
        assert decision["outcome"] == "block"
        assert any(m["policy_id"] == "authority:unknown"
                   for m in decision["matches"])

    def test_empty_tool_list_behaves_like_no_diff(self):
        report = _report()
        report["capability_diff"] = {"tools": []}
        decision = evaluate_policy(_policy_doc("deny"), report)
        assert decision["outcome"] != "block"


class TestUnknownCliFlag:
    def test_flag_fills_gap(self, kya_project, tmp_path):
        rc = main(["scan", kya_project["root"],
                   "--sarif", os.path.join(str(tmp_path), "r.sarif"),
                   "--no-registry", "--unknown-authority", "review"])
        assert rc in (0, 1)

    def test_flag_invalid_choice_rejected(self, kya_project, tmp_path):
        with pytest.raises(SystemExit):
            main(["scan", kya_project["root"],
                  "--sarif", os.path.join(str(tmp_path), "r.sarif"),
                  "--no-registry", "--unknown-authority", "maybe"])


class TestUnknownActionInput:
    @staticmethod
    def _driver():
        import importlib.util

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(repo_root, "scripts", "safeai-action.py")
        spec = importlib.util.spec_from_file_location("safeai_action", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_argv_mapping(self):
        argv = self._driver().build_scan_argv(
            ".", "critical", "r.sarif", unknown_authority="review")
        assert "--unknown-authority" in argv
        assert "review" in argv

    def test_argv_omitted_by_default(self):
        argv = self._driver().build_scan_argv(".", "critical", "r.sarif")
        assert "--unknown-authority" not in argv
