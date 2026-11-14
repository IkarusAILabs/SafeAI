"""A gate the operator asked for must not pass because its input is unusable.

Each case names a requested control whose input is missing, malformed, or
can never match. The scan must refuse (exit 2: "the requested control
cannot be satisfied"), never exit 0. Exit 0 would say "checked and clean"
about a check that did not run. Follow-up to #333.

The scanned project is clean, so every run here would exit 0 if the gate
were silently dropped.
"""

import json

import pytest

from safeai.cmd.cli import main
from safeai.cmd.postprocess import FAIL_ON_CATEGORY_PREFIXES


@pytest.fixture
def clean_project(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "notes.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def _scan(project, tmp_path, *extra):
    """Exit code of a scan, whether returned or raised by the parser."""
    argv = ["scan", str(project), "--no-registry",
            "--sarif", str(tmp_path / "out.sarif"), *extra]
    try:
        return main(argv)
    except SystemExit as exc:
        return exc.code


def test_clean_project_passes_without_gates(clean_project, tmp_path):
    # The control for every case below: with no gate requested, exit 0.
    assert _scan(clean_project, tmp_path) == 0


def _missing(tmp_path):
    return str(tmp_path / "does-not-exist.yml")


def _malformed(tmp_path):
    path = tmp_path / "malformed.yml"
    path.write_text("{not: [closed", encoding="utf-8")
    return str(path)


def _empty_baseline(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"findings": []}), encoding="utf-8")
    return str(path)


UNUSABLE_INPUTS = {
    # Fixed in this change: a named policy file that does not exist was
    # ignored and the default policy used.
    "policy-file-missing": lambda t: ["--policy", _missing(t)],
    "policy-file-malformed": lambda t: ["--policy", _malformed(t)],
    # Fixed in this change: escalation rules are not findings, so these
    # patterns could never fire.
    "fail-on-rule-escalation-glob": lambda t: ["--fail-on-rule", "ESC_*"],
    "fail-on-rule-escalation-id": lambda t: [
        "--fail-on-rule", "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT"],
    "fail-on-rule-escalation-among-valid": lambda t: [
        "--fail-on-rule", "GOV_*", "ESC_*"],
    # Already refused before this change; pinned so they stay refused.
    "baseline-missing": lambda t: ["--baseline", _missing(t)],
    "baseline-malformed": lambda t: ["--baseline", _malformed(t)],
    "exceptions-malformed": lambda t: ["--exceptions", _malformed(t)],
    "fail-on-new-without-baseline": lambda t: ["--fail-on-new"],
    "fail-on-escalation-without-baseline": lambda t: ["--fail-on-escalation", "high"],
    "fail-on-authority-change-without-baseline": lambda t: [
        "--fail-on-authority-change", "material"],
    "unknown-authority-block-without-baseline": lambda t: [
        "--unknown-authority", "block"],
    "baseline-approval-without-baseline": lambda t: [
        "--baseline-approval", _missing(t)],
    "fail-on-escalation-diff-blind-baseline": lambda t: [
        "--baseline", _empty_baseline(t), "--fail-on-escalation", "high"],
    "fail-on-authority-change-diff-blind-baseline": lambda t: [
        "--baseline", _empty_baseline(t), "--fail-on-authority-change", "material"],
    "fail-on-category-unknown": lambda t: ["--fail-on-category", "no-such-category"],
    "policy-profile-unknown": lambda t: ["--policy-profile", "no-such-profile"],
}


@pytest.mark.parametrize("case", sorted(UNUSABLE_INPUTS))
def test_unusable_gate_input_exits_2(case, clean_project, tmp_path):
    assert _scan(clean_project, tmp_path, *UNUSABLE_INPUTS[case](tmp_path)) == 2


def test_missing_policy_file_is_named(clean_project, tmp_path, capsys):
    missing = _missing(tmp_path)
    assert _scan(clean_project, tmp_path, "--policy", missing) == 2
    assert f"Policy file not found: {missing}" in capsys.readouterr().err


def test_absent_default_policy_file_is_not_an_error(clean_project, tmp_path):
    # No --policy and no .safeai/policy.yml: the default policy applies.
    assert not (clean_project / ".safeai" / "policy.yml").exists()
    assert _scan(clean_project, tmp_path) == 0


def test_existing_policy_file_is_used(clean_project, tmp_path):
    policy = tmp_path / "policy.yml"
    policy.write_text("version: '1'\ndefault_action: warn\npolicies: []\n",
                      encoding="utf-8")
    assert _scan(clean_project, tmp_path, "--policy", str(policy)) == 0


def test_escalation_pattern_points_to_the_escalation_gate(clean_project, tmp_path, capsys):
    assert _scan(clean_project, tmp_path, "--fail-on-rule", "ESC_*") == 2
    err = capsys.readouterr().err
    assert "--fail-on-rule ESC_*" in err
    assert "--fail-on-escalation" in err


def test_unknown_rule_pattern_warns(clean_project, tmp_path, capsys):
    # Not refused: a plugin or analyser may emit a rule ID that no rule
    # file declares, so an unknown pattern is not certainly a typo.
    assert _scan(clean_project, tmp_path, "--fail-on-rule", "NO_SUCH_RULE_*") == 0
    err = capsys.readouterr().err
    assert "warning: --fail-on-rule NO_SUCH_RULE_* matches no rule" in err


def test_known_rule_pattern_does_not_warn(clean_project, tmp_path, capsys):
    assert _scan(clean_project, tmp_path, "--fail-on-rule", "GOV_*", "DATA_LEAKAGE") == 0
    assert "--fail-on-rule" not in capsys.readouterr().err


@pytest.mark.parametrize("category", sorted(FAIL_ON_CATEGORY_PREFIXES))
def test_every_accepted_category_can_match_a_rule(category, clean_project, tmp_path):
    # ``data_leakage`` was accepted by the parser and mapped to nothing.
    # The parser's choices are the keys of this map, so each accepted
    # name has prefixes to match.
    assert FAIL_ON_CATEGORY_PREFIXES[category]
    # Accepted by the parser (not exit 2). ``mcp`` exits 1 even here: the
    # info-level inventory finding MCP_ASSETS_DISCOVERED carries the
    # prefix. That is a separate defect, recorded in the PR.
    assert _scan(clean_project, tmp_path, "--fail-on-category", category) in (0, 1)


def test_data_leakage_category_fails_on_a_data_leakage_finding(tmp_path):
    root = tmp_path / "leaky"
    root.mkdir()
    (root / "agent.py").write_text(
        "from langgraph.graph import StateGraph\n"
        'API_KEY = "sk-1234567890abcdefghij"\n'
        "graph = StateGraph(dict)\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.json"
    without = _scan(root, tmp_path, "--json", str(report))
    rule_ids = {f["rule_id"] for f in json.loads(report.read_text(encoding="utf-8"))["findings"]}
    assert "DATA_LEAKAGE" in rule_ids
    assert without == 0
    assert _scan(root, tmp_path, "--fail-on-category", "data_leakage") == 1
