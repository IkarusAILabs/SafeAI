"""Static-vs-runtime experiment tooling (research/collab/static-vs-runtime).

The runtime observations here are built by the test from each scenario's
*proposed* requests. They are test inputs for the outcome rules, not
measurements: no runtime was run.
"""

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "collab_evidence", REPO / "scripts" / "collab_evidence.py")
ce = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ce)

SCENARIO_DIRS = ce.scenario_dirs()
IDS = [d.name for d in SCENARIO_DIRS]


def _as_if_runtime(scenario, principal=True):
    """Observations a harness would report if every proposed request behaved as proposed."""
    observations = []
    for n, request in enumerate(scenario["runtime"]["requests"], start=1):
        permit = request["expect_decision"] == "PERMIT"
        observations.append({
            "request_id": f"req-{n}",
            "agent": request["agent"],
            "principal": f"principal:{request['agent']}" if principal else None,
            "tool": request["tool"],
            "decision": request["expect_decision"],
            "execution": "executed" if permit else "not_executed",
            "effect": "observed" if permit else "not_observed",
        })
    return {"spec_version": ce.SPEC_VERSION, "scenario": scenario["id"],
            "producer": {"tool": "test", "kind": "runtime"}, "observations": observations}


def test_there_are_six_scenarios():
    assert IDS == ["s0_direct_tool", "s1_delegated_access", "s2_attenuated_delegation",
                   "s3_attempted_escalation", "s4_runtime_denial",
                   "s5_incomplete_identity_link"]


@pytest.mark.parametrize("directory", SCENARIO_DIRS, ids=IDS)
def test_scenario_is_valid_and_still_a_draft(directory):
    scenario = ce.load_scenario(directory)
    # Ground truth needs a human from each project; until then it says so.
    assert scenario["annotation"] == {"basis": "ai_assisted_draft",
                                      "status": "pending_human_review", "reviewers": []}


@pytest.mark.parametrize("directory", SCENARIO_DIRS, ids=IDS)
def test_committed_static_record_matches_a_fresh_scan(directory):
    committed = json.loads((ce.STATIC_RECORDS / f"{directory.name}.json")
                           .read_text(encoding="utf-8"))
    fresh = ce.scan_scenario(directory)
    assert ce._without_version(committed) == ce._without_version(fresh)
    assert ce._dump(fresh) == ce._dump(ce.scan_scenario(directory))  # deterministic
    assert committed["limits"] == list(ce.STATIC_LIMITS)


@pytest.mark.parametrize("directory", SCENARIO_DIRS, ids=IDS)
def test_static_record_establishes_the_draft_intent(directory):
    scenario = ce.load_scenario(directory)
    cover = ce.intent_coverage(scenario, ce.scan_scenario(directory))
    assert cover["missing"] == [] and cover["not_in_intent"] == []
    record = ce.scan_scenario(directory)
    scopes = {(c["from"], c["to"]): c["scope"]
              for c in record["claims"] if c["kind"] == "delegation"}
    assert scopes == {(d["from"], d["to"]): d["scope"]
                      for d in scenario["intent"]["delegations"]}


@pytest.mark.parametrize("directory", SCENARIO_DIRS, ids=IDS)
def test_expected_outcomes_follow_from_the_proposed_requests(directory):
    scenario = ce.load_scenario(directory)
    identity_case = directory.name == "s5_incomplete_identity_link"
    result = ce.compare(ce.scan_scenario(directory),
                        _as_if_runtime(scenario, principal=not identity_case))
    got = {(r["agent"], r["tool"]): (r["outcome"], r["reason"]) for r in result["rows"]}
    want = {(e["agent"], e["tool"]): (e["outcome"], e["reason"])
            for e in scenario["expected_outcomes"]}
    assert got == want
    assert result["summary"]["units"] == len(want)


def test_identity_scenario_reports_the_unlinked_role():
    record = ce.scan_scenario(ce.SCENARIOS / "s5_incomplete_identity_link")
    assert [i["name"] for i in record["identities"]] == ["reporting-role"]
    link = next(c for c in record["claims"] if c["kind"] == "identity_link")
    assert (link["status"], link["principal"], link["reason"]) == (
        "unresolved", None, "identity_present_not_linked")


CLAIM = {"id": "tool_access:a:t", "status": "established", "via": []}
OBS = {"request_id": "r", "agent": "a", "tool": "t", "principal": "p", "decision": "PERMIT",
       "execution": "executed", "effect": "observed"}


@pytest.mark.parametrize(("claim", "changes", "expected"), [
    (CLAIM, None, ("insufficient_evidence", "not_tested")),
    (CLAIM, {"principal": None}, ("insufficient_evidence", "principal_unresolved")),
    ({**CLAIM, "status": "unresolved"}, {}, ("insufficient_evidence", "static_unresolved")),
    (CLAIM, {}, ("agreement", "potential_exercised")),
    # A PERMIT alone does not establish that an effect occurred.
    (CLAIM, {"effect": "unknown"}, ("insufficient_evidence", "effect_unverified")),
    (CLAIM, {"execution": "not_executed", "effect": "not_observed"},
     ("insufficient_evidence", "effect_unverified")),
    # Potential authority plus a denial is not a disagreement.
    (CLAIM, {"decision": "DENY", "execution": "not_executed", "effect": "not_observed"},
     ("agreement", "potential_restricted")),
    (None, {"decision": "DENY", "execution": "not_executed", "effect": "not_observed"},
     ("agreement", "absent_and_denied")),
    (CLAIM, {"decision": "DENY", "effect": "observed"},
     ("disagreement", "denied_but_effect_observed")),
    (None, {}, ("disagreement", "permitted_without_static_path")),
])
def test_outcome_rules(claim, changes, expected):
    obs = None if changes is None else {**OBS, **changes}
    assert ce.classify(claim, obs) == expected


def test_unresolved_units_stay_in_the_denominator():
    rows = [{"outcome": "agreement", "reason": "potential_exercised"},
            {"outcome": "insufficient_evidence", "reason": "not_tested"},
            {"outcome": "insufficient_evidence", "reason": "principal_unresolved"},
            {"outcome": "disagreement", "reason": "permitted_without_static_path"}]
    summary = ce.summarize(rows)
    assert summary["units"] == 4 and summary["resolved"] == 2
    assert summary["agreement_over_resolved"] == "1/2"
    assert summary["agreement_over_all_units"] == "1/4"


def test_invalid_runtime_records_are_refused():
    static = ce.scan_scenario(ce.SCENARIOS / "s0_direct_tool")
    bad = {"spec_version": ce.SPEC_VERSION, "scenario": "s0_direct_tool",
           "producer": {"tool": "x", "kind": "runtime"},
           "observations": [{"request_id": "r1", "agent": "clerk", "tool": "read_invoice",
                             "principal": "p", "decision": "MAYBE"},
                            {"request_id": "r1", "agent": "clerk", "tool": "read_invoice",
                             "principal": "p", "decision": "PERMIT"}]}
    with pytest.raises(ce.CollabError) as exc:
        ce.compare(static, bad)
    assert "decision not in" in str(exc.value) and "duplicate request_id" in str(exc.value)
    other = {**bad, "scenario": "s4_runtime_denial", "observations": []}
    with pytest.raises(ce.CollabError, match="different scenarios"):
        ce.compare(static, other)


def test_cli_check_and_compare(tmp_path, capsys):
    assert ce.main(["check"]) == 0
    scenario = ce.load_scenario(ce.SCENARIOS / "s3_attempted_escalation")
    (tmp_path / "s3.json").write_text(json.dumps(_as_if_runtime(scenario)), encoding="utf-8")
    out = tmp_path / "comparison.json"
    assert ce.main(["compare", "--runtime", str(tmp_path), "--json", str(out)]) == 0
    text = capsys.readouterr().out
    assert "agreement (potential_restricted)" in text
    assert "Agreement over resolved units: 3/3; over all units: 3/3" in text
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["units"] == 3
    assert ce.main(["compare", "--runtime", str(tmp_path / "missing")]) == 2
