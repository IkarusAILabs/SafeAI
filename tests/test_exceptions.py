"""Tests for file-backed policy exception records (WS4, v2.4)."""

import os

import pytest

from safeai.cmd.cli import main
from safeai.kya.exceptions import (
    ExceptionError,
    evaluate_exceptions,
    load_exceptions,
)


def _write(path, content):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _entry(**overrides):
    base = {
        "exception_id": "SAFEAI-EXC-0042",
        "finding_or_policy": "GOV_APPROVAL_MISSING",
        "risk_owner": "eng-director@example.com",
        "rationale": "Read-only internal retrieval; no side effects.",
    }
    base.update(overrides)
    return base


def _finding(rule_id="GOV_APPROVAL_MISSING"):
    return {"rule_id": rule_id, "severity": "medium", "status": "new"}


class TestLoadExceptions:
    def test_missing_file_yields_empty(self, tmp_path):
        entries, warnings = load_exceptions(str(tmp_path / "nope.yml"))
        assert entries == [] and warnings == []

    def test_valid_file(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: SAFEAI-EXC-0042
    finding_or_policy: GOV_APPROVAL_MISSING
    scope:
      repository: acme/agent
      commit_range: "v2.4.0..v2.4.3"
    risk_owner: eng-director@example.com
    rationale: "Read-only internal retrieval."
    compensating_controls:
      - Human review before customer response
    expires_at: "2099-01-31"
    review_trigger:
      - New external tool
""")
        entries, _ = load_exceptions(path)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["exception_id"] == "SAFEAI-EXC-0042"
        assert entry["expired"] is False
        assert entry["compensating_controls"] == ["Human review before customer response"]
        assert entry["review_trigger"] == ["New external tool"]

    def test_expired_flagged(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E1
    finding_or_policy: CAP_shell
    risk_owner: owner@example.com
    rationale: "Legacy."
    expires_at: "2000-01-31"
""")
        entries, _ = load_exceptions(path)
        assert entries[0]["expired"] is True

    def test_missing_required_field_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E1
    finding_or_policy: CAP_shell
    rationale: "No owner."
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)

    def test_bad_date_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E1
    finding_or_policy: CAP_shell
    risk_owner: o@example.com
    rationale: "x"
    expires_at: "31-01-2099"
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)

    def test_explicit_target_type(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E2
    target_type: escalation
    target_id: ESC_MCP_SERVER_ADDED
    risk_owner: o@example.com
    rationale: "Reviewed."
""")
        entries, _ = load_exceptions(path)
        assert entries[0]["target_type"] == "escalation"
        assert entries[0]["target_id"] == "ESC_MCP_SERVER_ADDED"

    def test_legacy_key_auto_classified(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E3
    finding_or_policy: CAP_shell
    risk_owner: o@example.com
    rationale: "Legacy file."
""")
        entries, _ = load_exceptions(path)
        assert entries[0]["target_type"] == "unspecified"
        assert entries[0]["target_id"] == "CAP_shell"

    def test_unknown_target_type_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E4
    target_type: vibe
    target_id: X
    risk_owner: o@example.com
    rationale: "x"
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)

    def test_split_target_keys_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E5
    target_type: finding
    risk_owner: o@example.com
    rationale: "x"
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)


class TestEvaluateExceptions:
    def test_active(self):
        evaluations = evaluate_exceptions([_entry()], [_finding()], [])
        assert evaluations[0]["state"] == "active"
        assert evaluations[0]["warnings"] == []

    def test_expired(self):
        entry = _entry()
        entry["expired"] = True
        entry["expires_at"] = "2000-01-31"
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "expired"
        assert evaluations[0]["warnings"]

    def test_stale_when_nothing_matches(self):
        evaluations = evaluate_exceptions([_entry()], [_finding("CAP_http")], [])
        assert evaluations[0]["state"] == "stale"
        assert evaluations[0]["warnings"]

    def test_escalation_id_matches(self):
        evaluations = evaluate_exceptions(
            [_entry(finding_or_policy="ESC_MCP_SERVER_ADDED")], [],
            [{"id": "ESC_MCP_SERVER_ADDED", "severity": "high"}])
        assert evaluations[0]["state"] == "active"

    def test_policy_target_matches_policy_id(self):
        entry = _entry()
        entry.update({"target_type": "policy", "target_id": "deny-shell"})
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], policy_ids=["deny-shell"])
        assert evaluations[0]["state"] == "active"

    def test_policy_target_stale_without_match(self):
        entry = _entry()
        entry.update({"target_type": "policy", "target_id": "deny-shell"})
        evaluations = evaluate_exceptions([entry], [_finding()], [], policy_ids=[])
        assert evaluations[0]["state"] == "stale"

    def test_authority_change_target_matches_tool(self):
        entry = _entry()
        entry.update({"target_type": "authority_change", "target_id": "tool:x"})
        evaluations = evaluate_exceptions(
            [entry], [], [], changed_tool_keys=["tool:x"])
        assert evaluations[0]["state"] == "active"

    def test_invalid_target_type_state(self):
        entry = _entry()
        entry.update({"target_type": "vibe", "target_id": "X"})
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "invalid"
        assert evaluations[0]["warnings"]

    def test_review_trigger_is_metadata_only(self):
        entry = _entry()
        entry["review_trigger"] = ["New external tool"]
        entry["scope"] = {"repository": None, "commit_range": "v1..v2"}
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "active"

    def test_scope_mismatch_state(self):
        entry = _entry()
        entry["scope"] = {"repository": "acme/other", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], project_identities={"acme/agent"})
        assert evaluations[0]["state"] == "scope-mismatch"
        assert evaluations[0]["warnings"]

    def test_scope_match_stays_active(self):
        entry = _entry()
        entry["scope"] = {"repository": "acme/agent", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], project_identities={"acme/agent"})
        assert evaluations[0]["state"] == "active"

    def test_unverified_scope_recorded_not_enforced(self):
        entry = _entry()
        entry["scope"] = {"repository": "acme/agent", "commit_range": None}
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "active"
        assert evaluations[0]["warnings"]


class TestExceptionsCli:
    def _exceptions_file(self, root, body):
        safeai_dir = os.path.join(root, ".safeai")
        os.makedirs(safeai_dir, exist_ok=True)
        return _write(os.path.join(safeai_dir, "exceptions.yml"), body)

    def test_warn_by_default(self, kya_project, tmp_path, capsys):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-STALE
    finding_or_policy: RULE_THAT_NEVER_FIRES
    risk_owner: o@example.com
    rationale: "Nothing matches."
""")
        rc = main(["scan", kya_project["root"],
                   "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry"])
        assert rc in (0, 1)  # warn-only: never fails the scan by itself
        assert "matches no current" in capsys.readouterr().err

    def test_strict_exceptions_fails(self, kya_project, tmp_path):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-STALE
    finding_or_policy: RULE_THAT_NEVER_FIRES
    risk_owner: o@example.com
    rationale: "Nothing matches."
""")
        rc = main(["scan", kya_project["root"],
                   "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry",
                   "--strict-exceptions"])
        assert rc == 1

    def test_active_exception_no_warning(self, kya_project, tmp_path, capsys):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-OK
    finding_or_policy: CAP_subprocess_shell
    risk_owner: o@example.com
    rationale: "Reviewed; constrained usage."
    expires_at: "2099-01-31"
""")
        main(["scan", kya_project["root"],
              "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry"])
        assert "E-OK" not in capsys.readouterr().err

    def test_invalid_file_is_hard_error(self, kya_project, tmp_path):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-BAD
    finding_or_policy: CAP_shell
    rationale: "No owner."
""")
        with __import__("pytest").raises(SystemExit):
            main(["scan", kya_project["root"],
                  "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry"])


# ---------------------------------------------------------------------------
# Security review: exception scope-escape paths (#196)
#
# Exceptions are a suppression mechanism, so the question is not "does a valid
# exception work" but "can an exception reach a finding outside the scope it
# declares". One class per criterion in the issue.
# ---------------------------------------------------------------------------
class TestTargetScopeCannotEscape:
    """Criterion 1: traversal- and glob-shaped target_ids never activate.

    This holds by construction rather than by validation: ``_live_targets``
    builds sets of concrete ids and the match is ``target_id in live[...]``,
    with no globbing and no path joining anywhere on the path. These tests
    exist so that adding ``fnmatch`` or a path resolve later cannot reopen it
    while the suite stays green.
    """

    @pytest.mark.parametrize("hostile", [
        "../GOV_APPROVAL_MISSING",
        "../../GOV_APPROVAL_MISSING",
        "../../../etc/passwd",
        "/etc/passwd",
        "/GOV_APPROVAL_MISSING",
        "..\\GOV_APPROVAL_MISSING",
        "..\\..\\GOV_APPROVAL_MISSING",
        "./GOV_APPROVAL_MISSING",
        "GOV_APPROVAL_MISSING/../GOV_APPROVAL_MISSING",
        "*",
        "**",
        "GOV_*",
        "GOV_APPROVAL_*",
        "?OV_APPROVAL_MISSING",
        "[GOV]_APPROVAL_MISSING",
    ])
    def test_hostile_target_id_never_activates(self, hostile):
        entry = _entry(target_type="finding", target_id=hostile)
        del entry["finding_or_policy"]
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] != "active", (
            f"{hostile!r} suppressed a finding it does not name"
        )
        assert evaluations[0]["state"] in ("stale", "invalid")

    def test_the_exact_id_does_activate(self):
        """Control: without this the parametrised test above could pass
        because nothing ever activates."""
        entry = _entry(target_type="finding", target_id="GOV_APPROVAL_MISSING")
        del entry["finding_or_policy"]
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "active"

    def test_a_glob_does_not_widen_across_namespaces(self):
        """A wildcard must not pick up policy or escalation ids either."""
        entry = _entry(target_type="policy", target_id="*")
        del entry["finding_or_policy"]
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [{"id": "ESC-1"}], policy_ids=["POL-1"])
        assert evaluations[0]["state"] == "stale"


class TestLegacyKeyScopeBoundary:
    """Criterion 2: how far a legacy ``finding_or_policy`` key reaches.

    It reaches wider than an explicit target by design - ``_live_targets``
    sets the ``unspecified`` namespace to ``finding | policy | escalation``,
    which the docstring calls the historical union. That is pinned here rather
    than changed, together with the bound that matters: the union excludes
    ``authority_change``, so a legacy key cannot suppress an authority change.
    """

    def test_legacy_key_reaches_an_escalation_that_an_explicit_finding_does_not(self):
        escalations = [{"id": "ESC-1"}]
        legacy = evaluate_exceptions(
            [_entry(finding_or_policy="ESC-1")], [_finding()], escalations)
        explicit = _entry(target_type="finding", target_id="ESC-1")
        del explicit["finding_or_policy"]
        typed = evaluate_exceptions([explicit], [_finding()], escalations)

        assert legacy[0]["state"] == "active"
        assert typed[0]["state"] == "stale", (
            "an explicit finding target must not reach the escalation namespace"
        )

    def test_legacy_key_cannot_reach_an_authority_change(self):
        """The bound on the union. If authority_change ever joins it, a legacy
        entry would start suppressing authority changes silently."""
        evaluations = evaluate_exceptions(
            [_entry(finding_or_policy="tool:acme:write")], [], [],
            changed_tool_keys=["tool:acme:write"])
        assert evaluations[0]["state"] == "stale"

    def test_an_explicit_authority_change_target_still_works(self):
        """Control for the test above."""
        entry = _entry(target_type="authority_change", target_id="tool:acme:write")
        del entry["finding_or_policy"]
        evaluations = evaluate_exceptions(
            [entry], [], [], changed_tool_keys=["tool:acme:write"])
        assert evaluations[0]["state"] == "active"


class TestNonActiveStatesAreNeverCoercedToActive:
    """Criterion 3: nothing downstream of the state decision can revive an
    entry. The scope block is the only code that writes ``state`` after the
    expired/stale/active decision, and it only ever writes
    ``scope-mismatch``."""

    def test_expired_never_reads_as_active(self):
        entry = _entry(expired=True, expires_at="2020-01-01")
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "expired"

    def test_expired_plus_scope_mismatch_is_still_not_active(self):
        """Both are non-active, so which wins is a reporting question rather
        than a security one - but it must not come out active, and the expiry
        must still be stated in the warnings."""
        entry = _entry(expired=True, expires_at="2020-01-01")
        entry["scope"] = {"repository": "acme/other", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], project_identities={"acme/agent"})

        assert evaluations[0]["state"] != "active"
        assert evaluations[0]["state"] == "scope-mismatch"
        assert any("expired" in w for w in evaluations[0]["warnings"]), (
            "the expiry disappeared from the record entirely"
        )

    def test_stale_plus_unverified_scope_is_not_active(self):
        entry = _entry(finding_or_policy="RULE_THAT_NEVER_FIRES")
        entry["scope"] = {"repository": "acme/agent", "commit_range": None}
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "stale"

    def test_unknown_target_type_can_never_activate(self):
        entry = _entry(target_type="file", target_id="safeai/kya/exceptions.py")
        del entry["finding_or_policy"]
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "invalid"


class TestRepositoryScopeIsIdentityGated:
    """Criterion 4: an exception naming another repository must not apply.

    It is gated whenever the scanned project has any identity, which through
    the CLI it always does - ``_resolve_identity`` runs immediately before
    ``_evaluate_exceptions`` and ``resolve_project_id`` never returns ``None``
    (it falls back to a persisted ``local-<uuid>``). ``evaluate_exceptions``
    is public and takes no identity, though, so the no-identity path is
    reachable by a caller; ``scope_verified`` records it.
    """

    def test_another_repository_is_refused_when_identity_is_known(self):
        entry = _entry()
        entry["scope"] = {"repository": "someone-else/repo", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], project_identities={"acme/agent"})
        assert evaluations[0]["state"] == "scope-mismatch"
        assert evaluations[0]["scope_verified"] is True

    def test_one_matching_identity_out_of_several_is_enough(self):
        entry = _entry()
        entry["scope"] = {"repository": "acme/agent", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [],
            project_identities={"proj-7", "agent", "acme/agent"})
        assert evaluations[0]["state"] == "active"
        assert evaluations[0]["scope_verified"] is True

    def test_unverifiable_scope_is_recorded_as_unverified(self):
        """The fail-open, stated rather than hidden: with no identity an
        exception naming ANOTHER repository still suppresses. The state is
        unchanged for compatibility; ``scope_verified`` is what the gate
        reads."""
        entry = _entry()
        entry["scope"] = {"repository": "someone-else/repo", "commit_range": None}
        evaluations = evaluate_exceptions([entry], [_finding()], [])

        assert evaluations[0]["state"] == "active"
        assert evaluations[0]["scope_verified"] is False
        assert any("another repository" in w for w in evaluations[0]["warnings"])

    def test_no_declared_scope_reports_nothing_to_verify(self):
        evaluations = evaluate_exceptions([_entry()], [_finding()], [])
        assert evaluations[0]["scope_verified"] is None

    def test_scope_verified_is_present_on_every_record(self):
        """The gate reads the key unconditionally, including on the invalid
        early-exit path."""
        bad = _entry(target_type="file", target_id="x")
        del bad["finding_or_policy"]
        evaluations = evaluate_exceptions([bad, _entry()], [_finding()], [])
        assert all("scope_verified" in e for e in evaluations)


class TestStrictExceptionsRefusesUnverifiedScope:
    """An operator asking for strict exceptions is asking not to be suppressed
    by something unverified. Before #196 an unverifiable declared scope stayed
    ``active``, so it reached no gate at all."""

    def _bad(self, evaluations):
        """The production predicate itself, imported rather than restated.

        Reimplementing it here would let the production line be deleted with
        these tests still green.
        """
        from safeai.cmd.postprocess import gated_exception_evaluations

        return gated_exception_evaluations(evaluations)

    def test_an_unverified_scope_is_gated(self):
        entry = _entry()
        entry["scope"] = {"repository": "someone-else/repo", "commit_range": None}
        evaluations = evaluate_exceptions([entry], [_finding()], [])

        assert evaluations[0]["state"] == "active"
        assert self._bad(evaluations), (
            "an active-but-unverified scope reached no gate at all"
        )

    def test_a_verified_active_exception_is_not_gated(self):
        """Control: strict mode must not start refusing healthy exceptions."""
        entry = _entry()
        entry["scope"] = {"repository": "acme/agent", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], project_identities={"acme/agent"})

        assert evaluations[0]["state"] == "active"
        assert not self._bad(evaluations)

    def test_an_exception_with_no_scope_is_not_gated(self):
        evaluations = evaluate_exceptions([_entry()], [_finding()], [])
        assert evaluations[0]["state"] == "active"
        assert not self._bad(evaluations)

    def test_a_healthy_exception_does_not_trip_strict_mode(
            self, kya_project, tmp_path, capsys):
        """Control at the CLI: widening the gate must not start refusing
        healthy exceptions. The scan's exit code reflects its findings, so the
        assertion is on the strict-exceptions refusal itself."""
        safeai_dir = os.path.join(kya_project["root"], ".safeai")
        os.makedirs(safeai_dir, exist_ok=True)
        _write(os.path.join(safeai_dir, "exceptions.yml"), """
exceptions:
  - exception_id: E-OK
    finding_or_policy: CAP_subprocess_shell
    risk_owner: o@example.com
    rationale: "Reviewed; constrained usage."
    expires_at: "2099-01-31"
""")
        main(["scan", kya_project["root"],
              "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry",
              "--strict-exceptions"])
        assert "--strict-exceptions is set" not in capsys.readouterr().err
