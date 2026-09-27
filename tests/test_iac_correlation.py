"""Tests for the graph correlation engine (v2.5 redesign)."""

from safeai.analysis.iac_correlation import (
    RULE_EXCESS,
    RULE_MISMATCH,
    RULE_UNVERIFIED,
    correlate_iac_authority,
)


def _grant(name, actions, resources, kind="aws_iam_role", ns="",
           source="terraform", res="resolved", f="main.tf", line=10):
    return {
        "identity": {"kind": kind, "name": name, "namespace": ns},
        "actions": {"values": list(actions), "resolution": res,
                    "notes": []},
        "resources": {"values": list(resources), "resolution": res,
                      "notes": []},
        "scope": "", "source": source, "source_file": f, "line": line,
        "provenance": "repo-iac-observed", "fidelity": [],
        "family": "cloud",
    }


def _surface(*tool_caps):
    return {"tool_surface": [
        {"tool_key": key,
         "capabilities": [{"name": cap, "access_mode": mode}]}
        for key, cap, mode in tool_caps], "findings": []}


def _link(name, kind="aws_iam_role", ns="", conf="high"):
    return {"agent": "<repo>",
            "identity": {"kind": kind, "name": name, "namespace": ns},
            "link_type": "explicit-config-reference", "confidence": conf,
            "evidence": [{"file": "config.yaml", "line": 3}]}


def _graph(grants=(), links=(), identities=(), bindings=(), meta=None):
    return {"identities": list(identities), "grants": list(grants),
            "grant_bindings": list(bindings), "agent_links": list(links),
            "meta": meta or {}}


def _verdicts(summary):
    return {v["domain"]: v for v in summary.get("verdicts") or []}


def test_empty_graph_is_silent():
    findings, summary = correlate_iac_authority(_surface(), _graph())
    assert findings == []
    assert summary["verdicts"] == []
    assert summary["lane"] == "B"
    assert summary["schema_version"] == 2


def test_match_requires_link_and_compatible_grant():
    report = _surface(("tool:x", "s3", "read"))
    graph = _graph(
        grants=[_grant("agent-role", ["s3:GetObject"],
                       ["arn:aws:s3:::b/*"])],
        links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert findings == []
    verdict = _verdicts(summary)["aws:s3"]
    assert verdict["verdict"] == "MATCH"
    assert verdict["resolution"] == "resolved"
    assert verdict["declared_evidence_refs"]
    assert verdict["grant_evidence_refs"] == ["main.tf:10"]
    assert verdict["link_evidence_refs"] == ["config.yaml:3"]


def test_match_medium_link_is_partially_resolved():
    report = _surface(("tool:x", "s3", "read"))
    graph = _graph(
        grants=[_grant("agent-role", ["s3:GetObject"], ["*"])],
        links=[_link("agent-role", conf="medium")])
    _, summary = correlate_iac_authority(report, graph)
    verdict = _verdicts(summary)["aws:s3"]
    assert verdict["verdict"] == "MATCH"
    assert verdict["resolution"] == "partially-resolved"


def test_excess_for_linked_wildcard_beyond_need():
    report = _surface(("tool:x", "s3", "read"))
    graph = _graph(grants=[_grant("agent-role", ["s3:*"], ["*"])],
                   links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_EXCESS
    assert findings[0]["severity"] == "medium"
    assert findings[0]["gateability"] == "review-only"
    assert _verdicts(summary)["aws:s3"]["verdict"] == "EXCESS_AUTHORITY"


def test_mismatch_for_linked_identity_without_cover():
    report = _surface(("tool:x", "s3", "write"))
    graph = _graph(
        grants=[_grant("agent-role", ["s3:GetObject"], ["*"])],
        links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_MISMATCH
    assert _verdicts(summary)["aws:s3"]["verdict"] == "AUTHORITY_MISMATCH"


def test_absence_without_link_is_unknown_not_mismatch():
    report = _surface(("tool:x", "s3", "write"))
    findings, summary = correlate_iac_authority(report, _graph())
    assert findings == []
    verdict = _verdicts(summary).get("aws:s3")
    assert verdict is None or verdict["verdict"] == "UNKNOWN"


def test_unrelated_grant_is_never_excess():
    report = _surface(("tool:x", "s3", "read"))
    graph = _graph(
        grants=[_grant("agent-role", ["iam:PassRole"],
                       ["arn:aws:iam::1:role/other"])],
        links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert [f["rule_id"] for f in findings] != [RULE_EXCESS]
    iam_verdict = _verdicts(summary).get("aws:iam")
    assert iam_verdict is None or iam_verdict["verdict"] == "UNKNOWN"
    # The s3 requirement with no s3 grant but a link: mismatch is
    # legitimate here (authoritative: no modules, no unparsed files).
    assert _verdicts(summary)["aws:s3"]["verdict"] == "AUTHORITY_MISMATCH"


def test_unverified_link_is_default_without_evidence():
    report = _surface(("tool:x", "s3", "read"))
    graph = _graph(grants=[_grant("agent-role", ["s3:GetObject"], ["*"])])
    findings, summary = correlate_iac_authority(report, graph)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_UNVERIFIED
    assert findings[0]["gateability"] == "review-only"
    assert _verdicts(summary)["aws:s3"]["verdict"] == "UNVERIFIED_LINK"


def test_unresolved_material_forces_unknown():
    report = _surface(("tool:x", "s3", "read"))
    graph = _graph(
        grants=[_grant("agent-role", [], [], res="unresolved")],
        links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert findings == []
    verdict = _verdicts(summary)["aws:s3"]
    assert verdict["verdict"] == "UNKNOWN"
    assert verdict["resolution"] == "unresolved"


def test_modules_degrade_mismatch_to_unknown():
    report = _surface(("tool:x", "s3", "write"))
    graph = _graph(links=[_link("agent-role")],
                   meta={"has_modules": True})
    findings, summary = correlate_iac_authority(report, graph)
    assert findings == []
    assert _verdicts(summary)["aws:s3"]["verdict"] == "UNKNOWN"


def test_kubernetes_chain_match():
    report = _surface(("tool:x", "kubernetes", "read"))
    identities = [{"kind": "kubernetes_service_account", "name": "sa",
                   "namespace": "prod", "source_ref": "rbac.yaml:1"}]
    graph = _graph(
        grants=[_grant("sa", ["get", "list"], ["pods"],
                       kind="kubernetes_service_account", ns="prod",
                       source="kubernetes", f="rbac.yaml")],
        links=[_link("sa", kind="kubernetes_service_account", ns="prod")],
        identities=identities)
    findings, summary = correlate_iac_authority(report, graph)
    assert findings == []
    verdict = _verdicts(summary)["kubernetes:*"]
    assert verdict["verdict"] == "MATCH"


def test_namespace_isolation_breaks_link():
    report = _surface(("tool:x", "kubernetes", "read"))
    graph = _graph(
        grants=[_grant("sa", ["get"], ["pods"],
                       kind="kubernetes_service_account", ns="prod",
                       source="kubernetes", f="rbac.yaml")],
        links=[_link("sa", kind="kubernetes_service_account", ns="dev")])
    findings, summary = correlate_iac_authority(report, graph)
    assert _verdicts(summary)["kubernetes:*"]["verdict"] == "UNVERIFIED_LINK"
    assert findings[0]["rule_id"] == RULE_UNVERIFIED


def test_all_findings_review_only_with_evidence():
    report = _surface(("tool:x", "s3", "read"))
    graph = _graph(grants=[_grant("agent-role", ["s3:*"], ["*"])],
                   links=[_link("agent-role")])
    findings, _ = correlate_iac_authority(report, graph)
    assert findings
    for finding in findings:
        assert finding["gateability"] == "review-only"
        assert finding["provenance_class"] == "repo-iac-observed"


def test_end_to_end_excess_with_link(tmp_path):
    from safeai.engine.orchestrator import ScanOrchestrator

    (tmp_path / "mcp.json").write_text(
        '{"mcp": {"version": "1.1", '
        '"servers": [{"name": "storage"}], '
        '"tools": [{"name": "s3_list_buckets", '
        '"description": "List S3 buckets."}]}}',
        encoding="utf-8",
    )
    (tmp_path / "config.yaml").write_text(
        "agent:\n  role_arn: arn:aws:iam::123456789012:role/agent-role\n",
        encoding="utf-8",
    )
    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_role" "agent_role" {\n'
        '  name = "agent-role"\n'
        '}\n'
        'resource "aws_iam_policy" "wide" {\n'
        '  name = "wide"\n'
        '  statement {\n'
        '    actions   = ["s3:*"]\n'
        '    resources = ["*"]\n'
        '  }\n'
        '}\n'
        'resource "aws_iam_role_policy_attachment" "a" {\n'
        '  role       = aws_iam_role.agent_role.name\n'
        '  policy_arn = aws_iam_policy.wide.arn\n'
        '}\n',
        encoding="utf-8",
    )
    report = ScanOrchestrator(str(tmp_path)).run()
    iac = report.get("iac_correlations") or {}
    assert iac.get("lane") == "B"
    assert iac.get("schema_version") == 2
    assert iac["counts"].get("agent_links") == 1
    rule_ids = [f.get("rule_id") for f in report.get("findings") or []]
    assert RULE_EXCESS in rule_ids
    for finding in report["findings"]:
        if str(finding.get("rule_id") or "").startswith("IAC_"):
            assert finding["gateability"] == "review-only"


def test_end_to_end_unknown_without_declared_match(tmp_path):
    from safeai.engine.orchestrator import ScanOrchestrator

    (tmp_path / "main.tf").write_text(
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
    report = ScanOrchestrator(str(tmp_path)).run()
    iac = report.get("iac_correlations") or {}
    assert iac["counts"]["grants"] == 1
    # Grants without any declared counterpart are recorded UNKNOWN —
    # never excess, never findings.
    assert iac["counts"].get("unknown") == 1
    rule_ids = [f.get("rule_id") for f in report.get("findings") or []]
    assert not [r for r in rule_ids if str(r).startswith("IAC_")]
