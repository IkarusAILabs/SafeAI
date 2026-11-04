"""Separation of Duties: Kubernetes RBAC pairs and the organisation catalogue (v2.14)."""

import json

import pytest

from safeai.analysis.sod import (
    SodCatalogueError,
    _k8s_roles,
    analyze_separation_of_duties,
    load_org_pairs,
)
from safeai.cmd.cli import main


def _grant(name, verbs, resources, ns="agents"):
    return {"identity": {"kind": "kubernetes_service_account", "name": name, "namespace": ns},
            "actions": {"values": verbs}, "resources": {"values": resources},
            "source_file": "rbac.yaml", "line": 3}


def _pairs(report, org=None):
    _findings, summary = analyze_separation_of_duties(report, org)
    return sorted((c["holder"], c["pair"]) for c in summary["conflicts"])


@pytest.mark.parametrize(("item", "roles"), [
    ("create certificatesigningrequests", {("request", ("certificatesigningrequest",)),
                                           ("act", None)}),
    ("update certificatesigningrequests/approval", {("approve", ("certificatesigningrequest",)),
                                                    ("act", None)}),
    ("approve signers", {("approve", ("certificatesigningrequest",))}),
    ("bind clusterroles", {("self-grant", None)}),
    ("escalate roles", {("self-grant", None)}),
    ("impersonate serviceaccounts", {("self-grant", None)}),
    ("create rolebindings", {("act", None)}),
    ("delete events", {("erase-audit", None)}),
    ("get secrets", set()),
    ("* *", set()),
    ("delete *", set()),
    ("* events", set()),
])
def test_kubernetes_item_roles(item, roles):
    assert _k8s_roles(item) == roles


def test_kubernetes_holders_are_service_accounts_per_namespace():
    report = {"iac_correlations": {"grants": [
        _grant("bot", ["create"], ["certificatesigningrequests"]),
        _grant("bot", ["update"], ["certificatesigningrequests/approval"]),
        _grant("bot", ["update"], ["certificatesigningrequests/approval"], ns="other"),
    ]}}
    assert _pairs(report) == [("kubernetes_service_account:agents/bot", "SOD-REQUEST-APPROVE")]


def _config(tmp_path, text):
    (tmp_path / ".safeai").mkdir(exist_ok=True)
    (tmp_path / ".safeai" / "config.yml").write_text(text, encoding="utf-8")
    return str(tmp_path)


def test_organisation_pairs_match_globs_case_insensitively(tmp_path):
    pairs = load_org_pairs(_config(tmp_path, (
        "project_id: demo\nseparation_of_duties:\n  pairs:\n"
        "    - id: ORG-DEPLOY-APPROVE\n      title: deploy and approve\n"
        "      first: ['Deploy_*']\n      second: ['approve_release']\n")))
    assert pairs[0]["evidence"] == {"file": ".safeai/config.yml", "line": 4}
    report = {"tool_surface": [{"tool_key": "mcp_server:rel", "capabilities": [
        {"name": "mcp_tool:deploy_api", "evidence": [{"path": ".mcp.json", "line": 2}]},
        {"name": "mcp_tool:approve_release", "evidence": []}]}]}
    findings, summary = analyze_separation_of_duties(report, pairs)
    assert [(c["pair"], c["catalogue"]) for c in summary["conflicts"]] == [
        ("ORG-DEPLOY-APPROVE", "organisation")]
    assert "ORG-DEPLOY-APPROVE" in summary["pairs"]
    assert summary["organisation_pairs"][0]["first"] == ["Deploy_*"]
    assert findings[0]["message"] == "mcp_server:rel can deploy and approve"
    assert "catalogue=.safeai/config.yml" in findings[0]["evidence"]
    assert findings[0]["gateability"] == "review-only"


def test_without_a_catalogue_the_summary_is_unchanged(tmp_path):
    assert load_org_pairs(str(tmp_path)) == []
    assert load_org_pairs(_config(tmp_path, "project_id: demo\n")) == []
    _findings, summary = analyze_separation_of_duties({})
    assert set(summary) == {"lane", "pairs", "conflicts", "holders_checked"}


@pytest.mark.parametrize("body", [
    "separation_of_duties: []\n",
    "separation_of_duties:\n  pairs: [x]\n",
    "separation_of_duties:\n  pairs:\n    - {id: SOD-SELF-GRANT, title: t, first: [a], second: [b]}\n",
    "separation_of_duties:\n  pairs:\n    - {id: org-lower, title: t, first: [a], second: [b]}\n",
    "separation_of_duties:\n  pairs:\n    - {id: ORG-A, title: t, first: [], second: [b]}\n",
    "separation_of_duties:\n  pairs:\n    - {id: ORG-A, first: [a], second: [b]}\n",
    ("separation_of_duties:\n  pairs:\n    - {id: ORG-A, title: t, first: [a], second: [b]}\n"
     "    - {id: ORG-A, title: t, first: [a], second: [b]}\n"),
])
def test_malformed_catalogue_is_refused(tmp_path, body):
    with pytest.raises(SodCatalogueError):
        load_org_pairs(_config(tmp_path, body))


def test_scan_reports_a_malformed_catalogue_and_skips_it(tmp_path):
    root = _config(tmp_path, "separation_of_duties:\n  pairs: nope\n")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": {
        "command": "x", "tools": ["create_invoice", "approve_invoice"]}}}), encoding="utf-8")
    out = tmp_path / "r.json"
    main(["scan", root, "--no-registry", "--json", str(out), "--sarif",
          str(tmp_path / "r.sarif")])
    summary = json.loads(out.read_text(encoding="utf-8"))["separation_of_duties"]
    assert summary["notes"][0].endswith("organisation pairs not checked")
    assert [c["pair"] for c in summary["conflicts"]] == ["SOD-REQUEST-APPROVE"]
