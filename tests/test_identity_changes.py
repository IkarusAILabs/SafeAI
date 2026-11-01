"""Workload-identity change types (v2.10, plan items 2.11-3 and 2.11-4)."""

import json
import os

import pytest

from safeai.analysis.identity_diff import (
    IDENTITY_CHANGE_TYPES,
    compute_identity_changes,
)
from safeai.cmd.cli import main
from safeai.iac import spiffe
from safeai.kya.contract import AUTHORITY_DIMENSIONS
from safeai.report.pr_comment import render_pr_comment

CONFIG = """apiVersion: spire.spiffe.io/v1alpha1
kind: ControllerManagerConfig
trustDomain: example.org
"""
TEMPLATE = ("spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}"
            "/sa/{{ .PodSpec.ServiceAccountName }}")


def _registration(selector=None, federates=None, name="agents"):
    spec = {"spiffeIDTemplate": TEMPLATE}
    if selector:
        spec["podSelector"] = {"matchLabels": selector}
    if federates:
        spec["federatesWith"] = federates
    return json.dumps({"apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterSPIFFEID",
                       "metadata": {"name": name}, "spec": spec})


def _deployment(name, namespace="agents", labels=None, env=None):
    pod = {"serviceAccountName": f"{name}-sa",
           "containers": [{"name": name, "image": "x", "env": env or []}]}
    return json.dumps({"apiVersion": "apps/v1", "kind": "Deployment",
                       "metadata": {"name": name, "namespace": namespace},
                       "spec": {"template": {"metadata": {"labels": labels or {"role": "agent"}},
                                             "spec": pod}}})


def _policy(principals):
    return json.dumps({
        "apiVersion": "security.istio.io/v1", "kind": "AuthorizationPolicy",
        "metadata": {"name": "pay", "namespace": "finance"},
        "spec": {"selector": {"matchLabels": {"app": "pay"}}, "action": "ALLOW",
                 "rules": [{"from": [{"source": {"principals": principals}}]}]}})


def _report(*documents):
    collection = spiffe.empty_collection()
    spiffe.collect_file(collection, "k8s.yaml", "\n---\n".join(documents))
    return {"iac_correlations": {
        "workload_identity": spiffe.resolve_workload_identity(collection)}}


def _types(before, after):
    result = compute_identity_changes(after, before)
    return [(c["type"], c["workload"], c["subject"]) for c in result["changes"]]


PLANNER = _deployment("planner")
WEB = _deployment("web", namespace="frontend", labels={"app": "web"})
PAY = _deployment("pay", namespace="finance", labels={"app": "pay"})


def test_change_types_map_onto_existing_dimensions():
    assert set(IDENTITY_CHANGE_TYPES.values()) <= set(AUTHORITY_DIMENSIONS)


def test_baseline_without_block_is_not_assessed():
    result = compute_identity_changes(_report(CONFIG, _registration(), PLANNER), {})
    assert result["baseline_available"] is False and result["changes"] == []
    assert "before v2.10" in result["notes"][0]


def test_identical_scans_have_no_changes():
    docs = (CONFIG, _registration({"role": "agent"}, ["p.example"]), PLANNER, PAY,
            _policy(["example.org/ns/agents/sa/planner-sa"]))
    assert _types(_report(*docs), _report(*reversed(docs))) == []


def test_identity_added_and_broadened():
    before = _report(CONFIG, _registration({"role": "agent"}), PLANNER, WEB)
    after = _report(CONFIG, _registration(), PLANNER, WEB)
    assert _types(before, after) == [
        ("IDENTITY_ADDED", "Deployment/frontend/web",
         "spiffe://example.org/ns/frontend/sa/web-sa"),
        ("IDENTITY_BROADENED", "", "agents"),
    ]
    broadened = compute_identity_changes(after, before)["changes"][1]
    assert "every pod" in broadened["detail"]


def test_identity_removed_with_and_without_the_workload():
    before = _report(CONFIG, _registration(), PLANNER)
    removed = compute_identity_changes(_report(CONFIG, PLANNER), before)["changes"]
    assert [(c["type"], c["detail"].endswith("(workload removed)")) for c in removed] == [
        ("IDENTITY_REMOVED", False)]
    gone = compute_identity_changes(_report(CONFIG, _registration()), before)["changes"]
    assert gone[0]["detail"].endswith("(workload removed)")


def test_federation_added_maps_to_destinations():
    before = _report(CONFIG, _registration(), PLANNER)
    after = _report(CONFIG, _registration(federates=["p.example"]), PLANNER)
    (change,) = compute_identity_changes(after, before)["changes"]
    assert (change["type"], change["dimension"], change["subject"]) == (
        "FEDERATION_ADDED", "destinations", "p.example")


def test_caller_added_and_negated_principals_ignored():
    base = (CONFIG, _registration({"role": "agent"}), PLANNER, PAY)
    before = _report(*base, _policy(["example.org/ns/finance/sa/other"]))
    after = _report(*base, _policy(["example.org/ns/finance/sa/other",
                                    "example.org/ns/agents/sa/planner-sa"]))
    assert _types(before, after) == [
        ("CALLER_ADDED", "Deployment/agents/planner", "finance/pay")]


def test_static_credential_only_counts_beside_an_identity():
    env = [{"name": "API_TOKEN", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]
    before = _report(CONFIG, _registration({"role": "agent"}), PLANNER, WEB)
    after = _report(CONFIG, _registration({"role": "agent"}),
                    _deployment("planner", env=env),
                    _deployment("web", namespace="frontend", labels={"app": "web"}, env=env))
    changes = compute_identity_changes(after, before)["changes"]
    assert [(c["type"], c["workload"], c["dimension"]) for c in changes] == [
        ("STATIC_CREDENTIAL_ADDED", "Deployment/agents/planner", "credential")]


def test_every_change_is_review_only():
    before = _report(CONFIG, _registration({"role": "agent"}), PLANNER, WEB)
    after = _report(CONFIG, _registration(federates=["p.example"]), PLANNER, WEB)
    for change in compute_identity_changes(after, before)["changes"]:
        assert change["gateability"] == "review-only"
        assert change["provenance_class"] == "repo-iac-observed"


# --- end to end: CLI baseline, gates, PR comment ----------------------------


def _write(root, *documents):
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "k8s.yaml"), "w", encoding="utf-8") as handle:
        handle.write("\n---\n".join(documents))


@pytest.mark.parametrize("baseline_kind", ["manifest", "json"])
def test_identity_changes_through_cli_never_gate(tmp_path, baseline_kind):
    base, cur = str(tmp_path / "base"), str(tmp_path / "cur")
    _write(base, CONFIG, _registration({"role": "agent"}), PLANNER, WEB)
    secret = "xoxb-never-in-output-123"
    _write(cur, CONFIG, _registration(federates=["p.example"]),
           _deployment("planner", env=[{"name": "SLACK_TOKEN", "value": secret}]), WEB)
    baseline = str(tmp_path / f"baseline.{baseline_kind}.json")
    flag = "--manifest" if baseline_kind == "manifest" else "--json"
    assert main(["scan", base, flag, baseline, "--no-registry"]) in (0, 1)
    report_path = str(tmp_path / "current.json")
    rc = main(["scan", cur, "--baseline", baseline, "--json", report_path,
               "--fail-on-authority-change", "material", "--fail-on-escalation", "medium",
               "--no-registry"])
    assert rc == 0
    with open(report_path, encoding="utf-8") as handle:
        text = handle.read()
    assert secret not in text
    block = json.loads(text)["capability_diff"]["workload_identity_changes"]
    assert block["baseline_available"] is True
    assert set(block["counts"]) == {"FEDERATION_ADDED", "IDENTITY_ADDED",
                                    "IDENTITY_BROADENED", "STATIC_CREDENTIAL_ADDED"}
    comment = render_pr_comment(json.loads(text))
    assert "Workload identity changes" in comment and "STATIC_CREDENTIAL_ADDED" in comment
    assert secret not in comment


def test_pr_comment_section_is_bounded():
    from safeai.report.pr_comment import _identity_changes

    changes = [{"type": "IDENTITY_ADDED", "workload": f"Deployment/a/w{i}",
                "detail": "x"} for i in range(20)]
    lines = _identity_changes({"workload_identity_changes": {"changes": changes}}, budget=7)
    assert len(lines) == 7 and lines[-1] == "- +16 more identity changes"
    assert _identity_changes({}, budget=7) == []


def test_harness_compares_identity_changes():
    from safeai.benchmark.compare import compare_case

    before = _report(CONFIG, _registration(), PLANNER)
    after = _report(CONFIG, _registration(federates=["p.example"]), PLANNER)
    after["capability_diff"] = {"workload_identity_changes":
                                compute_identity_changes(after, before)}
    good = {"identity_changes": [{"type": "FEDERATION_ADDED",
                                  "workload": "Deployment/agents/planner",
                                  "subject": "p.example"}]}
    bad = {"identity_changes": []}
    assert not [f for f in compare_case(good, after, before)["failures"]
                if "identity_changes" in f]
    assert [f for f in compare_case(bad, after, before)["failures"]
            if "identity_changes" in f]


def test_first_spire_adoption_against_a_yaml_free_manifest(tmp_path):
    """A v2.10+ manifest always carries the block, so adopting SPIRE in a repo
    that had no YAML reads as IDENTITY_ADDED, not as 'not assessed'."""
    base, cur = tmp_path / "base", tmp_path / "cur"
    base.mkdir()
    (base / "agent.py").write_text("print('hi')\n", encoding="utf-8")
    _write(str(cur), CONFIG, _registration(), PLANNER)
    manifest = str(tmp_path / "m.json")
    assert main(["scan", str(base), "--manifest", manifest, "--no-registry"]) in (0, 1)
    with open(manifest, encoding="utf-8") as handle:
        assert "workload_identity" in json.load(handle)["iac_correlations"]
    report_path = str(tmp_path / "r.json")
    main(["scan", str(cur), "--baseline", manifest, "--json", report_path, "--no-registry"])
    with open(report_path, encoding="utf-8") as handle:
        block = json.load(handle)["capability_diff"]["workload_identity_changes"]
    assert block["baseline_available"] is True
    assert [c["type"] for c in block["changes"]] == ["IDENTITY_ADDED"]
