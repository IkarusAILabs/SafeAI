"""Static SPIFFE workload identity (v2.10, plan items 2.10-1 to 2.10-5)."""

import json
import os

import pytest

from safeai.benchmark.compare import _compare_workload_identity
from safeai.engine.orchestrator import run_scan
from safeai.iac import spiffe
from safeai.iac.model import IDENTITY_KINDS, LINK_TYPES

TEMPLATE = ("spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}"
            "/sa/{{ .PodSpec.ServiceAccountName }}")

CONFIG = """apiVersion: spire.spiffe.io/v1alpha1
kind: ControllerManagerConfig
trustDomain: example.org
clusterName: prod
"""


def _registration(name="agents", selector=None, namespace_selector=None,
                  template=TEMPLATE, federates=None):
    spec = {"spiffeIDTemplate": template}
    if selector is not None:
        spec["podSelector"] = selector
    if namespace_selector is not None:
        spec["namespaceSelector"] = namespace_selector
    if federates:
        spec["federatesWith"] = federates
    return json.dumps({"apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterSPIFFEID",
                       "metadata": {"name": name}, "spec": spec})


def _deployment(name, namespace="agents", labels=None, account="agent-sa", env=None,
                volumes=None, kind="Deployment"):
    pod_spec = {"containers": [{"name": name, "image": "x", "env": env or []}]}
    if account:
        pod_spec["serviceAccountName"] = account
    if volumes:
        pod_spec["volumes"] = volumes
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    if kind == "Pod":
        metadata["labels"] = labels or {"role": "agent"}
        return json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": metadata,
                           "spec": pod_spec})
    return json.dumps({"apiVersion": "apps/v1", "kind": kind, "metadata": metadata,
                       "spec": {"template": {"metadata": {"labels": labels or {"role": "agent"}},
                                             "spec": pod_spec}}})


def _resolve(*documents):
    collection = spiffe.empty_collection()
    spiffe.collect_file(collection, "k8s/all.yaml", "\n---\n".join(documents))
    return spiffe.resolve_workload_identity(collection)


# --- 2.10-1 collector and templates ----------------------------------------


def test_identity_and_link_vocabulary_is_additive():
    assert "spiffe_id" in IDENTITY_KINDS
    assert "workload-spiffe-id" in LINK_TYPES
    assert IDENTITY_KINDS[:4] == ("aws_iam_role", "kubernetes_service_account",
                                  "kubernetes_user", "kubernetes_group")


def test_template_renders_from_config_and_manifest():
    block = _resolve(CONFIG, _registration(selector={"matchLabels": {"role": "agent"}}),
                     _deployment("planner"))
    (assignment,) = block["assignments"]
    assert assignment["spiffe_id"] == "spiffe://example.org/ns/agents/sa/agent-sa"
    assert assignment["resolution"] == "resolved"
    assert block["trust_domain"]["value"] == "example.org"
    assert block["identities"][0]["kind"] == "spiffe_id"
    assert block["links"][0]["link_type"] == "workload-spiffe-id"
    assert block["links"][0]["confidence"] == "high"


def test_missing_trust_domain_keeps_placeholder_partially_resolved():
    block = _resolve(_registration(), _deployment("planner"))
    (assignment,) = block["assignments"]
    assert assignment["resolution"] == "partially-resolved"
    assert assignment["spiffe_id"].startswith("spiffe://{{ .TrustDomain }}/ns/agents")
    assert assignment["unresolved_fields"] == [".TrustDomain"]
    assert block["trust_domain"]["resolution"] == "unresolved"
    assert any("no ControllerManagerConfig" in n for n in block["notes"])
    assert block["links"][0]["confidence"] == "medium"


@pytest.mark.parametrize(
    ("template", "kind", "expected", "resolution"),
    [
        ("spiffe://example.org/pod/{{ .PodMeta.Name }}", "Pod",
         "spiffe://example.org/pod/planner", "resolved"),
        ("spiffe://example.org/pod/{{ .PodMeta.Name }}", "Deployment",
         "spiffe://example.org/pod/{{ .PodMeta.Name }}", "partially-resolved"),
        ('spiffe://example.org/app/{{ index .PodMeta.Labels "role" }}', "Deployment",
         "spiffe://example.org/app/agent", "resolved"),
        ("spiffe://example.org/uid/{{ .PodMeta.UID }}", "Deployment",
         "spiffe://example.org/uid/{{ .PodMeta.UID }}", "partially-resolved"),
    ],
)
def test_template_fields(template, kind, expected, resolution):
    block = _resolve(_registration(template=template), _deployment("planner", kind=kind))
    (assignment,) = block["assignments"]
    assert (assignment["spiffe_id"], assignment["resolution"]) == (expected, resolution)


def test_template_without_scheme_is_unresolved_and_not_an_identity():
    block = _resolve(_registration(template="example.org/{{ .PodMeta.Namespace }}"),
                     _deployment("planner"))
    assert block["assignments"][0]["resolution"] == "unresolved"
    assert block["identities"] == [] and block["links"] == []


def test_config_embedded_in_configmap_and_conflicts():
    configmap = json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
                            "metadata": {"name": "cm", "namespace": "spire-system"},
                            "data": {"config.yaml": CONFIG}})
    block = _resolve(configmap, _registration(), _deployment("planner"))
    assert block["trust_domain"]["value"] == "example.org"
    other = CONFIG.replace("example.org", "other.org")
    block = _resolve(CONFIG, other, _registration(), _deployment("planner"))
    assert block["trust_domain"]["value"] == ""
    assert any("conflicting" in n for n in block["notes"])


def test_default_service_account_is_noted():
    block = _resolve(CONFIG, _registration(), _deployment("planner", account=None))
    (assignment,) = block["assignments"]
    assert assignment["service_account"] == "default"
    assert assignment["spiffe_id"].endswith("/sa/default")
    assert any("'default' ServiceAccount" in n for n in assignment["notes"])


# --- 2.10-2 selectors and linking --------------------------------------------


def test_ignored_namespaces_default_and_configured():
    block = _resolve(CONFIG, _registration(), _deployment("dns", namespace="kube-system"))
    assert block["assignments"] == [] and block["counts"]["workloads"] == 0
    configured = CONFIG + "ignoreNamespaces: [agents]\n"
    block = _resolve(configured, _registration(), _deployment("planner"),
                     _deployment("dns", namespace="kube-system"))
    assert [a["workload"] for a in block["assignments"]] == ["Deployment/kube-system/dns"]


@pytest.mark.parametrize(
    ("selector", "labels", "result"),
    [
        (None, {}, True),
        ({}, {"a": "1"}, True),
        ({"matchLabels": {"a": "1"}}, {"a": "1"}, True),
        ({"matchLabels": {"a": "1"}}, {"a": "2"}, False),
        ({"matchExpressions": [{"key": "a", "operator": "In", "values": ["1", "2"]}]},
         {"a": "2"}, True),
        ({"matchExpressions": [{"key": "a", "operator": "NotIn", "values": ["1"]}]},
         {"a": "1"}, False),
        ({"matchExpressions": [{"key": "a", "operator": "Exists"}]}, {}, False),
        ({"matchExpressions": [{"key": "a", "operator": "DoesNotExist"}]}, {}, True),
        ({"matchExpressions": [{"key": "a", "operator": "Gt", "values": ["1"]}]},
         {"a": "2"}, None),
        ("not-a-selector", {}, None),
    ],
)
def test_selector_evaluation(selector, labels, result):
    assert spiffe._selector_matches(selector, labels) is result


def test_incomplete_namespace_labels_are_undecidable_except_the_name_label():
    labels = {"kubernetes.io/metadata.name": "agents"}
    by_name = {"matchLabels": {"kubernetes.io/metadata.name": "agents"}}
    assert spiffe._selector_matches(by_name, labels, complete=False) is True
    assert spiffe._selector_matches({"matchLabels": {"trust": "high"}}, labels,
                                    complete=False) is None


def test_undecidable_selectors_create_no_identity():
    block = _resolve(CONFIG,
                     _registration(namespace_selector={"matchLabels": {"trust": "high"}}),
                     _deployment("triage", namespace="support"),
                     _deployment("scout", namespace=""))
    assert block["assignments"] == [] and block["links"] == []
    reasons = {u["workload"]: u["reason"] for u in block["unresolved"]}
    assert "Namespace not declared" in reasons["Deployment/support/triage"]
    assert "namespace not set" in reasons["Deployment/?/scout"]
    counts = block["counts"]
    assert (counts["unknown"], counts["unknown_undecidable_selector"],
            counts["unknown_rate"]) == (2, 2, 1.0)


def test_ambiguous_selector_fixture_preserves_each_unknown_reason():
    root = os.path.join(
        os.path.dirname(__file__), "benchmarks", "authority-pending", "identity",
        "spiffe_ambiguous_selector", "input",
    )
    collection = spiffe.empty_collection()
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root)
            with open(path, encoding="utf-8") as handle:
                spiffe.collect_file(collection, rel, handle.read())
    block = spiffe.resolve_workload_identity(collection)
    expected = {
        "Deployment/support/triage": "undecidable-selector",
        "Deployment/?/scout": "undecidable-selector",
        "Deployment/research/analyst": "no-matching-registration",
    }
    observed = {
        item["workload"]: item["unknown_reason"]
        for item in block["workloads"] if item["identity_state"] == "unknown"
    }
    assert observed == expected
    assert block["counts"]["unknown_undecidable_selector"] == 2
    assert block["counts"]["unknown_no_matching_registration"] == 1


def test_known_selector_non_match_is_distinct_from_undecidable():
    namespace = json.dumps({"apiVersion": "v1", "kind": "Namespace",
                            "metadata": {"name": "research",
                                         "labels": {"trust": "low"}}})
    block = _resolve(
        CONFIG,
        namespace,
        _registration(namespace_selector={"matchLabels": {"trust": "high"}}),
        _deployment("analyst", namespace="research"),
    )
    assert block["assignments"] == []
    state = next(
        item for item in block["workloads"]
        if item["workload"] == "Deployment/research/analyst"
    )
    assert state == {
        "workload": "Deployment/research/analyst",
        "service_account": "agent-sa",
        "identity_state": "unknown",
        "unknown_reason": "no-matching-registration",
    }
    assert block["counts"]["unknown_undecidable_selector"] == 0
    assert block["counts"]["unknown_no_matching_registration"] == 1


def test_declared_namespace_labels_decide_the_selector():
    namespace = json.dumps({"apiVersion": "v1", "kind": "Namespace",
                            "metadata": {"name": "agents", "labels": {"trust": "high"}}})
    block = _resolve(CONFIG, namespace,
                     _registration(namespace_selector={"matchLabels": {"trust": "high"}}),
                     _deployment("planner"))
    assert len(block["assignments"]) == 1


def test_breadth_and_undeclared_federation_are_recorded():
    block = _resolve(CONFIG, _registration(federates=["partner.example"]),
                     _deployment("planner"))
    (assignment,) = block["assignments"]
    assert assignment["selector_breadth"] == ["all-pods", "all-namespaces"]
    assert assignment["federates_with"] == ["partner.example"]
    assert any("partner.example" in n for n in assignment["notes"])
    assert block["registrations"][0]["selects_all_pods"] is True


def test_spiffe_links_stay_out_of_grant_correlation(tmp_path):
    """A SPIFFE ID holds no RBAC or IAM grant: it must not turn an UNKNOWN
    domain verdict into AUTHORITY_MISMATCH by counting as a link."""
    (tmp_path / "k8s.yaml").write_text(
        "\n---\n".join([CONFIG, _registration(), _deployment("planner")]), encoding="utf-8")
    report = run_scan(str(tmp_path))
    iac = report["iac_correlations"]
    assert iac["agent_identity_links"] == []
    assert iac["workload_identity"]["links"]
    assert all(v["verdict"] != "AUTHORITY_MISMATCH" for v in iac["verdicts"])


# --- 2.10-3 Istio AuthorizationPolicy ----------------------------------------


def _policy(name="allow", namespace="tools", selector=None, rules=None, action="ALLOW"):
    spec = {"action": action}
    if selector is not None:
        spec["selector"] = selector
    if rules is not None:
        spec["rules"] = rules
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return json.dumps({"apiVersion": "security.istio.io/v1", "kind": "AuthorizationPolicy",
                       "metadata": metadata, "spec": spec})


def test_ambiguous_fixture_retains_distinct_unknown_reasons():
    root = os.path.join(
        os.path.dirname(__file__), "benchmarks", "authority-pending", "identity",
        "spiffe_ambiguous_selector", "input",
    )
    collection = spiffe.empty_collection()
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root)
            with open(path, encoding="utf-8") as handle:
                spiffe.collect_file(collection, rel, handle.read())
    block = spiffe.resolve_workload_identity(collection)
    expected = {
        "Deployment/support/triage": "undecidable-selector",
        "Deployment/?/scout": "undecidable-selector",
        "Deployment/research/analyst": "no-matching-registration",
    }
    observed = {
        item["workload"]: item["unknown_reason"]
        for item in block["workloads"] if item["identity_state"] == "unknown"
    }
    assert observed == expected
    assert block["counts"]["unknown_undecidable_selector"] == 2
    assert block["counts"]["unknown_no_matching_registration"] == 1


def test_principals_map_to_assignments_and_negations_are_kept():
    rules = [{"from": [{"source": {
        "principals": ["example.org/ns/agents/*"],
        "notPrincipals": ["example.org/ns/agents/sa/agent-sa"],
        "requestPrincipals": ["issuer/subject"]}}]}]
    block = _resolve(CONFIG, _registration(), _deployment("planner"),
                     _deployment("search", namespace="tools", labels={"app": "search"},
                                 account="search-sa"),
                     _policy(selector={"matchLabels": {"app": "search"}}, rules=rules))
    (policy,) = block["authorization_policies"]
    assert [t["workload"] for t in policy["targets"]] == ["Deployment/tools/search"]
    by_principal = {(p["principal"], p["negated"]): p for p in policy["principals"]}
    allowed = by_principal[("example.org/ns/agents/*", False)]
    assert [c["workload"] for c in allowed["callers"]] == ["Deployment/agents/planner"]
    assert by_principal[("example.org/ns/agents/sa/agent-sa", True)]["callers"]
    assert any("requestPrincipals" in n for n in policy["notes"])


def test_policy_breadth_and_empty_rules():
    block = _resolve(CONFIG, _registration(), _deployment("planner"),
                     _policy(name="open", rules=[{"to": [{"operation": {"methods": ["GET"]}}]}]),
                     _policy(name="nothing", rules=[]),
                     _policy(name="mesh", namespace="istio-system",
                             rules=[{"from": [{"source": {"principals": ["*"]}}]}]))
    policies = {p["name"]: p for p in block["authorization_policies"]}
    assert policies["open"]["breadth"] == ["any-caller"]
    assert any("matches nothing" in n for n in policies["nothing"]["notes"])
    assert policies["mesh"]["mesh_wide"] is True
    assert policies["mesh"]["breadth"] == ["any-authenticated-caller"]
    assert [t["workload"] for t in policies["mesh"]["targets"]] == ["Deployment/agents/planner"]


@pytest.mark.parametrize(
    ("pattern", "value", "result"),
    [("*", "spiffe://a/b", True), ("spiffe://a/*", "spiffe://a/b", True),
     ("*/sa/x", "spiffe://a/ns/n/sa/x", True), ("spiffe://a/b", "spiffe://a/bc", False)],
)
def test_istio_string_match(pattern, value, result):
    assert spiffe._principal_matches(pattern, value) is result


# --- 2.10-4 static credential signal -----------------------------------------


SECRET_LITERAL = "ghp_do-not-leak-this-value-0123456789"


def _credential_repo(tmp_path):
    env = [{"name": "GITHUB_TOKEN", "value": SECRET_LITERAL},
           {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw"}}},
           {"name": "LOG_LEVEL", "value": "debug"}]
    volumes = [{"name": "creds", "secret": {"secretName": "cloud-creds"}}]
    (tmp_path / "k8s.yaml").write_text("\n---\n".join([
        CONFIG, _registration(selector={"matchLabels": {"role": "agent"}}),
        _deployment("coder", env=env, volumes=volumes),
        _deployment("legacy", labels={"app": "legacy"}, env=env),
    ]), encoding="utf-8")
    return run_scan(str(tmp_path))


def test_static_credential_finding_is_review_only_and_names_only(tmp_path):
    report = _credential_repo(tmp_path)
    findings = [f for f in report["findings"]
                if f["rule_id"] == spiffe.RULE_STATIC_CREDENTIAL]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["gateability"] == "review-only"
    assert finding["provenance_class"] == "repo-iac-observed"
    assert "GITHUB_TOKEN (literal)" in finding["evidence"]
    assert "DB_PASSWORD (secret)" in finding["evidence"]
    assert "cloud-creds (secret-volume)" in finding["evidence"]
    assert "LOG_LEVEL" not in finding["evidence"]
    (item,) = report["iac_correlations"]["workload_identity"]["static_credentials"]
    assert item["workload"] == "Deployment/agents/coder"
    assert SECRET_LITERAL not in json.dumps(report)


def test_static_credential_rule_is_registered_and_mapped():
    import yaml

    import safeai.rules
    from safeai.controls.mappings import RULE_MAPPINGS

    path = os.path.join(os.path.dirname(safeai.rules.__file__), "base_rules.yaml")
    with open(path, encoding="utf-8") as handle:
        rules = {r["id"]: r for r in yaml.safe_load(handle)}
    assert rules[spiffe.RULE_STATIC_CREDENTIAL]["severity"] == "low"
    assert RULE_MAPPINGS[spiffe.RULE_STATIC_CREDENTIAL]


# --- 2.10-5 harness ----------------------------------------------------------


def test_harness_compares_each_listed_key_exactly():
    block = _resolve(CONFIG, _registration(federates=["p.example"]), _deployment("planner"))
    good = {"assignments": [{"workload": "Deployment/agents/planner",
                             "spiffe_id": "spiffe://example.org/ns/agents/sa/agent-sa"}],
            "federations": [{"workload": "Deployment/agents/planner",
                             "trust_domain": "p.example"}],
            "unknown": []}
    failures = []
    part = _compare_workload_identity(good, block, failures)
    assert failures == [] and part["assignments"]["matched"] == 1
    assert "callers" not in part
    bad = dict(good, unknown=["Deployment/agents/planner"])
    failures = []
    _compare_workload_identity(bad, block, failures)
    assert failures and "unknown" in failures[0]


def test_no_yaml_means_an_empty_block(tmp_path):
    (tmp_path / "agent.py").write_text("print('hi')\n", encoding="utf-8")
    block = run_scan(str(tmp_path))["iac_correlations"]["workload_identity"]
    assert block["counts"]["workloads"] == 0 and block["counts"]["unknown_rate"] is None
    assert block["lane"] == "B"


def test_pending_identity_cases_exist():
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmarks",
                        "authority-pending", "identity")
    assert sorted(os.listdir(root)) == [
        "istio_principal_authorization", "spiffe_ambiguous_selector",
        "spiffe_federation_widening", "spiffe_template_resolution",
        "static_credential_with_spiffe", "workload_agent_links"]


def test_manifest_validates_and_carries_the_identity_rate(tmp_path):
    from safeai.cmd.cli import main
    from safeai.kya.contract import validate_manifest

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "k8s.yaml").write_text("\n---\n".join([
        CONFIG, _registration(selector={"matchLabels": {"role": "agent"}}),
        _deployment("planner"), _deployment("web", labels={"app": "web"})]),
        encoding="utf-8")
    manifest_path = tmp_path / "m.json"
    rc = main(["scan", str(repo), "--manifest", str(manifest_path),
               "--sarif", str(tmp_path / "r.sarif"), "--no-registry"])
    assert rc in (0, 1)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert validate_manifest(manifest)[0] == []
    rate = manifest["summary"]["evidence_metrics"]["rates"]["unknown_workload_identity_rate"]
    assert (rate["status"], rate["numerator"], rate["denominator"]) == ("measured", 1, 2)


def test_identity_rate_is_insufficient_without_workloads():
    from safeai.analysis.evidence_metrics import compute_evidence_metrics, summary_lines

    metrics = compute_evidence_metrics([], [], None, None)
    assert metrics["rates"]["unknown_workload_identity_rate"]["status"] == "insufficient_evidence"
    assert not any("SPIFFE" in line for line in summary_lines(metrics))
    metrics = compute_evidence_metrics([], [], None, {"counts": {"workloads": 4, "unknown": 1}})
    assert "Workloads with unknown SPIFFE identity: 25% (1/4)" in summary_lines(metrics)


def test_api_group_is_matched_exactly_not_by_prefix():
    lookalike = _registration().replace("spire.spiffe.io/v1alpha1",
                                        "spire.spiffe.io.example/v1")
    policy = _policy(rules=[]).replace("security.istio.io/v1", "security.istio.io.example/v1")
    block = _resolve(CONFIG, lookalike, policy, _deployment("planner"))
    assert block["registrations"] == [] and block["assignments"] == []
    assert block["authorization_policies"] == []
