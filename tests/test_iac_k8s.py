"""Tests for Kubernetes RBAC chain construction (v2.5 redesign)."""

import os

from safeai.iac.k8s import parse_k8s_file

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "iac", "kubernetes",
    "representative", "rbac.yaml")


def _read_fixture():
    with open(FIXTURE, encoding="utf-8") as handle:
        return handle.read()


def test_representative_fixture_chain():
    identities, grants, bindings, workloads, meta = parse_k8s_file(
        "rbac.yaml", _read_fixture())
    assert meta == {"unparsed": False}
    assert len(identities) == 1
    assert identities[0] == {
        "kind": "kubernetes_service_account", "name": "agent-sa",
        "namespace": "prod", "source_ref": "rbac.yaml:12",
    }
    assert len(grants) == 1
    grant = grants[0]
    assert grant["identity"] == {
        "kind": "kubernetes_service_account", "name": "agent-sa",
        "namespace": "prod"}
    assert grant["actions"]["values"] == ["get", "list"]
    assert grant["actions"]["resolution"] == "resolved"
    assert grant["resources"]["values"] == ["pods", "configmaps"]
    assert grant["scope"] == "prod"
    assert grant["family"] == "kubernetes"
    assert "via-RoleBinding:agent-binding" in grant["fidelity"]
    assert len(bindings) == 1
    assert bindings[0]["binding_kind"] == "RoleBinding"
    assert bindings[0]["binding_name"] == "agent-binding"
    assert bindings[0]["role"] == "Role/agent-reader"
    assert bindings[0]["notes"] == []
    assert workloads == []


def test_workload_refs_collected_for_linking():
    text = (
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata:\n  name: agent\n  namespace: prod\n"
        "spec:\n  template:\n    spec:\n"
        "      serviceAccountName: agent-sa\n"
        "      containers: []\n"
    )
    _, _, _, workloads, _ = parse_k8s_file("deploy.yaml", text)
    assert workloads == [{
        "kind": "Deployment", "name": "agent", "namespace": "prod",
        "service_account": "agent-sa", "source_file": "deploy.yaml",
        "line": 4,
    }]


def test_namespace_mismatch_breaks_chain():
    text = (
        "apiVersion: v1\nkind: ServiceAccount\n"
        "metadata:\n  name: sa\n  namespace: prod\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata:\n  name: r\n  namespace: dev\n"
        "rules:\n- apiGroups: ['']\n  resources: ['pods']\n"
        "  verbs: ['get']\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
        "metadata:\n  name: b\n  namespace: dev\n"
        "subjects:\n- kind: ServiceAccount\n  name: sa\n  namespace: dev\n"
        "roleRef:\n  kind: Role\n  name: r\n"
    )
    _, grants, bindings, _, _ = parse_k8s_file("ns.yaml", text)
    # Subject (dev/sa) has no matching collected SA (prod/sa): the
    # binding is recorded, but no grant is fabricated.
    assert grants == []
    assert len(bindings) == 1
    assert "subject-not-in-repo" in bindings[0]["notes"]


def test_duplicate_role_names_stay_isolated():
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata:\n  name: r\n  namespace: a\n"
        "rules:\n- apiGroups: ['']\n  resources: ['pods']\n"
        "  verbs: ['get']\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata:\n  name: r\n  namespace: b\n"
        "rules:\n- apiGroups: ['']\n  resources: ['secrets']\n"
        "  verbs: ['get']\n"
    )
    _, grants, _, _, _ = parse_k8s_file("dup.yaml", text)
    assert grants == []  # no bindings at all: no chains, no grants


def test_clusterrole_binding_uses_cluster_scope():
    text = (
        "apiVersion: v1\nkind: ServiceAccount\n"
        "metadata:\n  name: sa\n  namespace: prod\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata:\n  name: cr\n"
        "rules:\n- apiGroups: ['*']\n  resources: ['*']\n"
        "  verbs: ['*']\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n  name: crb\n"
        "subjects:\n- kind: ServiceAccount\n  name: sa\n  namespace: prod\n"
        "roleRef:\n  kind: ClusterRole\n  name: cr\n"
    )
    _, grants, bindings, _, _ = parse_k8s_file("c.yaml", text)
    assert len(grants) == 1
    assert grants[0]["scope"] == "*"
    assert grants[0]["actions"]["values"] == ["*"]
    assert "admin-wildcard" in grants[0]["actions"]["notes"]
    assert bindings[0]["role"] == "ClusterRole/cr"


def test_dangling_roleref_records_binding_only():
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
        "metadata:\n  name: b\n  namespace: prod\n"
        "subjects:\n- kind: ServiceAccount\n  name: sa\n  namespace: prod\n"
        "roleRef:\n  kind: Role\n  name: ghost\n"
    )
    _, grants, bindings, _, _ = parse_k8s_file("dangle.yaml", text)
    assert grants == []
    assert len(bindings) == 1


def test_non_user_subjects_skipped():
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: crb\n"
        "subjects:\n- kind: Group\n  name: devs\n"
        "roleRef:\n  kind: ClusterRole\n  name: cr\n"
    )
    _, grants, bindings, _, _ = parse_k8s_file("g.yaml", text)
    assert grants == []
    assert bindings == []


def test_non_rbac_and_malformed_never_raise():
    assert parse_k8s_file("d.yaml", "kind: Deployment\nspec: {}")[:4] == (
        [], [], [], [])
    assert parse_k8s_file("bad.yaml", ":\t: [\n{{{")[:4] == (
        [], [], [], [])
    assert parse_k8s_file("empty.yaml", "")[:4] == ([], [], [], [])
