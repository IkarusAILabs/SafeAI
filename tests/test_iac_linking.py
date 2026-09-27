"""Tests for the Agent→Identity link resolver (v2.5 redesign)."""

from safeai.iac.linking import resolve_links
from safeai.iac.model import identity


def _sa(name, namespace="prod"):
    return identity("kubernetes_service_account", name,
                    namespace=namespace,
                    source_ref="rbac.yaml:1")


def _role(name):
    return identity("aws_iam_role", name, source_ref="main.tf:1")


def _workload(sa, namespace="prod", source_file="deploy.yaml"):
    return {"kind": "Deployment", "name": "agent", "namespace": namespace,
            "service_account": sa, "source_file": source_file, "line": 8}


def test_workload_service_account_links(tmp_path):
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        "  name: agent\n  namespace: prod\nspec:\n  template:\n"
        "    spec:\n      serviceAccountName: agent-sa\n",
        encoding="utf-8",
    )
    links, _meta = resolve_links(str(tmp_path), [_sa("agent-sa")],
                                 [_workload("agent-sa")])
    assert len(links) == 1
    link = links[0]
    assert link["agent"] == "<repo>"
    assert link["identity"]["name"] == "agent-sa"
    assert link["link_type"] == "workload-service-account"
    assert link["confidence"] == "high"
    assert link["evidence"][0]["file"] == "deploy.yaml"


def test_namespace_mismatch_does_not_link(tmp_path):
    links, _ = resolve_links(str(tmp_path), [_sa("agent-sa", namespace="prod")],
                             [_workload("agent-sa", namespace="dev")])
    assert links == []


def test_partial_name_match_does_not_link(tmp_path):
    (tmp_path / "deploy.yaml").write_text(
        "spec:\n  template:\n    spec:\n      serviceAccountName: agent-sa\n",
        encoding="utf-8",
    )
    links, _ = resolve_links(str(tmp_path), [_sa("agent-sa-prod")],
                             [_workload("agent-sa")])
    assert links == []


def test_config_role_arn_links(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "agent:\n  role_arn: arn:aws:iam::123456789012:role/agent-role\n",
        encoding="utf-8",
    )
    links, _ = resolve_links(str(tmp_path), [_role("agent-role")], [])
    assert len(links) == 1
    assert links[0]["link_type"] == "explicit-config-reference"
    assert links[0]["confidence"] == "high"
    assert links[0]["evidence"][0]["file"] == "config.yaml"


def test_config_bare_name_links_with_medium_confidence(tmp_path):
    (tmp_path / "config.json").write_text(
        '{"service_account": "agent-sa"}', encoding="utf-8")
    links, _ = resolve_links(str(tmp_path), [_sa("agent-sa")], [])
    assert len(links) == 1
    assert links[0]["confidence"] == "medium"


def test_tool_key_coincidence_alone_never_links(tmp_path):
    # A tool key equal to an identity name is NOT link evidence: the
    # resolver only reads workload manifests and structured identity
    # keys, so with no such files there is no link.
    links, _ = resolve_links(str(tmp_path), [_role("fetch-report")], [])
    assert links == []


def test_duplicate_sa_names_across_namespaces_isolate(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "spec:\n  serviceAccountName: sa\n", encoding="utf-8")
    idents = [_sa("sa", namespace="a"), _sa("sa", namespace="b")]
    links, _ = resolve_links(str(tmp_path), idents,
                             [_workload("sa", namespace="a")])
    assert len(links) == 1
    assert links[0]["identity"]["namespace"] == "a"


def test_resolver_never_raises(tmp_path):
    (tmp_path / "bad.yaml").write_text(":\t: [\n", encoding="utf-8")
    (tmp_path / "huge.bin").write_bytes(b"\x00\x01" * 10)
    links, meta = resolve_links(str(tmp_path), [_sa("x")],
                                [{"kind": "Deployment"}])
    assert links == []
    assert meta["links"] == 0
