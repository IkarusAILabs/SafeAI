"""Adversarial tests for IaC authority evidence (v2.5 redesign).

Each test attacks a specific confusion the correlator must resist:
name coincidence, namespace confusion, wildcard smuggling, unresolved
content masquerading as absence, malicious inputs, and evidence
injection into review output. All must resolve to strict verdicts
(MATCH only with evidence) or honest UNKNOWN — never a fabricated
MATCH, EXCESS, or MISMATCH.
"""

import os

from safeai.analysis.iac_correlation import correlate_iac_authority
from safeai.iac import k8s as k8s_mod
from safeai.iac import terraform as tf_mod
from safeai.report.pr_comment import sanitize_pr_text


def _grant(name, actions, resources, kind="aws_iam_role", ns="",
           res="resolved", f="main.tf"):
    return {
        "identity": {"kind": kind, "name": name, "namespace": ns},
        "actions": {"values": list(actions), "resolution": res,
                    "notes": []},
        "resources": {"values": list(resources), "resolution": res,
                      "notes": []},
        "scope": "", "source": "terraform", "source_file": f, "line": 1,
        "provenance": "repo-iac-observed", "fidelity": [],
        "family": "cloud",
    }


def _surface(*tool_caps):
    return {"tool_surface": [
        {"tool_key": key,
         "capabilities": [{"name": cap, "access_mode": "read"}]}
        for key, cap in tool_caps], "findings": []}


def _link(name, kind="aws_iam_role", ns=""):
    return {"agent": "<repo>",
            "identity": {"kind": kind, "name": name, "namespace": ns},
            "link_type": "explicit-config-reference", "confidence": "high",
            "evidence": [{"file": "config.yaml", "line": 1}]}


def _graph(grants=(), links=(), meta=None):
    return {"identities": [], "grants": list(grants),
            "grant_bindings": [], "agent_links": list(links),
            "meta": meta or {}}


def _verdicts(summary):
    return {v["domain"]: v["verdict"]
            for v in summary.get("verdicts") or []}


def test_partial_principal_name_never_links():
    report = _surface(("tool:x", "s3"))
    graph = _graph(grants=[_grant("agent-sa-prod", ["s3:GetObject"], ["*"])],
                   links=[_link("agent-sa")])
    _, summary = correlate_iac_authority(report, graph)
    # Link is for agent-sa; grant is for agent-sa-prod: no triple match.
    assert _verdicts(summary).get("aws:s3") in (None, "UNVERIFIED_LINK",
                                                "UNKNOWN")
    assert "aws:s3" not in _verdicts(summary) or \
        _verdicts(summary)["aws:s3"] != "MATCH"


def test_unrelated_service_grant_with_link_is_mismatch_not_match():
    report = _surface(("tool:x", "s3"))
    graph = _graph(grants=[_grant("agent-role", ["iam:PassRole"], ["*"])],
                   links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert _verdicts(summary)["aws:s3"] == "AUTHORITY_MISMATCH"
    assert _verdicts(summary)["aws:iam"] == "UNKNOWN"
    assert [f["rule_id"] for f in findings] == ["IAC_AUTHORITY_MISMATCH"]


def test_admin_wildcard_is_excess_not_match():
    # A bare "*" is provider-wide admin: it genuinely covers the read
    # requirement, so the verdict is EXCESS (observed breadth beyond
    # need) — never a quiet MATCH, never ignored.
    report = _surface(("tool:x", "s3"))
    graph = _graph(grants=[_grant("agent-role", ["*"], ["*"])],
                   links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert _verdicts(summary)["aws:s3"] == "EXCESS_AUTHORITY"
    assert findings[0]["rule_id"] == "IAC_EXCESS_AUTHORITY"


def test_service_wildcard_beyond_need_is_excess():
    report = _surface(("tool:x", "s3"))
    graph = _graph(grants=[_grant("agent-role", ["s3:*"], ["*"])],
                   links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert _verdicts(summary)["aws:s3"] == "EXCESS_AUTHORITY"
    assert findings[0]["rule_id"] == "IAC_EXCESS_AUTHORITY"


def test_count_meta_blocks_create_opaque_shadow():
    text = '''
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy" "inline" {
  count  = 2
  name   = "inline-${count.index}"
  role   = aws_iam_role.app.name
  policy = file("policy.json")
}
'''
    _, grants, _, _ = tf_mod.parse_terraform_file("c.tf", text)
    assert len(grants) == 1
    assert grants[0]["actions"]["resolution"] == "unresolved"


def test_malicious_yaml_tags_never_execute():
    text = (
        "kind: Role\nmetadata:\n  name: r\n"
        "rules: !!python/object:os.system [echo pwned]\n"
    )
    assert k8s_mod.parse_k8s_file("evil.yaml", text)[:4] == (
        [], [], [], [])


def test_deeply_nested_yaml_is_skipped_safely():
    depth = 500
    text = "kind: Role\nmetadata:\n  name: r\n" + "spec:\n" + "  a:\n" * depth
    _, grants, _, _, meta = k8s_mod.parse_k8s_file("deep.yaml", text)
    assert grants == []
    assert isinstance(meta.get("unparsed"), bool)


def test_huge_terraform_block_depth_capped():
    text = 'resource "aws_iam_policy" "p" {\n' + "  x {\n" * 60 + "  }\n" * 60
    identities, grants, _, _ = tf_mod.parse_terraform_file("huge.tf", text)
    assert grants == []
    assert identities == []


def test_binary_terraform_file_skipped(tmp_path):
    (tmp_path / "evil.tf").write_bytes(b"\x00\x01\x02{\xff\xfe" * 100)
    from safeai.iac import scan_iac
    graph, meta = scan_iac(str(tmp_path))
    assert graph["grants"] == []
    assert isinstance(meta, dict)


def test_scan_root_containment_predicate(tmp_path):
    from safeai.iac import _is_within_root
    inside = os.path.join(str(tmp_path), "sub", "main.tf")
    assert _is_within_root(str(tmp_path), str(tmp_path)) is True
    assert _is_within_root(str(tmp_path), os.path.dirname(
        os.path.dirname(str(tmp_path)))) is False
    assert _is_within_root(str(tmp_path), inside) is True


def test_excluded_paths_respected(tmp_path):
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "main.tf").write_text(
        'resource "aws_iam_role" "r" {\n  name = "r"\n}\n',
        encoding="utf-8")
    from safeai.iac import collect_iac_files
    assert collect_iac_files(str(tmp_path), ["infra"]) == ([], [])


def test_pr_comment_drops_control_characters():
    assert sanitize_pr_text("a\x00b\x1b[2Jc\x7fd") == "ab[2Jcd"
    assert sanitize_pr_text("line1\x00\nline2") == "line1 line2"
    assert sanitize_pr_text("caf\u00e9 \u2192 ok") == "caf\u00e9 \u2192 ok"


def test_generated_config_forces_unknown_not_mismatch():
    report = _surface(("tool:x", "s3"))
    graph = _graph(
        grants=[_grant("agent-role", [], [], res="unresolved")],
        links=[_link("agent-role")])
    findings, summary = correlate_iac_authority(report, graph)
    assert findings == []
    assert set(_verdicts(summary).values()) == {"UNKNOWN"}
