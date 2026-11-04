"""v2.12: approval metadata (2.12-3), agent identity field (2.12-2) and the
experimental Agent Authority Attestation (2.12-1)."""

import json
import os
from datetime import date

import pytest

from safeai.cmd.cli import main
from safeai.kya import agent_identity, approval, attestation
from safeai.kya.contract import (
    APPROVAL_STATES,
    CONTRACT_VERSION,
    IDENTITY_PROVENANCE_CLASSES,
    IDENTITY_STATES,
    validate_manifest,
)
from safeai.kya.exceptions import ExceptionError, load_exceptions
from safeai.kya.suppressions import SuppressionError, load_suppressions

TODAY = date(2026, 11, 2)

SPIFFE_YAML = """\
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: agents
spec:
  spiffeIDTemplate: "spiffe://example.org/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}"
  podSelector:
    matchLabels:
      app: drafter
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: drafter
  namespace: agents
spec:
  template:
    metadata:
      labels:
        app: drafter
    spec:
      serviceAccountName: drafter
      containers:
        - name: c
          image: x
"""

DRAFTER_ID = "spiffe://example.org/ns/agents/sa/drafter"


def _write(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _repo(tmp_path, extra=None):
    repo = tmp_path / "repo"
    _write(repo, {
        ".claude/settings.json": json.dumps({"permissions": {"allow": ["Read"]}}),
        ".claude/agents/drafter.md": ("---\nname: drafter\n"
                                      "tools: Edit(src/**), Bash(gh pr merge:*)\n---\nx\n"),
        **(extra or {}),
    })
    return repo


def _declare(*pairs):
    lines = ["agent_identities:"]
    for agent, identifier in pairs:
        lines += [f"  - agent: {agent}", f"    id: {identifier}"]
    return "\n".join(lines) + "\n"


def _scan(tmp_path, repo, *flags):
    manifest = tmp_path / "m.json"
    statement = tmp_path / "a.json"
    rc = main(["scan", str(repo), "--manifest", str(manifest),
               "--experimental-attestation", str(statement), "--no-registry", *flags])
    return rc, manifest, statement


# --- 2.12-3 approval metadata ---------------------------------------------------


def test_approval_block_is_normalized():
    parsed = approval.parse_approval(
        {"approved_by": "bob@example.org", "approved_at": "2026-10-30",
         "escalation_owner": "ciso@example.org"}, expires=date(2027, 1, 1), today=TODAY)
    assert parsed == {"approved_by": "bob@example.org", "approved_at": "2026-10-30",
                      "escalation_owner": "ciso@example.org"}
    assert approval.parse_approval(None) is None


@pytest.mark.parametrize(("raw", "message"), [
    ({"approved_at": "2026-10-30"}, "approved_by is required"),
    ({"approved_by": "b"}, "approved_at is required"),
    ({"approved_by": "b", "approved_at": "30/10/2026"}, "ISO date"),
    ({"approved_by": "b", "approved_at": "2026-12-01"}, "in the future"),
    ({"approved_by": "b", "approved_at": "2026-10-30", "approver": "x"}, "unknown field"),
    ("bob", "must be a mapping"),
])
def test_malformed_approval_is_rejected(raw, message):
    with pytest.raises(approval.ApprovalError, match=message):
        approval.parse_approval(raw, today=TODAY)


def test_approval_after_expiry_is_rejected():
    with pytest.raises(approval.ApprovalError, match="after the expiry"):
        approval.parse_approval({"approved_by": "b", "approved_at": "2026-10-30"},
                                expires=date(2026, 10, 1), today=TODAY)


@pytest.mark.parametrize(("block", "owner", "state"), [
    (None, "alice", "unrecorded"),
    ({"approved_by": "Alice "}, "alice", "self-approved"),
    ({"approved_by": "bob"}, "alice", "approved"),
])
def test_approval_state(block, owner, state):
    assert approval.approval_state(block, owner) == state
    assert state in APPROVAL_STATES


def _exceptions_file(tmp_path, approval_yaml):
    path = tmp_path / "exceptions.yml"
    path.write_text(
        "exceptions:\n  - exception_id: E1\n    target_type: finding\n"
        "    target_id: SOD_CONFLICTING_AUTHORITY\n    risk_owner: alice@example.org\n"
        "    rationale: reviewed\n" + approval_yaml, encoding="utf-8")
    return path


def test_exception_loader_wraps_approval_errors(tmp_path):
    path = _exceptions_file(tmp_path, "    approval:\n      approved_at: 2026-10-30\n")
    with pytest.raises(ExceptionError, match="'E1': approval.approved_by is required"):
        load_exceptions(str(path))


def test_suppression_carries_approval(tmp_path):
    path = tmp_path / "suppressions.yml"
    path.write_text(
        "suppressions:\n  - rule_id: X\n    reason: fp\n    owner: alice\n"
        "    created: 2026-10-01\n    approval:\n      approved_by: bob\n"
        "      approved_at: 2026-10-02\n", encoding="utf-8")
    (entry,), _ = load_suppressions(str(path))
    assert entry["approval_state"] == "approved"
    assert entry["approval"]["approved_by"] == "bob"
    path.write_text(path.read_text(encoding="utf-8").replace("2026-10-02", "nope"),
                    encoding="utf-8")
    with pytest.raises(SuppressionError, match="Suppression #1: approval.approved_at"):
        load_suppressions(str(path))


@pytest.mark.parametrize(("approver", "rc"), [("bob@example.org", 0),
                                              ("alice@example.org", 1)])
def test_require_approval_gates_on_independent_approval(tmp_path, approver, rc):
    repo = _repo(tmp_path)
    (repo / ".safeai").mkdir()
    _exceptions_file(repo / ".safeai", (f"    approval:\n      approved_by: {approver}\n"
                                        "      approved_at: 2026-10-30\n"))
    assert main(["scan", str(repo), "--no-registry", "--require-approval"]) == rc
    # Without the flag the decision is only recorded.
    out = tmp_path / "r.json"
    assert main(["scan", str(repo), "--no-registry", "--json", str(out)]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    (evaluation,) = report["exception_evaluations"]
    assert evaluation["state"] == "active"
    assert evaluation["approval_state"] == ("approved" if rc == 0 else "self-approved")


# --- 2.12-2 identity field --------------------------------------------------------


def test_declared_identity_validation(tmp_path):
    _write(tmp_path, {".safeai/config.yml": _declare(("a", "https://example.org/a"))})
    with pytest.raises(agent_identity.AgentIdentityError, match="SPIFFE ID"):
        agent_identity.load_declared_identities(str(tmp_path))
    _write(tmp_path, {".safeai/config.yml": "agent_identities:\n  - agent: a\n"})
    with pytest.raises(agent_identity.AgentIdentityError, match="both 'agent' and 'id'"):
        agent_identity.load_declared_identities(str(tmp_path))
    _write(tmp_path, {".safeai/config.yml": _declare(("a", "wimse://example.org/a"))})
    (item,) = agent_identity.load_declared_identities(str(tmp_path))
    assert (item["scheme"], item["evidence"]) == (
        "wimse", [{"file": ".safeai/config.yml", "line": 3}])


def _identity(report_agents, name):
    return next(a["workload_identity"] for a in report_agents if a["name"] == name)


def test_identity_states(tmp_path):
    # Declared and issued by the repository's own ClusterSPIFFEID.
    repo = _repo(tmp_path, {"k8s/spiffe.yaml": SPIFFE_YAML,
                            ".safeai/config.yml": _declare(("drafter", DRAFTER_ID))})
    _, manifest, _ = _scan(tmp_path, repo)
    agents = json.loads(manifest.read_text(encoding="utf-8"))["agents"]
    drafter = _identity(agents, "drafter")
    assert drafter["state"] == "corroborated"
    assert [i["provenance_class"] for i in drafter["identifiers"]] == [
        "declared", "repo-iac-observed"]
    assert drafter["identifiers"][1]["workloads"] == ["Deployment/agents/drafter"]
    assert drafter["runtime_verified"] is False
    # The observed SPIFFE ID is never attached to an agent that declared nothing.
    other = next(a["workload_identity"] for a in agents if a["name"] != "drafter")
    assert other["state"] == "unknown"
    assert "not attributed to individual agents" in other["unknown_reason"]


def test_declared_but_not_observed(tmp_path):
    repo = _repo(tmp_path, {".safeai/config.yml": _declare(("drafter", DRAFTER_ID))})
    _, manifest, _ = _scan(tmp_path, repo)
    drafter = _identity(json.loads(manifest.read_text(encoding="utf-8"))["agents"], "drafter")
    assert drafter["state"] == "declared"
    assert [i["provenance_class"] for i in drafter["identifiers"]] == ["declared"]


def test_unmatched_declaration_is_a_warning(tmp_path, capsys):
    repo = _repo(tmp_path, {".safeai/config.yml": _declare(("ghost", DRAFTER_ID))})
    _scan(tmp_path, repo)
    assert "names agent 'ghost', which this scan did not report" in capsys.readouterr().err


def test_validator_accepts_reserved_and_rejects_unknown_provenance():
    def doc(provenance, state="declared"):
        return {"agents": [{"agent_id": "a", "workload_identity": {
            "state": state, "identifiers": [{"id": DRAFTER_ID,
                                             "provenance_class": provenance}]}}]}
    def agent_errors(document):
        errors, _ = validate_manifest(document)
        return [e for e in errors if e.startswith("$.agents")]
    assert agent_errors(doc("runtime-unverified")) == []
    assert agent_errors(doc("guessed"))
    assert agent_errors(doc("declared", state="maybe"))
    assert "runtime-unverified" in IDENTITY_PROVENANCE_CLASSES
    assert "runtime-unverified" not in agent_identity.IDENTITY_PROVENANCE


# --- 2.12-1 attestation ---------------------------------------------------------


def test_attestation_round_trips_through_manifest_verify(tmp_path, capsys):
    repo = _repo(tmp_path, {"k8s/spiffe.yaml": SPIFFE_YAML,
                            ".safeai/config.yml": _declare(("drafter", DRAFTER_ID))})
    rc, manifest, statement = _scan(tmp_path, repo)
    assert rc == 0
    document = json.loads(manifest.read_text(encoding="utf-8"))
    assert document["contract"]["version"] == CONTRACT_VERSION == "1.2.0"
    assert validate_manifest(document)[0] == []
    capsys.readouterr()
    assert main(["manifest", "verify", str(manifest), "--attestation", str(statement)]) == 0
    assert capsys.readouterr().out.startswith("verified:")

    data = json.loads(statement.read_text(encoding="utf-8"))
    assert data["_type"] == attestation.STATEMENT_TYPE
    assert data["predicateType"] == attestation.PREDICATE_TYPE
    assert data["subject"][0]["name"] == "m.json"
    predicate = data["predicate"]
    assert predicate["experimental"] is True and predicate["schema_stability"] == "none"
    drafter = next(a for a in predicate["agents"] if a["name"] == "drafter")
    assert set(drafter) >= {"machine_derived", "declared", "unknown"}
    assert [i["provenance_class"] for i in drafter["declared"]["workload_identity"]] == [
        "declared"]
    assert [i["provenance_class"] for i in drafter["machine_derived"]["workload_identity"]] == [
        "repo-iac-observed"]
    assert drafter["machine_derived"]["delegated_by"] == ["claude_code:session"]
    assert [c["pair"] for c in drafter["machine_derived"]["separation_of_duties"]] == [
        "SOD-CHANGE-MERGE"]
    assert {u["field"] for u in drafter["unknown"]} == {
        "runtime_identity", "governance.owner", "governance.lifecycle", "governance.purpose",
        "governance.client_id"}
    assert predicate["repository"]["machine_derived"]["workload_identities"] == [
        {"id": DRAFTER_ID, "workloads": ["Deployment/agents/drafter"]}]


def test_attestation_detects_tampering(tmp_path, capsys):
    rc, manifest, statement = _scan(tmp_path, _repo(tmp_path))
    assert rc == 0
    data = json.loads(statement.read_text(encoding="utf-8"))
    data["predicate"]["agents"][0]["declared"]["workload_identity"] = [
        {"id": DRAFTER_ID, "provenance_class": "declared"}]
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert main(["manifest", "verify", str(manifest), "--attestation", str(forged)]) == 1
    assert capsys.readouterr().out.startswith("predicate-mismatch:")

    # Any edit to the manifest file breaks the subject binding, even one
    # that keeps its integrity digest valid (whitespace only).
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert main(["manifest", "verify", str(manifest), "--attestation", str(statement)]) == 1
    assert capsys.readouterr().out.startswith("subject-mismatch:")


def test_manifest_without_attestation_block(tmp_path, capsys):
    repo = _repo(tmp_path)
    _, _, statement = _scan(tmp_path, repo)
    plain = tmp_path / "plain.json"
    assert main(["scan", str(repo), "--manifest", str(plain), "--no-registry"]) == 0
    assert "authority_attestation" not in json.loads(plain.read_text(encoding="utf-8"))
    capsys.readouterr()
    assert main(["manifest", "verify", str(plain), "--attestation", str(statement)]) == 1
    assert capsys.readouterr().out.startswith("no-attestation-block:")


def test_attestation_requires_manifest(tmp_path):
    with pytest.raises(SystemExit):
        main(["scan", str(_repo(tmp_path)), "--no-registry",
              "--experimental-attestation", str(tmp_path / "a.json")])


def test_predicate_is_deterministic(tmp_path):
    repo = _repo(tmp_path, {"k8s/spiffe.yaml": SPIFFE_YAML})
    _, _, first = _scan(tmp_path, repo)
    one = json.loads(first.read_text(encoding="utf-8"))["predicate"]
    _, _, second = _scan(tmp_path, repo)
    two = json.loads(second.read_text(encoding="utf-8"))["predicate"]
    assert attestation.predicate_digest(one) == attestation.predicate_digest(two)


# --- schema parity ----------------------------------------------------------------


def test_schema_enums_match_contract():
    path = os.path.join("schemas", "safeai-manifest", "v1.2.0.json")
    with open(path, encoding="utf-8") as handle:
        props = json.load(handle)["properties"]
    identity = props["agents"]["items"]["properties"]["workload_identity"]["properties"]
    assert tuple(identity["state"]["enum"]) == IDENTITY_STATES
    assert tuple(identity["identifiers"]["items"]["properties"]["provenance_class"]["enum"]) \
        == IDENTITY_PROVENANCE_CLASSES
    evaluation = props["exception_evaluations"]["items"]["properties"]
    assert tuple(evaluation["approval_state"]["enum"]) == APPROVAL_STATES
    assert "authority_attestation" in props
