"""Declared governance metadata and CIMD documents in the attestation (v2.15, plan 2.15-2)."""

import hashlib
import json

import pytest

from safeai.cmd.cli import main
from safeai.kya import attestation
from safeai.kya.governance import (
    GovernanceError,
    attach_governance,
    collect_client_metadata_documents,
    load_declared_governance,
)
from safeai.kya.integrity import stamp_integrity

CLIENT = "https://support.example.com/oauth/client.json"
SUBAGENT = "---\nname: drafter\ndescription: drafts replies\ntools: Read, Grep\n---\nDraft.\n"


def _repo(tmp_path, config, files=None):
    (tmp_path / ".safeai").mkdir(exist_ok=True)
    (tmp_path / ".safeai" / "config.yml").write_text(config, encoding="utf-8")
    for rel, text in (files or {}).items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return str(tmp_path)


def test_declaration_is_read_with_its_line(tmp_path):
    root = _repo(tmp_path, (
        "project_id: demo\nagent_governance:\n"
        "  - agent: drafter\n    owner: team@example.com\n    lifecycle: production\n"))
    (item,) = load_declared_governance(root)
    assert (item["owner"], item["lifecycle"], item["client_id"]) == (
        "team@example.com", "production", None)
    assert item["evidence"] == [{"file": ".safeai/config.yml", "line": 3}]


@pytest.mark.parametrize("entry", [
    "x",
    "{owner: a}",
    "{agent: d}",
    "{agent: d, lifecycle: live}",
    "{agent: d, client_id: 'http://insecure.example/c.json'}",
    "{agent: d, client_id: 'https://example.com'}",
    "{agent: d, owner: ''}",
])
def test_malformed_declarations_are_refused(tmp_path, entry):
    with pytest.raises(GovernanceError):
        load_declared_governance(_repo(tmp_path, f"agent_governance:\n  - {entry}\n"))


def test_client_metadata_document_is_matched_by_client_id(tmp_path):
    doc = {"client_id": CLIENT, "client_name": "Support bot",
           "redirect_uris": ["https://support.example.com/cb"], "client_secret": "never-copied"}
    root = _repo(tmp_path, "", {"oauth/client.json": json.dumps(doc),
                                "other.json": json.dumps({"client_id": CLIENT}),
                                "dup/a.json": json.dumps(dict(doc, client_id=CLIENT + "?x")),
                                "dup/b.json": json.dumps(dict(doc, client_id=CLIENT + "?x"))})
    documents = collect_client_metadata_documents(root)
    assert documents[CLIENT]["evidence"] == [{"file": "oauth/client.json", "line": 1}]
    assert "client_secret" not in documents[CLIENT]["fields"]
    assert documents[CLIENT + "?x"] is None  # two files claim it: ambiguous

    agents = [{"agent_id": "a1", "name": "bot"}, {"agent_id": "a2", "name": "other"}]
    declared = [{"agent": "bot", "owner": "o", "lifecycle": None, "purpose": None,
                 "client_id": CLIENT, "evidence": []},
                {"agent": "other", "owner": "o", "lifecycle": None, "purpose": None,
                 "client_id": "https://elsewhere.example/c.json", "evidence": []},
                {"agent": "ghost", "owner": "o", "lifecycle": None, "purpose": None,
                 "client_id": None, "evidence": []}]
    notes = attach_governance(agents, declared, documents)
    assert notes == [(".safeai/config.yml: agent_governance names agent 'ghost', which this "
                      "scan did not report")]
    assert agents[0]["governance"]["client_metadata_state"] == "in-repository"
    assert agents[0]["governance"]["client_metadata"]["fields"]["client_name"] == "Support bot"
    assert agents[1]["governance"]["client_metadata_state"] == "not-in-repository"


def test_scan_puts_governance_in_the_manifest_and_the_attestation(tmp_path):
    root = _repo(tmp_path, (
        "project_id: demo\nagent_governance:\n"
        f"  - agent: drafter\n    owner: team@example.com\n    client_id: {CLIENT}\n"),
        {".claude/agents/drafter.md": SUBAGENT,
         "oauth/client.json": json.dumps({"client_id": CLIENT, "client_name": "Drafter"})})
    manifest_path, statement_path = tmp_path / "m.json", tmp_path / "a.json"
    main(["scan", root, "--no-registry", "--manifest", str(manifest_path), "--sarif",
          str(tmp_path / "s.sarif"), "--experimental-attestation", str(statement_path)])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    (agent,) = [a for a in manifest["agents"] if a["name"] == "drafter"]
    assert agent["governance"]["owner"] == "team@example.com"
    assert agent["governance"]["provenance_class"] == "declared"
    statement = json.loads(statement_path.read_text(encoding="utf-8"))
    assert statement["predicateType"].endswith("agent-authority-v0.2-experimental.md")
    (entry,) = [a for a in statement["predicate"]["agents"] if a["name"] == "drafter"]
    assert entry["declared"]["governance"]["client_metadata"]["fields"]["client_name"] == \
        "Drafter"
    assert {u["field"] for u in entry["unknown"]} >= {"governance.lifecycle",
                                                      "governance.purpose"}
    assert "governance.owner" not in {u["field"] for u in entry["unknown"]}
    status, _ = attestation.verify_attestation(manifest_path.read_bytes(), manifest, statement)
    assert status == attestation.ATTESTATION_OK


def test_v01_statements_still_verify(tmp_path):
    root = _repo(tmp_path, "project_id: demo\n", {".claude/agents/drafter.md": SUBAGENT})
    manifest_path, statement_path = tmp_path / "m.json", tmp_path / "a.json"
    main(["scan", root, "--no-registry", "--manifest", str(manifest_path), "--sarif",
          str(tmp_path / "s.sarif"), "--experimental-attestation", str(statement_path)])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    statement = json.loads(statement_path.read_text(encoding="utf-8"))
    # A manifest and Statement written by 2.12-2.14 name the v0.1 type.
    old_type = attestation.KNOWN_PREDICATE_TYPES[1]
    manifest["authority_attestation"]["predicate_type"] = old_type
    stamp_integrity(manifest)
    data = json.dumps(manifest).encode("utf-8")
    statement["predicateType"] = old_type
    statement["subject"] = [{"name": "m.json",
                             "digest": {"sha256": hashlib.sha256(data).hexdigest()}}]
    assert attestation.verify_attestation(data, manifest, statement)[0] == \
        attestation.ATTESTATION_OK
    statement["predicateType"] = attestation.PREDICATE_TYPE
    assert attestation.verify_attestation(data, manifest, statement)[0] == \
        attestation.PREDICATE_MISMATCH
