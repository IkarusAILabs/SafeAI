"""v2.13 file-only interoperability exports: OCSF events and SSF SET payloads."""

import copy
import hashlib
import json
import os
import socket
from pathlib import Path

import jsonschema
import pytest

from safeai.cmd.cli import main
from safeai.report.exports import build_export
from safeai.report.ocsf import build_events
from safeai.report.ssf import EVENT_TYPE, build_payloads

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
EXAMPLE = ROOT / "examples" / "integrations" / "ocsf-ssf-consumer"
OCSF_SCHEMA_FILES = {
    2007: "ocsf/1.9.0/application_security_posture_finding.json",
    2008: "ocsf/1.9.0/iam_analysis_finding.json",
}
#: SHA-256 of the vendored OCSF files as published (see schemas/ocsf/README.md).
OCSF_SCHEMA_SHA256 = {
    "ocsf/1.9.0/application_security_posture_finding.json":
        "19f8987cce020a36edfe2872be3b4427031b723e68533c352644dcb18543cdeb",
    "ocsf/1.9.0/iam_analysis_finding.json":
        "4d16cba131673def94dbc8be6adb71e0e193af6e6385354f8a6e9a734000ec97",
}


def _validator(rel):
    return jsonschema.Draft7Validator(json.loads((SCHEMAS / rel).read_text(encoding="utf-8")))


OCSF_VALIDATORS = {uid: _validator(rel) for uid, rel in OCSF_SCHEMA_FILES.items()}
SET_VALIDATOR = _validator("safeai-ssf-set/v0.1.0.json")


def _read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    """Scan the reference fixture pair with both exports; returns the paths."""
    out = tmp_path_factory.mktemp("exports")
    paths = {k: out / v for k, v in (("baseline", "baseline.json"), ("manifest", "m.json"),
                                     ("ocsf", "e.ocsf.jsonl"), ("set", "e.set.jsonl"))}
    assert main(["scan", str(EXAMPLE / "fixture" / "baseline"), "--no-registry",
                 "--manifest", str(paths["baseline"]), "--sarif", str(out / "b.sarif")]) == 0
    main(["scan", str(EXAMPLE / "fixture" / "current"), "--no-registry",
          "--baseline", str(paths["baseline"]), "--manifest", str(paths["manifest"]),
          "--sarif", str(out / "c.sarif"), "--ocsf", str(paths["ocsf"]),
          "--ssf-set", str(paths["set"]), "--ssf-audience", "https://receiver.example"])
    return paths


def _manifest(paths):
    return json.loads(paths["manifest"].read_text(encoding="utf-8"))


# --- OCSF ---------------------------------------------------------------------

def test_vendored_ocsf_schemas_are_unmodified():
    for rel, digest in OCSF_SCHEMA_SHA256.items():
        assert hashlib.sha256((SCHEMAS / rel).read_bytes()).hexdigest() == digest


def test_every_ocsf_event_validates(scanned):
    events = _read_jsonl(scanned["ocsf"])
    assert {e["class_uid"] for e in events} == {2007, 2008}
    for event in events:
        errors = [e.message for e in OCSF_VALIDATORS[event["class_uid"]].iter_errors(event)]
        assert errors == [], (event["finding_info"]["types"], errors)


def test_ocsf_covers_findings_and_changes(scanned):
    manifest = _manifest(scanned)
    events = _read_jsonl(scanned["ocsf"])
    findings = [e for e in events if e["class_uid"] == 2007]
    changes = [e for e in events if e["class_uid"] == 2008]
    assert len(findings) == len(manifest["findings"])
    assert {e["unmapped"]["safeai"]["tool_key"] for e in changes} == {
        c["tool_key"] for c in manifest["authority_changes"] if c["change_class"] != "NO_CHANGE"}
    for event in events:
        assert event["type_uid"] == event["class_uid"] * 100 + 1
        assert event["metadata"]["version"] == "1.9.0"


def test_ocsf_change_severity_takes_the_highest_escalation(scanned):
    docs = next(e for e in _read_jsonl(scanned["ocsf"])
                if e["class_uid"] == 2008
                and e["unmapped"]["safeai"]["tool_key"] == "mcp_server:docs")
    # HIGH_RISK_CHANGE alone is 4 (High); the critical escalation makes it 5.
    assert docs["severity_id"] == 5
    assert "mcp_tool:run_command:execute" in (
        docs["permission_analysis_results"][0]["granted_privileges"])


def test_ocsf_finding_fields():
    manifest = {"project": {"project_id": "p", "name": "demo"},
                "scan": {"scan_id": "s", "completed_at": "2026-11-03T00:00:00Z"},
                "safeai": {"version": "2.13.0"},
                "findings": [{"rule_id": "R1", "severity": "high", "message": "m",
                              "fingerprint": "f1", "status": "suppressed",
                              "confidence": "medium", "remediation": "fix it",
                              "location": {"path": ".claude/settings.json", "line_start": 3}}]}
    (event,) = build_events(manifest)
    assert OCSF_VALIDATORS[2007].is_valid(event)
    assert (event["severity_id"], event["status_id"], event["confidence_id"]) == (4, 3, 2)
    assert event["time"] == 1793664000000
    assert event["resources"] == [{"type": "file", "name": ".claude/settings.json",
                                   "uid": ".claude/settings.json"}]
    assert event["finding_info"]["uid"] == "f1"
    assert event["unmapped"]["safeai"]["line_start"] == 3


def test_ocsf_rejects_what_the_schema_forbids(scanned):
    event = _read_jsonl(scanned["ocsf"])[0]
    bad = dict(event, risk_label="whatever")
    assert not OCSF_VALIDATORS[event["class_uid"]].is_valid(bad)
    bad = dict(event, severity_id=7)
    assert not OCSF_VALIDATORS[event["class_uid"]].is_valid(bad)


# --- SSF SET payloads ---------------------------------------------------------

def test_every_set_payload_validates(scanned):
    payloads = _read_jsonl(scanned["set"])
    assert len(payloads) == 2
    for payload in payloads:
        assert [e.message for e in SET_VALIDATOR.iter_errors(payload)] == []
        assert payload["aud"] == "https://receiver.example"
        assert list(payload["events"]) == [EVENT_TYPE]
        assert "sub" not in payload and "exp" not in payload


def test_set_binds_to_the_manifest(scanned):
    manifest = _manifest(scanned)
    for payload in _read_jsonl(scanned["set"]):
        event = payload["events"][EVENT_TYPE]
        assert event["evidence"]["manifest_payload_sha256"] == (
            manifest["integrity"]["payload_sha256"])
        assert payload["txn"] == manifest["scan"]["scan_id"]
        assert payload["sub_id"] == {"format": "opaque", "id": (
            f"{manifest['project']['project_id']}:{event['tool']['key']}")}


@pytest.mark.parametrize("change_class", ["LOW_CHANGE", "UNKNOWN", "NO_CHANGE"])
def test_only_material_and_high_risk_changes_become_sets(change_class):
    manifest = {"project": {"project_id": "p"}, "scan": {},
                "integrity": {"payload_sha256": "0" * 64},
                "authority_changes": [{"tool_key": "t", "change_class": change_class}]}
    assert build_payloads(manifest) == []


def test_set_issuer_and_audiences():
    manifest = {"project": {"project_id": "p"}, "scan": {"scan_id": "s"},
                "integrity": {"payload_sha256": "a" * 64},
                "authority_changes": [{"tool_key": "t", "change_class": "MATERIAL_CHANGE"}]}
    (default,) = build_payloads(manifest)
    assert default["iss"] == "urn:safeai:project:p" and "aud" not in default
    (custom,) = build_payloads(manifest, issuer="https://ci.example", audience=["a", "b"])
    assert (custom["iss"], custom["aud"]) == ("https://ci.example", ["a", "b"])
    assert SET_VALIDATOR.is_valid(custom)


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(sub="x"),
    lambda p: p.update(exp=1),
    lambda p: p.pop("sub_id"),
    lambda p: p["sub_id"].pop("id"),
    lambda p: p["events"].update({"urn:other": {}}),
    lambda p: p["events"][EVENT_TYPE].update(change_class="LOW_CHANGE"),
    lambda p: p["events"][EVENT_TYPE]["evidence"].update(manifest_payload_sha256="x"),
])
def test_set_schema_rejects_malformed_payloads(scanned, mutate):
    payload = copy.deepcopy(_read_jsonl(scanned["set"])[0])
    mutate(payload)
    assert not SET_VALIDATOR.is_valid(payload)


# --- Determinism, offline, CLI ------------------------------------------------

def test_exports_are_a_function_of_the_manifest(scanned, tmp_path):
    manifest = _manifest(scanned)
    assert build_export("ocsf", manifest) == build_export("ocsf", copy.deepcopy(manifest))
    for fmt, key, extra in (("ocsf", "ocsf", []),
                            ("ssf-set", "set", ["--ssf-audience", "https://receiver.example"])):
        out = tmp_path / f"{fmt}.jsonl"
        assert main(["manifest", "export", str(scanned["manifest"]), "--format", fmt,
                     "--output", str(out), *extra]) == 0
        assert out.read_bytes() == scanned[key].read_bytes()


def test_exports_hold_no_local_paths(scanned):
    for key in ("ocsf", "set"):
        text = scanned[key].read_text(encoding="utf-8")
        assert str(EXAMPLE) not in text and str(EXAMPLE).replace("\\", "/") not in text


def test_export_refuses_a_tampered_manifest(scanned, tmp_path, capsys):
    manifest = _manifest(scanned)
    manifest["findings"] = []
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")
    out = tmp_path / "out.jsonl"
    assert main(["manifest", "export", str(tampered), "--format", "ocsf",
                 "--output", str(out)]) == 1
    assert "not exported" in capsys.readouterr().out
    assert not out.exists()


def test_ssf_claim_options_require_ssf_set(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["scan", str(tmp_path), "--no-registry", "--sarif", str(tmp_path / "r.sarif"),
              "--ssf-issuer", "https://ci.example"])


def test_exports_open_no_network_connection(tmp_path, monkeypatch):
    def _refuse(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    base = tmp_path / "base.json"
    main(["scan", str(EXAMPLE / "fixture" / "baseline"), "--no-registry",
          "--manifest", str(base), "--sarif", str(tmp_path / "b.sarif")])
    main(["scan", str(EXAMPLE / "fixture" / "current"), "--no-registry", "--baseline",
          str(base), "--sarif", str(tmp_path / "c.sarif"),
          "--ocsf", str(tmp_path / "e.jsonl"), "--ssf-set", str(tmp_path / "s.jsonl")])
    assert (tmp_path / "e.jsonl").stat().st_size > 0
    assert (tmp_path / "s.jsonl").stat().st_size > 0


# --- Reference integration (2.13-3) -------------------------------------------

def test_reference_integration_reproduces(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(EXAMPLE))
    import reproduce

    expected = json.loads((EXAMPLE / "expected" / "review_queue.json").read_text(
        encoding="utf-8"))
    assert reproduce.run(str(tmp_path)) == expected


def test_consumer_rejects_sets_from_another_manifest(scanned, tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE))
    import consumer

    result = consumer.review_queue(_read_jsonl(scanned["ocsf"]), _read_jsonl(scanned["set"]),
                                   manifest_digest="f" * 64)
    assert result["review_queue"] == []
    assert len(result["rejected"]) == 2
    out = tmp_path / "q.json"
    rc = consumer.main(["--ocsf", str(scanned["ocsf"]), "--ssf-set", str(scanned["set"]),
                        "--schemas", str(SCHEMAS), "--output", str(out)])
    assert rc == 0 and os.path.getsize(out) > 0
