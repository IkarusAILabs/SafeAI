"""Tests for the SafeAI Community Scan programme sanitisation and disclosure logic."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "community-scans", "scripts"))

from build_scan_manifest import build_manifest
from sanitise_report import (
    classify,
    redact_secret,
    sanitise_report,
    sanitize_location,
    sanitize_text,
)
from validate_targets import is_safe_ref, validate_security_policy

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _sample_report(findings):
    return {
        "display_name": "TestProject",
        "repository": "owner/test",
        "resolved_commit_sha": "a" * 40,
        "safeai_version": "1.0.0",
        "scan_timestamp_utc": "2026-01-01T00:00:00Z",
        "scope": "static",
        "safeai_security_scorecard": {"score": 7.5},
        "status": "REVIEW",
        "findings": findings,
    }


def test_target_entries_in_manifest():
    import yaml

    with open(os.path.join(FIXTURE_DIR, "..", "..", "..", "community-scans", "targets.yml"), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    ids = [t["id"] for t in data["targets"]]
    assert len(ids) >= 25, f"Expected at least 25 targets, got {len(ids)}"
    assert ids[0] == "n8n"
    assert "langchain" in ids
    assert "crewai" in ids


def test_invalid_repository_rejected():
    bad = {"version": 1, "targets": [{"id": "x", "repository": "not-a-repo", "display_name": "X",
                                      "default_ref": "main", "upstream_url": "https://github.com/x"}]}
    from validate_targets import validate_yaml_structure
    errors = validate_yaml_structure(bad)
    assert any("owner/name" in e for e in errors)


def test_secret_redaction():
    text = 'key = "sk-abcdefghijklmnopqrstuvwx"'
    assert "sk-" not in redact_secret(text)
    assert "[REDACTED_SECRET]" in redact_secret(text)


def test_sensitive_finding_classified():
    f = {"severity": "critical", "summary": "hardcoded api_key found", "category": "secret"}
    assert classify(f) == "potentially_sensitive"


def test_critical_without_secret_is_review():
    f = {"severity": "critical", "summary": "unsafe deserialization", "category": "injection"}
    assert classify(f) == "review_recommended"


def test_low_severity_is_informational():
    f = {"severity": "low", "summary": "verbose logging", "category": "logging"}
    assert classify(f) == "informational"


def test_sanitise_removes_sensitive_from_public():
    report = _sample_report([
        {"id": "1", "rule_id": "R1", "severity": "critical", "category": "secret",
         "summary": "api_key leaked", "location": {"file": "a.py", "line": 1}},
        {"id": "2", "rule_id": "R2", "severity": "high", "category": "injection",
         "summary": "unsafe eval", "location": {"file": "b.py", "line": 2}},
    ])
    summary = sanitise_report(report)
    public_ids = [f["id"] for f in summary["findings"]]
    assert "1" not in public_ids
    assert "2" in public_ids
    assert summary["sensitive_count"] >= 1


def test_markdown_escaping_no_execution():
    report = _sample_report([
        {"id": "1", "rule_id": "R1", "severity": "high", "category": "injection",
         "summary": "$(rm -rf /) backtick `code` [link](http://evil.example)", "location": {"file": "a.py", "line": 1}},
    ])
    summary = sanitise_report(report)
    pub = summary["findings"][0]["summary"]
    assert "$(rm -rf /)" not in pub
    assert "http://evil.example" not in pub
    assert "[URL_REDACTED]" in pub
    # Markdown metacharacters are escaped, so they cannot forge headings/links.
    assert "`code`" not in pub


def test_markdown_injection_is_escaped():
    text = "# Heading\n\n[click](javascript:alert(1))\n\n**bold** and <script>alert(1)</script>"
    out = sanitize_text(text)
    # The leading '#' must be escaped so it cannot render as a heading.
    assert out.startswith("\\# Heading")
    assert "<script>" not in out
    assert "javascript:alert" not in out
    assert "\\# Heading" in out


def test_location_with_malicious_path_is_redacted():
    loc = {"file": "../../etc/passwd\0", "line": -5}
    assert sanitize_location(loc) == {"file": "[REDACTED_PATH]", "line": None}
    safe = sanitize_location({"file": "src/agent.py", "line": 42})
    assert safe == {"file": "src/agent.py", "line": 42}


def test_scorecard_summary_structure_extracted():
    report = _sample_report([])
    report["safeai_security_scorecard"] = {"summary": {"score": 8.4}}
    summary = sanitise_report(report)
    assert summary["safeai_score"] == 8.4


def test_is_safe_ref():
    assert is_safe_ref("a" * 40)
    assert is_safe_ref("main")
    assert is_safe_ref("refs/heads/feat/x")
    assert not is_safe_ref("")
    assert not is_safe_ref("; rm -rf /")
    assert not is_safe_ref("$(touch x)")
    # Path traversal / URL-path manipulation must be rejected: the ref is
    # interpolated into a GitHub API URL path.
    assert not is_safe_ref("..")
    assert not is_safe_ref("../foo")
    assert not is_safe_ref("heads/../other")
    assert not is_safe_ref("/etc/passwd")
    assert not is_safe_ref("refs/heads/x/")


def test_security_policy_validation_rejects_non_github():
    ok, _status = validate_security_policy("https://example.com/policy", None)
    assert ok is False
    ok2, _ = validate_security_policy("", None)
    assert ok2 is False


def test_security_policy_validation_is_offline_by_default():
    # A GitHub-hosted URL must not trigger a network call by default; it should
    # be reported as "unknown" (None) so target validation stays hermetic.
    ok, status = validate_security_policy("https://github.com/owner/repo/security/policy", None)
    assert ok is None
    assert status == 0


def test_resolve_repository_detects_public(monkeypatch):
    import validate_targets

    captured = {}

    def fake_http(url, token=None, timeout=20):
        captured["url"] = url
        captured["token"] = token
        return {"full_name": "n8n-io/n8n", "private": False, "default_branch": "master"}

    monkeypatch.setattr(validate_targets, "_http_json", fake_http)
    data = validate_targets.resolve_repository("n8n-io/n8n", "tok")
    assert data["private"] is False
    assert captured["url"].endswith("/repos/n8n-io/n8n")


def test_resolve_repository_rejects_private(monkeypatch):
    import validate_targets

    def fake_http(url, token=None, timeout=20):
        return {"full_name": "acme/secret", "private": True}

    monkeypatch.setattr(validate_targets, "_http_json", fake_http)
    try:
        validate_targets.resolve_repository("acme/secret", None)
        assert False, "expected ValueError for private repo"
    except ValueError as exc:
        assert "not public" in str(exc)



def test_target_name_special_characters():
    manifest = build_manifest(
        target_id="langchain", repository="langchain-ai/langchain",
        upstream_url="https://github.com/langchain-ai/langchain",
        requested_ref="main", resolved_commit_sha="a" * 40,
        safeai_version="1.0.0", safeai_action_ref="ikaruscareer/SafeAI@v1",
        safeai_action_commit="", rule_set_version="",
        scan_timestamp_utc="2026-01-01T00:00:00Z", fail_on="critical",
        no_registry=True, github_run_id="123", python_version="3.12", disclosure_status="private",
    )
    assert manifest["target_id"] == "langchain"
    assert manifest["resolved_commit_sha"] == "a" * 40
    assert manifest["disclosure_status"] == "private"


def test_manifest_schema_valid():
    import jsonschema

    with open(os.path.join(FIXTURE_DIR, "..", "..", "..", "community-scans", "report-schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    manifest = build_manifest(
        target_id="n8n", repository="n8n-io/n8n",
        upstream_url="https://github.com/n8n-io/n8n",
        requested_ref="master", resolved_commit_sha="a" * 40,
        safeai_version="1.0.0", safeai_action_ref="ikaruscareer/SafeAI@v1",
        safeai_action_commit="", rule_set_version="",
        scan_timestamp_utc="2026-01-01T00:00:00Z", fail_on="critical",
        no_registry=True, github_run_id="123", python_version="3.12", disclosure_status="private",
    )
    jsonschema.validate(manifest, schema)


def test_manifest_records_security_policy_url():
    import jsonschema

    with open(os.path.join(FIXTURE_DIR, "..", "..", "..", "community-scans", "report-schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    manifest = build_manifest(
        target_id="crewai", repository="crewAIInc/crewAI",
        upstream_url="https://github.com/crewAIInc/crewAI",
        requested_ref="main", resolved_commit_sha="b" * 40,
        safeai_version="1.0.0", safeai_action_ref="local:./@abc",
        safeai_action_commit="", rule_set_version="",
        scan_timestamp_utc="2026-01-01T00:00:00Z", fail_on="critical",
        no_registry=True, github_run_id="123", python_version="3.12", disclosure_status="private",
        security_policy_url="https://github.com/crewAIInc/crewAI/security/policy",
    )
    assert manifest["security_policy_url"].endswith("/security/policy")
    jsonschema.validate(manifest, schema)


def test_reddit_draft_contains_disclaimer(tmp_path):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "community-scans", "scripts"))
    from render_reddit_draft import render

    summary = sanitise_report(_sample_report([
        {"id": "2", "rule_id": "R2", "severity": "high", "category": "injection",
         "summary": "unsafe eval", "location": {"file": "b.py", "line": 2}},
    ]))
    summary.update({
        "display_name": "TestProject",
        "upstream_url": "https://github.com/owner/test",
        "resolved_commit_sha": "a" * 40,
        "security_policy_url": "https://github.com/owner/test/security/policy",
        "disclosure_status": "pending",
    })
    rendered = render(summary, os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "community-scans", "templates")))
    assert "do not constitute a complete security audit" in rendered["reddit"]
    assert "read-only static analysis" in rendered["reddit"]
    assert "Reddit" not in rendered["reddit"] or "draft" in rendered["reddit"].lower()


def test_reproducible_commit_recording():
    m1 = build_manifest("n8n", "n8n-io/n8n", "https://github.com/n8n-io/n8n", "master", "a" * 40,
                        "1.0.0", "ikaruscareer/SafeAI@v1", "", "", "2026-01-01T00:00:00Z",
                        "critical", True, "123", "3.12", "private")
    m2 = build_manifest("n8n", "n8n-io/n8n", "https://github.com/n8n-io/n8n", "master", "a" * 40,
                        "1.0.0", "ikaruscareer/SafeAI@v1", "", "", "2026-01-01T00:00:00Z",
                        "critical", True, "123", "3.12", "private")
    assert m1["resolved_commit_sha"] == m2["resolved_commit_sha"]
