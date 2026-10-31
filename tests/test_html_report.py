from safeai.report.html import write_html


def test_write_html_report(tmp_path):
    report = {
        "files_scanned": 3,
        "counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1},
        "detected_frameworks": ["langchain"],
        "mcp_assets": [],
        "normalized_capabilities": [{
            "name": "shell_execution",
            "category": "Shell",
            "source_frameworks": ["langchain"],
            "confidence": 0.8,
            "evidence": ["subprocess.run"],
        }],
        "trust_score": {
            "overall_ai_risk_score": 72,
            "categories": {"Capability": 60, "Safety": 85},
        },
        "findings": [{
            "rule_id": "CAP_shell",
            "severity": "high",
            "file": "a.py",
            "line": 1,
            "message": "Capability discovered",
            "evidence": "subprocess.run",
            "remediation": "Restrict shell commands",
            "risk_category": "Capability",
        }],
        "capability_diff": {
            "schema_version": 2,
            "counts": {"added": 1, "removed": 0, "changed": 1, "escalations": 1},
            "highest_escalation": "high",
            "baseline_tool_attribution": True,
            "tools": [{
                "tool_key": "tool:shell-run",
                "status": "escalated",
                "access_summary": {"before": "read", "after": "write"},
                "escalations": [{"id": "ESC_WRITE_TOOL_ADDED", "severity": "high",
                                 "summary": "write capability added", "inferred": False}],
            }],
        },
        "tool_surface": [{
            "tool_key": "tool:shell-run",
            "kind": "tool",
            "framework": "langchain",
            "access_summary": "write",
            "capabilities": [{"name": "filesystem", "access_mode": "write",
                              "access_mode_inferred": False}],
        }],
        "policy_decision": {"outcome": "warn", "reasons": ["review shell usage"]},
        "policy_profile": "strict-ci",
        "kya_agents": [{
            "name": "agent-1",
            "agent_id": "agent-abc",
            "framework": "langchain",
            "agent_type": "agent",
            "confidence": 0.9,
            "capabilities": [{"name": "shell"}],
            "source_locations": [{"path": "a.py", "line_start": 1}],
        }],
        "assurance_boundary": {
            "summary": "Static evidence only.",
            "verified_statically": ["declared tools"],
            "not_verifiable_statically": ["runtime identity"],
            "coverage_notes": ["no files skipped"],
            "inferred_value_count": 0,
        },
        "baseline": {"new": 1, "existing": 2, "resolved": 0, "new_high_critical": 0},
    }

    out = tmp_path / "report.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "SafeAI Early Preview Report" in content
    assert "Executive Summary" in content
    assert "Capability Matrix" in content
    assert "Capability Escalations" in content
    assert "ESC_WRITE_TOOL_ADDED" in content
    assert "Highest escalation" in content
    assert "Tool Capability Surface" in content
    assert "Assurance boundary" in content
    assert "Know Your Agent (KYA)" in content
    assert "Policy outcome" in content
    assert "Policy profile:" in content
    assert "strict-ci" in content
    assert "Trust Scores" in content
    assert "data-theme=\"light\"" in content


def test_html_escapes_user_data(tmp_path):
    report = {
        "files_scanned": 1,
        "counts": {},
        "detected_frameworks": [],
        "findings": [{
            "severity": "high",
            "file": "<script>alert('x')</script>.py",
            "line": 1,
            "message": "<img src=x onerror=alert(1)>",
        }],
        "normalized_capabilities": [],
        "trust_score": {"overall_ai_risk_score": 50, "categories": {}},
        "policy_profile": "<script>alert('profile')</script>",
        "policy_decision": {"outcome": "warn", "reasons": []},
    }
    out = tmp_path / "escaped.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "<script>alert" not in content
    assert "<img src=x" not in content
    assert "&lt;script&gt;alert" in content
    assert "&lt;img" in content
    assert "<script>alert('profile')</script>" not in content
    assert "&lt;script&gt;alert(&#x27;profile&#x27;)&lt;/script&gt;" in content



def test_html_report_absent_policy_profile(tmp_path):
    report = {
        "files_scanned": 1,
        "counts": {},
        "detected_frameworks": [],
        "findings": [],
        "normalized_capabilities": [],
        "trust_score": {"overall_ai_risk_score": 50, "categories": {}},
        # No policy_profile key
        "policy_decision": {"outcome": "warn", "reasons": []},
    }
    out = tmp_path / "no_policy_profile.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "Policy outcome" in content
    assert "Policy profile:" not in content


def _brief_report():
    return {
        "files_scanned": 2,
        "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        "detected_frameworks": ["langchain"],
        "normalized_capabilities": [{"name": "shell_execution"}],
        "trust_score": {"overall_ai_risk_score": 62, "categories": {}},
        "findings": [{
            "rule_id": "CAP_shell", "severity": "critical", "file": "a.py",
            "line": 1, "message": "Shell execution detected",
            "evidence": "subprocess.run", "remediation": "Restrict shell.",
            "fingerprint": "a" * 64, "provenance_class": "detected",
            "gateability": "deterministic", "confidence_label": "high",
        }],
        "tool_surface": [{
            "tool_key": "tool:shell-run", "kind": "tool",
            "framework": "langchain", "access_summary": "execute",
            "capabilities": [{"name": "shell_execution", "access_mode": "execute",
                              "evidence": [{"path": "a.py", "line": 1}]}],
        }],
        "kya_agents": [{"agent_id": "agent-1"}],
        "capability_diff": {
            "baseline_available": True,
            "counts": {"added": 1, "removed": 0, "changed": 0, "escalations": 1},
            "tools": [{
                "tool_key": "tool:shell-run", "status": "new",
                "change_class": "HIGH_RISK_CHANGE",
                "escalations": [{
                    "id": "ESC_SHELL_ADDED", "severity": "critical",
                    "summary": "Shell added",
                    "remediation": {
                        "why_it_matters": "Shell enables arbitrary commands.",
                        "recommended_actions": ["Remove shell access."],
                        "review_questions": ["Is shell intended?"],
                        "limitations": ["Static evidence only."],
                    },
                }],
            }],
        },
        "iac_correlations": {
            "schema_version": 2,
            "lane": "B",
            "grants": [{
                "identity": {"kind": "aws_iam_role", "name": "agent-role"},
                "actions": {"values": ["s3:*"], "resolution": "resolved"},
                "resources": {"values": ["*"], "resolution": "resolved"},
                "source": "terraform", "source_file": "main.tf", "line": 10,
            }],
            "verdicts": [{
                "agent_ref": "<repo>",
                "identity_ref": {"kind": "aws_iam_role", "name": "agent-role"},
                "domain": "aws:s3",
                "verdict": "EXCESS_AUTHORITY",
                "declared_evidence_refs": ["tool:shell-run"],
                "grant_evidence_refs": ["main.tf:10"],
                "link_evidence_refs": ["config.yaml:3"],
                "resolution": "resolved",
                "reason": "Grant exceeds requirement.",
            }],
        },
        "policy_decision": {"outcome": "warn", "reasons": [],
                            "matches": [{"policy_id": "P1", "lane": "B",
                                         "message": "Please review."}]},
        "assurance_boundary": {
            "summary": "Static evidence only.",
            "verified_statically": ["declared tools"],
            "not_verifiable_statically": ["runtime identity"],
            "coverage_notes": [],
            "inferred_value_count": 0,
        },
    }


def test_html_security_brief_sections(tmp_path):
    out = tmp_path / "brief.html"
    write_html(_brief_report(), str(out))
    content = out.read_text(encoding="utf-8")
    for heading in ("Security Brief", "What SafeAI Found",
                    "Recommended Review Actions", "Capability Changes",
                    "Authority Review", "Evidence Confidence"):
        assert heading in content, f"missing section: {heading}"
    assert "EXCESS_AUTHORITY" in content
    assert "main.tf:10" in content
    assert "Is shell intended?" in content
    # Assurance moved before detailed evidence.
    assert content.index("Assurance boundary") < content.index("<h2>Findings</h2>")
    # No affirmative runtime claims (negations like "never proof of
    # deployed permission" are required and present).
    lowered = content.lower()
    assert "never proof of deployed permission" in lowered
    for phrase in ("deployed permission granted", "verified runtime permission",
                   "runtime permission verified", "certified safe",
                   "guaranteed secure"):
        assert phrase not in lowered, f"runtime claim leaked: {phrase}"


def test_html_new_sections_escape_injection(tmp_path):
    report = _brief_report()
    report["tool_surface"][0]["tool_key"] = "<script>alert(1)</script>"
    report["iac_correlations"]["verdicts"][0]["domain"] = "<img src=x onerror=alert(1)>"
    report["iac_correlations"]["grants"][0]["source_file"] = "x\"><b>evil</b>"
    out = tmp_path / "injected.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "<img src=x" not in content
    assert "<b>evil</b>" not in content


def test_html_omits_absent_sections(tmp_path):
    report = _brief_report()
    del report["iac_correlations"]
    del report["capability_diff"]
    out = tmp_path / "minimal.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "Authority Review" not in content
    assert "--baseline" in content
    assert "Security Brief" in content
    assert "Recommended Review Actions" in content


def test_html_shows_evidence_metrics(tmp_path):
    """v2.7 evidence metrics render from the report's top-level key."""
    report = _brief_report()
    report["evidence_metrics"] = {"rates": {
        "evidence_backed_authority_rate": {"status": "measured", "value": 0.8, "numerator": 8, "denominator": 10},
        "inferred_authority_rate": {"status": "measured", "value": 0.2, "numerator": 2, "denominator": 10},
        "unattributed_authority_rate": {"status": "measured", "value": 0.0, "numerator": 0, "denominator": 10},
    }}
    out = tmp_path / "metrics.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "Evidence metrics" in content
    assert "Evidence-backed authority: 80% (8/10)" in content
    assert "Inferred authority: 20% (2/10)" in content
    assert "Unattributed authority: 0% (0/10)" in content


def test_html_evidence_metrics_insufficient_evidence(tmp_path):
    """An unmeasured rate reads as insufficient evidence, never 0% or 100%."""
    report = _brief_report()
    unmeasured = {"value": None, "status": "insufficient_evidence",
                  "reason": "no authority statements"}
    report["evidence_metrics"] = {"rates": {
        "evidence_backed_authority_rate": unmeasured,
        "inferred_authority_rate": unmeasured,
        "unattributed_authority_rate": unmeasured,
    }}
    out = tmp_path / "insufficient.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "Evidence-backed authority: insufficient evidence" in content
    assert "Inferred authority: insufficient evidence" in content
    assert "Unattributed authority: insufficient evidence" in content


def test_html_omits_evidence_metrics_when_absent(tmp_path):
    """Reports from before v2.7 have no evidence_metrics key and still render."""
    report = _brief_report()
    report.pop("evidence_metrics", None)
    out = tmp_path / "legacy.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "Security Brief" in content
    assert "Evidence metrics" not in content


def test_scan_html_includes_evidence_metrics(tmp_path):
    """End to end: a real scan's HTML report carries the metrics card."""
    from safeai.cmd.cli import main

    project = tmp_path / "proj"
    project.mkdir()
    (project / "agent.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    out = tmp_path / "scan.html"
    main(["scan", str(project), "--no-registry",
          "--sarif", str(tmp_path / "scan.sarif"), "--html", str(out)])
    content = out.read_text(encoding="utf-8")
    assert "Evidence metrics" in content
    assert "Evidence-backed authority:" in content
