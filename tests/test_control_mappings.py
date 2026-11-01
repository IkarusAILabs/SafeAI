"""Tests for WS4: Control Mappings — OWASP LLM, OWASP Agentic, NIST AI RMF, Blueprint."""


class TestControlCatalogs:
    def test_owasp_llm_has_10_controls(self):
        from safeai.controls.catalogs import OWASP_LLM
        assert len(OWASP_LLM) == 10

    def test_owasp_agentic_has_10_controls(self):
        from safeai.controls.catalogs import OWASP_AGENTIC
        assert len(OWASP_AGENTIC) == 10

    def test_nist_ai_rmf_has_controls(self):
        from safeai.controls.catalogs import NIST_AI_RMF
        assert len(NIST_AI_RMF) >= 10

    def test_get_control_owasp_llm(self):
        from safeai.controls.catalogs import get_control
        control = get_control("owasp_llm", "LLM01")
        assert control is not None
        assert control["framework"] == "owasp_llm"
        assert control["id"] == "LLM01"
        assert "Prompt Injection" in control["title"]

    def test_get_control_owasp_agentic(self):
        from safeai.controls.catalogs import get_control
        control = get_control("owasp_agentic", "AGENTIC02")
        assert control is not None
        assert control["framework"] == "owasp_agentic"
        assert "Tool Misuse" in control["title"]

    def test_get_control_nist(self):
        from safeai.controls.catalogs import get_control
        control = get_control("nist_ai_rmf", "GOVERN_1")
        assert control is not None
        assert control["framework"] == "nist_ai_rmf"

    def test_get_control_unknown_returns_none(self):
        from safeai.controls.catalogs import get_control
        assert get_control("unknown", "X1") is None

    def test_list_frameworks(self):
        from safeai.controls.catalogs import list_frameworks
        frameworks = list_frameworks()
        assert len(frameworks) == 4
        ids = {f["id"] for f in frameworks}
        assert ids == {"owasp_llm", "owasp_agentic", "nist_ai_rmf", "blueprint"}


class TestControlMappings:
    def test_map_prompt_injection(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("PROMPT_INJECTION")
        frameworks = {m["framework"] for m in mappings}
        assert "owasp_llm" in frameworks
        assert "owasp_agentic" in frameworks

    def test_map_cap_shell(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("CAP_shell")
        assert len(mappings) >= 1
        control_ids = {m["control_id"] for m in mappings}
        assert "LLM06" in control_ids

    def test_map_gov_timeout_missing(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("GOV_TIMEOUT_MISSING")
        frameworks = {m["framework"] for m in mappings}
        assert "owasp_agentic" in frameworks
        assert "nist_ai_rmf" in frameworks

    def test_map_unknown_rule_returns_empty(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("UNKNOWN_RULE")
        assert mappings == []

    def test_mapping_has_required_fields(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("PROMPT_INJECTION")
        for m in mappings:
            assert "framework" in m
            assert "control_id" in m
            assert "family" in m
            assert "title" in m
            assert "description" in m

    def test_deduplicates_mappings(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("PROMPT_INJECTION")
        keys = {(m["framework"], m["control_id"]) for m in mappings}
        assert len(keys) == len(mappings)

    def test_map_findings_to_controls(self):
        from safeai.controls.mappings import map_findings_to_controls
        findings = [
            {"rule_id": "PROMPT_INJECTION", "severity": "critical"},
            {"rule_id": "CAP_shell", "severity": "high"},
        ]
        enriched = map_findings_to_controls(findings)
        assert len(enriched) == 2
        assert "control_mappings" in enriched[0]
        assert "control_mappings" in enriched[1]
        assert len(enriched[0]["control_mappings"]) >= 2

    def test_enriched_finding_preserves_original_data(self):
        from safeai.controls.mappings import map_findings_to_controls
        findings = [{"rule_id": "PROMPT_INJECTION", "severity": "critical", "file": "test.py"}]
        enriched = map_findings_to_controls(findings)
        assert enriched[0]["file"] == "test.py"
        assert enriched[0]["severity"] == "critical"

    def test_get_framework_summary(self):
        from safeai.controls.mappings import get_framework_summary
        summary = get_framework_summary()
        assert len(summary) == 4
        for fw in summary:
            assert "id" in fw
            assert "name" in fw
            assert "control_count" in fw

    def test_all_rules_have_mappings(self):
        from safeai.controls.mappings import RULE_MAPPINGS
        for rule_id, mappings in RULE_MAPPINGS.items():
            assert len(mappings) >= 1, f"Rule {rule_id} has no mappings"
            for framework, control_id in mappings:
                assert framework in {"owasp_llm", "owasp_agentic", "nist_ai_rmf", "blueprint"}
                assert isinstance(control_id, str)


class TestRuleCoverageSummary:
    def test_unmapped_rules_are_visible(self):
        """Issue #89: coverage must surface gaps, not just a mapped count."""
        from safeai.controls.mappings import rule_coverage_summary
        summary = rule_coverage_summary()

        by_category = {entry["category"]: entry for entry in summary}
        # PROMPT_DELIMITER etc. are not in RULE_MAPPINGS as of this test.
        assert by_category["PROMPT"]["unmapped_count"] >= 1
        assert "PROMPT_DELIMITER" in by_category["PROMPT"]["unmapped_rules"]

    def test_gov_and_dataflow_are_fully_mapped(self):
        from safeai.controls.mappings import rule_coverage_summary
        summary = rule_coverage_summary()

        by_category = {entry["category"]: entry for entry in summary}
        assert by_category["GOV"]["unmapped_count"] == 0
        assert by_category["DATAFLOW"]["unmapped_count"] == 0

    def test_counts_match_the_rule_lists(self):
        from safeai.controls.mappings import rule_coverage_summary
        for entry in rule_coverage_summary():
            assert entry["unmapped_count"] == len(entry["unmapped_rules"])

    def test_no_compliance_claim_field(self):
        """This is informational only -- no field should imply a pass/fail claim."""
        from safeai.controls.mappings import rule_coverage_summary
        for entry in rule_coverage_summary():
            assert set(entry) == {
                "category", "mapped_count", "unmapped_count", "unmapped_rules",
            }

    def test_deterministic_and_sorted(self):
        from safeai.controls.mappings import rule_coverage_summary
        summary = rule_coverage_summary()
        categories = [entry["category"] for entry in summary]
        assert categories == sorted(categories)
        for entry in summary:
            assert entry["unmapped_rules"] == sorted(entry["unmapped_rules"])
        # Calling it twice must produce identical output.
        assert rule_coverage_summary() == summary


class TestBlueprintMappings:
    """v2.8 (ROADMAP B1): Blueprint components are taxonomy, not conformance."""

    def test_every_mapped_component_is_in_the_catalog(self):
        from safeai.controls.catalogs import BLUEPRINT
        from safeai.controls.mappings import BLUEPRINT_MAPPINGS
        for rule_id, components in BLUEPRINT_MAPPINGS.items():
            for component in components:
                assert component in BLUEPRINT, f"{rule_id} maps to unknown {component}"

    def test_catalog_holds_only_static_evidence_components(self):
        """Runtime components (P3 authorization, P4 response) stay out of scope."""
        from safeai.controls.catalogs import BLUEPRINT
        for control_id, control in BLUEPRINT.items():
            assert control_id.startswith(("BP-P1-", "BP-P2-", "BP-P4-RECOVERY"))
            assert control["framework"] == "blueprint"

    def test_framework_name_claims_no_membership(self):
        from safeai.controls.catalogs import FRAMEWORKS
        name = FRAMEWORKS["blueprint"]["name"].lower()
        assert "publicly available" in name
        for word in ("member", "certified", "compliant", "conformant"):
            assert word not in name

    def test_blueprint_mappings_join_existing_rule_mappings(self):
        from safeai.controls.mappings import map_rule_to_controls
        controls = {(m["framework"], m["control_id"]) for m in map_rule_to_controls("GOV_APPROVAL_MISSING")}
        assert ("owasp_agentic", "AGENTIC05") in controls
        assert ("blueprint", "BP-P2-GOVERNANCE") in controls


def test_scan_writes_control_mappings_to_json_and_sarif_only(kya_project, tmp_path):
    """JSON and SARIF carry mappings; the manifest (and its digest) does not."""
    import json

    from safeai.cmd.cli import main

    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    manifest_path = tmp_path / "manifest.json"
    main(["scan", kya_project["root"], "--json", str(json_path), "--sarif", str(sarif_path),
          "--manifest", str(manifest_path), "--no-registry"])

    report = json.loads(json_path.read_text(encoding="utf-8"))
    mapped = [f for f in report["findings"] if f.get("control_mappings")]
    assert mapped, "no finding carries control mappings"
    assert all("control_mappings" in f for f in report["findings"])

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    with_controls = [r for r in run["results"] if r.get("properties", {}).get("controls")]
    assert with_controls
    assert all(":" in ref for r in with_controls for ref in r["properties"]["controls"])
    tagged = [r for r in run["tool"]["driver"]["rules"] if r.get("properties", {}).get("tags")]
    assert tagged and all(r["properties"]["tags"][0] == "security" for r in tagged)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert not any("control_mappings" in f for f in manifest["findings"])
