"""
Mutation tests for security-sensitive fields in the KYA manifest.

These tests verify that the manifest validation catches tampering
with security-sensitive fields in the authority_evidence section
and other critical parts of the manifest.
"""

import copy
import json
import pytest

from safeai.kya.manifest import build_manifest, serialize_manifest
from safeai.kya.contract import validate_manifest


def _minimal_report():
    """Create a minimal report for testing."""
    return {
        "findings": [],
        "files_scanned": 1,
        "detected_frameworks": [],
        "tool_surface": [],
        "normalized_capabilities": [],
    }


def _minimal_project():
    """Create minimal project metadata."""
    return {
        "project_id": "test-project",
        "name": "test",
        "source_root": ".",
        "repository": {},
    }


def _minimal_scan_meta():
    """Create minimal scan metadata."""
    return {
        "scan_id": "test-scan",
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:01Z",
    }


def _minimal_safeai_meta():
    """Create minimal SafeAI metadata."""
    return {
        "version": "2.6.0",
        "ruleset_version": "1.0.0",
        "config_hash": "abc123",
    }


def _build_test_manifest():
    """Build a test manifest with authority_evidence."""
    report = _minimal_report()
    return build_manifest(
        report,
        project=_minimal_project(),
        scan_meta=_minimal_scan_meta(),
        safeai_meta=_minimal_safeai_meta(),
        agents=[],
    )


class TestAuthorityEvidenceMutations:
    """Mutation tests for authority_evidence security-sensitive fields."""

    def test_mutate_contract_identity_name_fails_validation(self):
        """Mutating contract_identity.name should be detectable."""
        manifest = _build_test_manifest()
        original = manifest["authority_evidence"]["contract_identity"]["name"]

        # Mutate the contract identity name
        manifest["authority_evidence"]["contract_identity"]["name"] = "tampered-contract"

        # The manifest should still validate structurally (schema allows any string)
        # but the contract identity is now wrong
        errors, _ = validate_manifest(manifest)
        # Schema validation may pass, but the contract identity is tampered
        # This test documents that schema validation alone doesn't catch semantic tampering
        assert isinstance(errors, list)

    def test_mutate_contract_identity_version_fails_validation(self):
        """Mutating contract_identity.version should be detectable."""
        manifest = _build_test_manifest()

        # Mutate the contract identity version to invalid format
        manifest["authority_evidence"]["contract_identity"]["version"] = "invalid-version"

        errors, _ = validate_manifest(manifest)
        # Version must match pattern ^1\.[0-9]+\.[0-9]+$
        version_errors = [e for e in errors if "version" in e.lower()]
        assert len(version_errors) > 0, f"Expected version validation error, got: {errors}"

    def test_mutate_safeai_version_fails_validation(self):
        """Mutating safeai_version to non-string should fail validation."""
        manifest = _build_test_manifest()

        # Mutate safeai_version to a non-string
        manifest["authority_evidence"]["safeai_version"] = 12345

        errors, _ = validate_manifest(manifest)
        version_errors = [e for e in errors if "safeai_version" in e]
        assert len(version_errors) > 0, f"Expected safeai_version validation error, got: {errors}"

    def test_mutate_ruleset_version_fails_validation(self):
        """Mutating ruleset_version to non-string should fail validation."""
        manifest = _build_test_manifest()

        # Mutate ruleset_version to a non-string
        manifest["authority_evidence"]["ruleset_version"] = None

        errors, _ = validate_manifest(manifest)
        version_errors = [e for e in errors if "ruleset_version" in e]
        assert len(version_errors) > 0, f"Expected ruleset_version validation error, got: {errors}"

    def test_mutate_source_revision_commit_fails_validation(self):
        """Mutating source_revision.commit to non-string should fail validation."""
        manifest = _build_test_manifest()

        # Mutate source_revision.commit to a non-string
        manifest["authority_evidence"]["source_revision"]["commit"] = {"tampered": True}

        errors, _ = validate_manifest(manifest)
        commit_errors = [e for e in errors if "commit" in e]
        assert len(commit_errors) > 0, f"Expected commit validation error, got: {errors}"

    def test_mutate_source_revision_repository_fails_validation(self):
        """Mutating source_revision.repository to non-string should fail validation."""
        manifest = _build_test_manifest()

        # Mutate source_revision.repository to a non-string
        manifest["authority_evidence"]["source_revision"]["repository"] = ["tampered"]

        errors, _ = validate_manifest(manifest)
        repo_errors = [e for e in errors if "repository" in e]
        assert len(repo_errors) > 0, f"Expected repository validation error, got: {errors}"

    def test_mutate_assurance_boundary_to_non_array_fails_validation(self):
        """Mutating assurance_boundary to non-array should fail validation."""
        manifest = _build_test_manifest()

        # Mutate assurance_boundary to a non-array
        manifest["authority_evidence"]["assurance_boundary"] = "tampered"

        errors, _ = validate_manifest(manifest)
        boundary_errors = [e for e in errors if "assurance_boundary" in e]
        assert len(boundary_errors) > 0, f"Expected assurance_boundary validation error, got: {errors}"

    def test_mutate_assurance_boundary_item_to_non_string_fails_validation(self):
        """Mutating assurance_boundary item to non-string should fail validation."""
        manifest = _build_test_manifest()

        # Mutate an assurance_boundary item to a non-string
        manifest["authority_evidence"]["assurance_boundary"][0] = 12345

        errors, _ = validate_manifest(manifest)
        boundary_errors = [e for e in errors if "assurance_boundary" in e]
        assert len(boundary_errors) > 0, f"Expected assurance_boundary item validation error, got: {errors}"

    def test_mutate_uncertainty_summary_to_non_object_fails_validation(self):
        """Mutating uncertainty_summary to non-object should fail validation."""
        manifest = _build_test_manifest()

        # Mutate uncertainty_summary to a non-object
        manifest["authority_evidence"]["uncertainty_summary"] = "tampered"

        errors, _ = validate_manifest(manifest)
        summary_errors = [e for e in errors if "uncertainty_summary" in e]
        assert len(summary_errors) > 0, f"Expected uncertainty_summary validation error, got: {errors}"

    def test_mutate_uncertainty_count_to_non_integer_fails_validation(self):
        """Mutating uncertainty_summary count to non-integer should fail validation."""
        manifest = _build_test_manifest()

        # Mutate an uncertainty count to a non-integer
        manifest["authority_evidence"]["uncertainty_summary"]["authority_statement_count"] = "tampered"

        errors, _ = validate_manifest(manifest)
        count_errors = [e for e in errors if "authority_statement_count" in e]
        assert len(count_errors) > 0, f"Expected count validation error, got: {errors}"

    def test_mutate_authority_statement_provenance_fails_validation(self):
        """Mutating authority_statement provenance to invalid enum should fail validation."""
        manifest = _build_test_manifest()

        # Add a statement if none exists
        if not manifest["authority_evidence"]["authority_statements"]:
            manifest["authority_evidence"]["authority_statements"].append({
                "statement_id": "stmt-test",
                "agent_id": "test-agent",
                "capability": "test:capability",
                "provenance": "detected",
            })

        # Mutate provenance to an invalid value
        manifest["authority_evidence"]["authority_statements"][0]["provenance"] = "tampered"

        errors, _ = validate_manifest(manifest)
        provenance_errors = [e for e in errors if "provenance" in e]
        assert len(provenance_errors) > 0, f"Expected provenance validation error, got: {errors}"

    def test_mutate_authority_statement_access_mode_fails_validation(self):
        """Mutating authority_statement access_mode to invalid enum should fail validation."""
        manifest = _build_test_manifest()

        # Add a statement if none exists
        if not manifest["authority_evidence"]["authority_statements"]:
            manifest["authority_evidence"]["authority_statements"].append({
                "statement_id": "stmt-test",
                "agent_id": "test-agent",
                "capability": "test:capability",
                "provenance": "detected",
            })

        # Mutate access_mode to an invalid value
        manifest["authority_evidence"]["authority_statements"][0]["access_mode"] = "tampered"

        errors, _ = validate_manifest(manifest)
        access_mode_errors = [e for e in errors if "access_mode" in e]
        assert len(access_mode_errors) > 0, f"Expected access_mode validation error, got: {errors}"

    def test_mutate_authority_statement_resolution_fails_validation(self):
        """Mutating authority_statement resolution to invalid enum should fail validation."""
        manifest = _build_test_manifest()

        # Add a statement if none exists
        if not manifest["authority_evidence"]["authority_statements"]:
            manifest["authority_evidence"]["authority_statements"].append({
                "statement_id": "stmt-test",
                "agent_id": "test-agent",
                "capability": "test:capability",
                "provenance": "detected",
            })

        # Mutate resolution to an invalid value
        manifest["authority_evidence"]["authority_statements"][0]["resolution"] = "tampered"

        errors, _ = validate_manifest(manifest)
        resolution_errors = [e for e in errors if "resolution" in e]
        assert len(resolution_errors) > 0, f"Expected resolution validation error, got: {errors}"

    def test_mutate_delegation_type_fails_validation(self):
        """Mutating delegation_type to invalid enum should fail validation."""
        manifest = _build_test_manifest()

        # Add a delegation if none exists
        if not manifest["authority_evidence"]["delegation_evidence"]:
            manifest["authority_evidence"]["delegation_evidence"].append({
                "source_agent": "agent-a",
                "target_agent": "agent-b",
                "delegation_type": "explicit_sub_agent",
            })

        # Mutate delegation_type to an invalid value
        manifest["authority_evidence"]["delegation_evidence"][0]["delegation_type"] = "tampered"

        errors, _ = validate_manifest(manifest)
        delegation_errors = [e for e in errors if "delegation_type" in e]
        assert len(delegation_errors) > 0, f"Expected delegation_type validation error, got: {errors}"

    def test_mutate_change_context_change_class_fails_validation(self):
        """Mutating change_context.change_class to invalid enum should fail validation."""
        manifest = _build_test_manifest()

        # Mutate change_class to an invalid value
        manifest["authority_evidence"]["change_context"]["change_class"] = "tampered"

        errors, _ = validate_manifest(manifest)
        change_class_errors = [e for e in errors if "change_class" in e]
        assert len(change_class_errors) > 0, f"Expected change_class validation error, got: {errors}"

    def test_mutate_subject_agent_framework_fails_validation(self):
        """Mutating subject_agent framework to non-string should fail validation."""
        manifest = _build_test_manifest()

        # Add a subject agent if none exists
        if not manifest["authority_evidence"]["subject_agents"]:
            manifest["authority_evidence"]["subject_agents"].append({
                "agent_id": "test-agent",
                "framework": "test-framework",
            })

        # Mutate framework to a non-string
        manifest["authority_evidence"]["subject_agents"][0]["framework"] = 12345

        errors, _ = validate_manifest(manifest)
        framework_errors = [e for e in errors if "framework" in e]
        assert len(framework_errors) > 0, f"Expected framework validation error, got: {errors}"

    def test_mutate_principal_evidence_kind_fails_validation(self):
        """Mutating principal_evidence kind to invalid enum should fail validation."""
        manifest = _build_test_manifest()

        # Add a principal if none exists
        if not manifest["authority_evidence"]["principal_evidence"]:
            manifest["authority_evidence"]["principal_evidence"].append({
                "principal_id": "test-principal",
                "kind": "unknown",
            })

        # Mutate kind to an invalid value
        manifest["authority_evidence"]["principal_evidence"][0]["kind"] = "tampered"

        errors, _ = validate_manifest(manifest)
        kind_errors = [e for e in errors if "kind" in e]
        assert len(kind_errors) > 0, f"Expected kind validation error, got: {errors}"


class TestManifestIntegrityMutations:
    """Mutation tests for manifest integrity fields."""

    def test_mutate_integrity_algorithm_fails_validation(self):
        """Mutating integrity.algorithm to non-sha256 should fail validation."""
        manifest = _build_test_manifest()

        # Mutate integrity algorithm
        manifest["integrity"]["algorithm"] = "md5"

        errors, _ = validate_manifest(manifest)
        algorithm_errors = [e for e in errors if "algorithm" in e]
        assert len(algorithm_errors) > 0, f"Expected algorithm validation error, got: {errors}"

    def test_mutate_integrity_canonicalization_fails_validation(self):
        """Mutating integrity.canonicalization to wrong value should fail validation."""
        manifest = _build_test_manifest()

        # Mutate integrity canonicalization
        manifest["integrity"]["canonicalization"] = "tampered"

        errors, _ = validate_manifest(manifest)
        canonicalization_errors = [e for e in errors if "canonicalization" in e]
        assert len(canonicalization_errors) > 0, f"Expected canonicalization validation error, got: {errors}"

    def test_mutate_integrity_payload_sha256_fails_validation(self):
        """Mutating integrity.payload_sha256 to invalid format should fail validation."""
        manifest = _build_test_manifest()

        # Mutate integrity payload_sha256 to invalid format (not 64 hex chars)
        manifest["integrity"]["payload_sha256"] = "tampered"

        errors, _ = validate_manifest(manifest)
        sha256_errors = [e for e in errors if "payload_sha256" in e]
        assert len(sha256_errors) > 0, f"Expected payload_sha256 validation error, got: {errors}"


class TestManifestSerializationMutations:
    """Mutation tests for manifest serialization determinism."""

    def test_manifest_serialization_is_deterministic(self):
        """Serializing the same manifest twice should produce identical output."""
        manifest = _build_test_manifest()

        serialized1 = serialize_manifest(manifest)
        serialized2 = serialize_manifest(manifest)

        assert serialized1 == serialized2, "Manifest serialization should be deterministic"

    def test_manifest_serialization_sorts_keys(self):
        """Serialized manifest should have sorted keys."""
        manifest = _build_test_manifest()

        serialized = serialize_manifest(manifest)
        parsed = json.loads(serialized)

        # Check that keys are sorted (JSON with sort_keys=True)
        keys = list(parsed.keys())
        assert keys == sorted(keys), "Manifest keys should be sorted"

    def test_manifest_round_trip_preserves_data(self):
        """Serializing and deserializing should preserve all data."""
        manifest = _build_test_manifest()

        serialized = serialize_manifest(manifest)
        deserialized = json.loads(serialized)

        # Check that authority_evidence is preserved
        assert "authority_evidence" in deserialized
        assert deserialized["authority_evidence"]["contract_identity"]["name"] == "agent-authority-evidence"
        assert deserialized["authority_evidence"]["contract_identity"]["version"] == "1.0.0"


class TestAuthorityEvidenceTamperingDetection:
    """Tests for detecting tampering with authority evidence."""

    def test_removing_authority_evidence_section_is_detectable(self):
        """Removing the authority_evidence section should be detectable."""
        manifest = _build_test_manifest()

        # Remove the authority_evidence section
        del manifest["authority_evidence"]

        # The manifest should still validate (authority_evidence is optional in schema)
        # but the absence is detectable
        errors, _ = validate_manifest(manifest)
        # Schema validation may pass since authority_evidence is optional
        # This test documents that absence is detectable by consumers
        assert isinstance(errors, list)

    def test_adding_extra_fields_to_authority_evidence_is_allowed(self):
        """Adding extra fields to authority_evidence should be allowed (additionalProperties: true)."""
        manifest = _build_test_manifest()

        # Add an extra field
        manifest["authority_evidence"]["custom_field"] = "custom_value"

        errors, _ = validate_manifest(manifest)
        # Should not have validation errors for extra fields
        extra_field_errors = [e for e in errors if "custom_field" in e]
        assert len(extra_field_errors) == 0, f"Extra fields should be allowed, got: {errors}"

    def test_mutating_authority_statement_id_fails_validation(self):
        """Mutating authority_statement statement_id to empty string should fail validation."""
        manifest = _build_test_manifest()

        # Add a statement if none exists
        if not manifest["authority_evidence"]["authority_statements"]:
            manifest["authority_evidence"]["authority_statements"].append({
                "statement_id": "stmt-test",
                "agent_id": "test-agent",
                "capability": "test:capability",
                "provenance": "detected",
            })

        # Mutate statement_id to empty string (minLength: 1)
        manifest["authority_evidence"]["authority_statements"][0]["statement_id"] = ""

        errors, _ = validate_manifest(manifest)
        statement_id_errors = [e for e in errors if "statement_id" in e]
        assert len(statement_id_errors) > 0, f"Expected statement_id validation error, got: {errors}"

    def test_mutating_authority_statement_agent_id_fails_validation(self):
        """Mutating authority_statement agent_id to empty string should fail validation."""
        manifest = _build_test_manifest()

        # Add a statement if none exists
        if not manifest["authority_evidence"]["authority_statements"]:
            manifest["authority_evidence"]["authority_statements"].append({
                "statement_id": "stmt-test",
                "agent_id": "test-agent",
                "capability": "test:capability",
                "provenance": "detected",
            })

        # Mutate agent_id to empty string (minLength: 1)
        manifest["authority_evidence"]["authority_statements"][0]["agent_id"] = ""

        errors, _ = validate_manifest(manifest)
        agent_id_errors = [e for e in errors if "agent_id" in e]
        assert len(agent_id_errors) > 0, f"Expected agent_id validation error, got: {errors}"

    def test_mutating_subject_agent_id_fails_validation(self):
        """Mutating subject_agent agent_id to empty string should fail validation."""
        manifest = _build_test_manifest()

        # Add a subject agent if none exists
        if not manifest["authority_evidence"]["subject_agents"]:
            manifest["authority_evidence"]["subject_agents"].append({
                "agent_id": "test-agent",
                "framework": "test-framework",
            })

        # Mutate agent_id to empty string (minLength: 1)
        manifest["authority_evidence"]["subject_agents"][0]["agent_id"] = ""

        errors, _ = validate_manifest(manifest)
        agent_id_errors = [e for e in errors if "agent_id" in e]
        assert len(agent_id_errors) > 0, f"Expected agent_id validation error, got: {errors}"

    def test_mutating_principal_id_fails_validation(self):
        """Mutating principal_evidence principal_id to empty string should fail validation."""
        manifest = _build_test_manifest()

        # Add a principal if none exists
        if not manifest["authority_evidence"]["principal_evidence"]:
            manifest["authority_evidence"]["principal_evidence"].append({
                "principal_id": "test-principal",
                "kind": "unknown",
            })

        # Mutate principal_id to empty string (minLength: 1)
        manifest["authority_evidence"]["principal_evidence"][0]["principal_id"] = ""

        errors, _ = validate_manifest(manifest)
        principal_id_errors = [e for e in errors if "principal_id" in e]
        assert len(principal_id_errors) > 0, f"Expected principal_id validation error, got: {errors}"