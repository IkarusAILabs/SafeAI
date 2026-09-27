"""Manifest Contract v1 — versioned public contract for ``safeai-manifest.json``.

The contract version (``contract.version``, e.g. ``1.0.0``) is distinct from
the package version (``safeai.version``, e.g. ``2.2.x``) and from the legacy
document ``schema_version`` string (``1.0``/``1.1``/``1.2``).

Validation here is intentionally standard-library only: it enforces the
structural guarantees SafeAI itself relies on (required keys, value domains,
compatibility semantics) rather than executing a full JSON-Schema draft
engine. The published schema file
(``schemas/safeai-manifest/v1.0.0.json``) is the normative reference for
third-party consumers with their own validators; this module's verdicts
agree with it on every required-field and enum rule.

Limitation (documented honestly): this validator does not evaluate
``$ref``/``$dynamicRef``, regex ``pattern`` keywords beyond the two pinned
constants, or ``minLength`` on optional strings — it checks the shapes
SafeAI emits. Unknown optional fields are always ignored (never rejected),
per ``docs/manifest/COMPATIBILITY.md``.
"""

from __future__ import annotations

CONTRACT_NAME = "safeai-manifest"
CONTRACT_VERSION = "1.0.0"
CONTRACT_MIN_READER = "1.0.0"

#: Legacy document versions this contract accepts (purely additive history).
COMPATIBLE_SCHEMA_VERSIONS = ("1.0", "1.1", "1.2")

SEVERITIES = ("critical", "high", "medium", "low", "info")
POLICY_OUTCOMES = ("pass", "warn", "review-required", "block", "accepted-exception")
PROVENANCE_CLASSES = ("declared", "detected", "inferred", "unknown",
                      "repo-iac-observed")
GATEABILITY_VALUES = ("deterministic", "review-only")
CHANGE_CLASSES = ("NO_CHANGE", "LOW_CHANGE", "MATERIAL_CHANGE", "HIGH_RISK_CHANGE", "UNKNOWN")
EXCEPTION_STATES = ("active", "expired", "stale", "scope-mismatch", "invalid")
#: IaC authority correlation verdicts (v2.5, ADR-0007).
CORRELATION_VERDICTS = ("MATCH", "EXCESS_AUTHORITY", "AUTHORITY_MISMATCH",
                        "UNVERIFIED_LINK", "UNKNOWN")


def contract_block():
    """Return the ``contract`` metadata block stamped into new manifests."""
    return {
        "name": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "compatibility": {"minimum_reader_version": CONTRACT_MIN_READER},
    }


def _err(errors, path, message):
    errors.append(f"{path}: {message}")
    return errors


def validate_manifest(document):
    """Validate a manifest document against Contract v1.

    Returns ``(errors, warnings)`` — both lists of human-readable,
    field-level strings. ``errors`` empty means the document validates.
    Never raises on malformed input; never touches the network.
    """
    errors, warnings = [], []

    if not isinstance(document, dict):
        return (["$: root must be a JSON object"], warnings)

    # --- schema_version / contract compatibility -------------------------
    schema_version = document.get("schema_version")
    if schema_version not in COMPATIBLE_SCHEMA_VERSIONS:
        _err(errors, "$.schema_version",
             f"unsupported schema_version {schema_version!r} "
             f"(supported: {', '.join(COMPATIBLE_SCHEMA_VERSIONS)})")
    elif schema_version != "1.2":
        warnings.append(
            f"$.schema_version: {schema_version!r} predates 1.2; "
            "tool_surface/assurance_boundary may be absent (still importable)")

    contract = document.get("contract")
    if contract is not None:
        if not isinstance(contract, dict):
            _err(errors, "$.contract", "must be an object")
        else:
            if contract.get("name") != CONTRACT_NAME:
                _err(errors, "$.contract.name",
                     f"must be {CONTRACT_NAME!r}, got {contract.get('name')!r}")
            version = str(contract.get("version") or "")
            parts = version.split(".")
            if len(parts) != 3 or not all(p.isdigit() for p in parts):
                _err(errors, "$.contract.version",
                     f"must be semver x.y.z, got {version!r}")
            elif parts[0] != "1":
                _err(errors, "$.contract.version",
                     f"unsupported contract major version {version!r} "
                     "(this reader supports 1.x)")

    # --- manifest_type ----------------------------------------------------
    if document.get("manifest_type") != "safeai.kya":
        _err(errors, "$.manifest_type",
             f"must be 'safeai.kya', got {document.get('manifest_type')!r}")

    # --- safeai -----------------------------------------------------------
    safeai = document.get("safeai")
    if not isinstance(safeai, dict):
        _err(errors, "$.safeai", "must be an object")
    elif not safeai.get("version"):
        _err(errors, "$.safeai.version", "must be a non-empty version string")

    # --- project ----------------------------------------------------------
    project = document.get("project")
    if not isinstance(project, dict):
        _err(errors, "$.project", "must be an object")
    elif not (isinstance(project.get("project_id"), str) and project["project_id"].strip()):
        _err(errors, "$.project.project_id", "must be a non-empty string")

    # --- agents -----------------------------------------------------------
    agents = document.get("agents")
    if not isinstance(agents, list):
        _err(errors, "$.agents", "must be an array")
    else:
        for i, agent in enumerate(agents):
            if not isinstance(agent, dict) or not agent.get("agent_id"):
                _err(errors, f"$.agents[{i}].agent_id", "must be a non-empty string")

    # --- findings ---------------------------------------------------------
    findings = document.get("findings")
    if not isinstance(findings, list):
        _err(errors, "$.findings", "must be an array")
    else:
        for i, finding in enumerate(findings):
            base = f"$.findings[{i}]"
            if not isinstance(finding, dict):
                _err(errors, base, "must be an object")
                continue
            if not finding.get("rule_id"):
                _err(errors, f"{base}.rule_id", "must be a non-empty string")
            if finding.get("severity") not in SEVERITIES:
                _err(errors, f"{base}.severity",
                     f"must be one of {', '.join(SEVERITIES)}, "
                     f"got {finding.get('severity')!r}")
            if "provenance_class" in finding and finding["provenance_class"] not in PROVENANCE_CLASSES:
                _err(errors, f"{base}.provenance_class",
                     f"must be one of {', '.join(PROVENANCE_CLASSES)}, "
                     f"got {finding['provenance_class']!r}")
            if "gateability" in finding and finding["gateability"] not in GATEABILITY_VALUES:
                _err(errors, f"{base}.gateability",
                     f"must be one of {', '.join(GATEABILITY_VALUES)}, "
                     f"got {finding['gateability']!r}")

    # --- summary / policy decision ----------------------------------------
    summary = document.get("summary")
    if not isinstance(summary, dict):
        _err(errors, "$.summary", "must be an object")
    else:
        decision = summary.get("policy_decision")
        if not isinstance(decision, dict):
            _err(errors, "$.summary.policy_decision", "must be an object")
        elif decision.get("outcome") not in POLICY_OUTCOMES:
            _err(errors, "$.summary.policy_decision.outcome",
                 f"must be one of {', '.join(POLICY_OUTCOMES)}, "
                 f"got {decision.get('outcome')!r}")

    # --- escalations (optional; present when a baseline diff exists) -------
    escalations = document.get("escalations")
    if escalations is not None:
        if not isinstance(escalations, list):
            _err(errors, "$.escalations", "must be an array")
        else:
            for i, escalation in enumerate(escalations):
                base = f"$.escalations[{i}]"
                if not isinstance(escalation, dict):
                    _err(errors, base, "must be an object")
                    continue
                if not escalation.get("id"):
                    _err(errors, f"{base}.id", "must be a non-empty string")
                if escalation.get("severity") not in SEVERITIES:
                    _err(errors, f"{base}.severity",
                         f"must be one of {', '.join(SEVERITIES)}, "
                         f"got {escalation.get('severity')!r}")

    # --- authority_changes (optional; v2.4 portable change evidence) --------
    authority_changes = document.get("authority_changes")
    if authority_changes is not None:
        if not isinstance(authority_changes, list):
            _err(errors, "$.authority_changes", "must be an array")
        else:
            for i, change in enumerate(authority_changes):
                base = f"$.authority_changes[{i}]"
                if not isinstance(change, dict):
                    _err(errors, base, "must be an object")
                    continue
                if not change.get("tool_key"):
                    _err(errors, f"{base}.tool_key", "must be a non-empty string")
                if change.get("change_class") not in CHANGE_CLASSES:
                    _err(errors, f"{base}.change_class",
                         f"must be one of {', '.join(CHANGE_CLASSES)}, "
                         f"got {change.get('change_class')!r}")

    # --- exception_evaluations (optional; v2.4 exception evidence) ----------
    evaluations = document.get("exception_evaluations")
    if evaluations is not None:
        if not isinstance(evaluations, list):
            _err(errors, "$.exception_evaluations", "must be an array")
        else:
            for i, evaluation in enumerate(evaluations):
                base = f"$.exception_evaluations[{i}]"
                if not isinstance(evaluation, dict):
                    _err(errors, base, "must be an object")
                    continue
                if not evaluation.get("exception_id"):
                    _err(errors, f"{base}.exception_id", "must be a non-empty string")
                if evaluation.get("state") not in EXCEPTION_STATES:
                    _err(errors, f"{base}.state",
                         f"must be one of {', '.join(EXCEPTION_STATES)}, "
                         f"got {evaluation.get('state')!r}")

    # --- iac_correlations (optional; v2.5 IaC authority evidence) --------
    iac = document.get("iac_correlations")
    if iac is not None:
        if not isinstance(iac, dict):
            _err(errors, "$.iac_correlations", "must be an object")
        else:
            if iac.get("lane") not in (None, "B"):
                _err(errors, "$.iac_correlations.lane",
                     f"must be 'B' (IaC output is review-only), "
                     f"got {iac.get('lane')!r}")
            for i, verdict in enumerate(iac.get("verdicts") or []):
                base = f"$.iac_correlations.verdicts[{i}]"
                if not isinstance(verdict, dict):
                    _err(errors, base, "must be an object")
                    continue
                if verdict.get("verdict") not in CORRELATION_VERDICTS:
                    _err(errors, f"{base}.verdict",
                         f"must be one of {', '.join(CORRELATION_VERDICTS)}, "
                         f"got {verdict.get('verdict')!r}")
                if verdict.get("verdict") not in (None, "UNKNOWN"):
                    refs = (verdict.get("declared_evidence_refs") or []) + \
                           (verdict.get("grant_evidence_refs") or [])
                    if not refs:
                        _err(errors, base,
                             "non-UNKNOWN verdicts must cite declared or "
                             "grant evidence refs")
            for i, grant in enumerate(iac.get("grants") or []):
                base = f"$.iac_correlations.grants[{i}]"
                if not isinstance(grant, dict):
                    _err(errors, base, "must be an object")
                    continue
                if not grant.get("source_file"):
                    _err(errors, f"{base}.source_file",
                         "must be a non-empty string")

    # --- assurance boundary / limitations ---------------------------------
    if "assurance_boundary" not in document:
        _err(errors, "$.assurance_boundary", "is required (static-evidence statement)")
    limitations = document.get("limitations")
    if not isinstance(limitations, list) or not limitations:
        _err(errors, "$.limitations", "must be a non-empty array of strings")

    # --- integrity (optional on pre-2.2 manifests) -------------------------
    integrity = document.get("integrity")
    if integrity is not None:
        if not isinstance(integrity, dict):
            _err(errors, "$.integrity", "must be an object")
        else:
            if integrity.get("algorithm") != "sha256":
                _err(errors, "$.integrity.algorithm", "must be 'sha256'")
            if integrity.get("canonicalization") != "safeai-manifest-v1":
                _err(errors, "$.integrity.canonicalization",
                     "must be 'safeai-manifest-v1'")
            digest = integrity.get("payload_sha256") or ""
            if not (isinstance(digest, str) and len(digest) == 64
                    and all(c in "0123456789abcdef" for c in digest)):
                _err(errors, "$.integrity.payload_sha256",
                     "must be 64 lowercase hex characters")

    return (errors, warnings)
