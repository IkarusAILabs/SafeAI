"""Canonical KYA manifest: ``safeai-manifest.json`` (schema version 1.2).

The manifest is the portable public contract for scan-derived KYA
evidence. The SQLite registry is an implementation detail; integrations
should consume the manifest, not the database.

Determinism contract:
  * Same repository, configuration, ruleset, and commit produce an
    equivalent manifest (``generated_at``/``scan_id``/timestamps aside).
  * Serialization uses sorted keys and stable ordering of agents and
    findings so diffs between runs are meaningful.
  * No raw source code or unredacted secret values are ever included.
"""

import json
import os

from safeai.kya import (
    MANIFEST_SCHEMA_VERSION,
    MANIFEST_TYPE,
    STATIC_ANALYSIS_DISCLAIMER,
)
from safeai.kya.assurance import build_assurance_boundary
from safeai.kya.contract import contract_block
from safeai.kya.fingerprints import normalize_path
from safeai.kya.integrity import payload_digest, stamp_integrity
from safeai.kya.util import confidence_label, redact_secrets, sha256_text
from safeai.severity import SEVERITIES

SEVERITY_ORDER = list(reversed(SEVERITIES))


def config_hash(effective_config):
    """Compute a deterministic SHA-256 hash of normalized configuration."""
    canonical = json.dumps(effective_config or {}, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_text(canonical)


def _finding_entry(finding):
    return {
        "finding_id": finding.get("finding_id") or finding.get("fingerprint"),
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity", "medium"),
        "title": finding.get("title") or str(finding.get("message", "")).split("\n")[0][:120],
        "message": redact_secrets(str(finding.get("message", ""))),
        "remediation": finding.get("remediation"),
        "confidence": confidence_label(finding.get("confidence_label") or finding.get("confidence")),
        "provenance": finding.get("provenance") or {"analyzer": "unknown", "evidence": []},
        "provenance_class": finding.get("provenance_class", "unknown"),
        "gateability": finding.get("gateability", "review-only"),
        "location": {
            "path": normalize_path(finding.get("file")),
            "line_start": int(finding.get("line") or 0),
            "line_end": int(finding.get("line") or 0),
        },
        "fingerprint": finding.get("fingerprint"),
        "status": finding.get("status", "unknown"),
    }


def _authority_change_entries(report):
    """Compact per-tool authority changes for portable evidence.

    Carries change_class + change_types (never severity-derived beyond
    the classification itself); full tool entries stay in the report.
    """
    entries = []
    diff = report.get("capability_diff") or {}
    for tool in diff.get("tools") or []:
        if tool.get("status", "unchanged") == "unchanged" and not tool.get("escalations"):
            continue
        entries.append({
            "tool_key": tool.get("tool_key"),
            "status": tool.get("status"),
            "change_class": tool.get("change_class", "UNKNOWN"),
            "change_types": tool.get("change_types") or [],
            "inferred_only": bool(tool.get("inferred_only")),
        })
    entries.sort(key=lambda e: str(e.get("tool_key")))
    return entries


def _authority_change_counts(report):
    """Summary counts of authority change classes (portable, additive)."""
    diff = report.get("capability_diff") or {}
    counts = (diff.get("counts") or {}).get("by_change_class")
    if isinstance(counts, dict):
        return dict(counts)
    return {}


def _iac_correlations_entry(report):
    """Compact IaC authority correlation evidence (v2.5, Lane B).

    Returns None when the scan carries no IaC correlation (no IaC
    sources, or a pre-v2.5 report) so the block stays absent rather
    than empty. Schema v2: identities, agent_identity_links, grants,
    grant_bindings, verdicts with full evidence refs.
    """
    iac = report.get("iac_correlations")
    if not isinstance(iac, dict):
        return None
    if not (iac.get("grants") or iac.get("verdicts")):
        return None
    return {
        "schema_version": int(iac.get("schema_version") or 2),
        "correlation_model": iac.get("correlation_model"),
        "lane": "B",
        "files": iac.get("files") or {},
        "identities": iac.get("identities") or [],
        "agent_identity_links": iac.get("agent_identity_links") or [],
        "grants": iac.get("grants") or [],
        "grant_bindings": iac.get("grant_bindings") or [],
        "verdicts": iac.get("verdicts") or [],
        "counts": iac.get("counts") or {},
    }


def _capability_counts(agents, report):
    counts = {}
    seen = set()
    for agent in agents:
        for cap in agent.get("capabilities") or []:
            name = str(cap.get("name", "")).lower()
            if name and name not in seen:
                seen.add(name)
                category = cap.get("category", "Capability")
                counts[category] = counts.get(category, 0) + 1
    if not counts:
        for cap in report.get("normalized_capabilities") or []:
            category = cap.get("category", "Capability")
            counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def _escalation_entries(report):
    """Flatten capability-diff escalations (with remediation) for the manifest."""
    entries = []
    diff = report.get("capability_diff") or {}
    for tool in diff.get("tools") or []:
        for escalation in tool.get("escalations") or []:
            entries.append({
                "tool_key": tool.get("tool_key"),
                "id": escalation.get("id"),
                "severity": escalation.get("severity", "medium"),
                "summary": escalation.get("summary"),
                "before": escalation.get("before"),
                "after": escalation.get("after"),
                "confidence": escalation.get("confidence"),
                "remediation": escalation.get("remediation"),
            })
    entries.sort(key=lambda e: (str(e.get("tool_key")), str(e.get("id"))))
    return entries


def build_manifest(report, *, project, scan_meta, safeai_meta, agents,
                   policy_decision=None, limitations=None):
    """Assemble the canonical manifest dict from a normalized scan report.

    Parameters
    ----------
    report : dict
        The scan report (findings already normalized via ``enrich``).
    project : dict
        Keys: ``project_id``, ``name``, ``source_root``, ``repository``.
    scan_meta : dict
        Keys: ``scan_id``, ``started_at``, ``completed_at``.
    safeai_meta : dict
        Keys: ``version``, ``ruleset_version``, ``config_hash``,
        ``analyzer_versions`` (name -> version), ``parser_versions``.
    agents : list
        KYA agent records (from ``enrich.build_agent_records``).
    policy_decision : dict, optional
        Evaluated policy outcome; defaults to ``warn``-style neutral.
    """
    findings = [_finding_entry(f) for f in report.get("findings", [])]
    findings.sort(key=lambda f: (f["fingerprint"] or ""))

    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        sev = finding.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    trust = report.get("trust_score") or {}

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "manifest_type": MANIFEST_TYPE,
        "contract": contract_block(),
        "generated_at": scan_meta.get("completed_at"),
        "safeai": {
            "version": safeai_meta.get("version"),
            "ruleset_version": safeai_meta.get("ruleset_version"),
            "config_hash": safeai_meta.get("config_hash"),
            "custom_rules_dir": safeai_meta.get("custom_rules_dir"),
            "custom_rules_count": safeai_meta.get("custom_rules_count", 0),
            "builtin_rules_count": safeai_meta.get("builtin_rules_count", 0),
            "rule_pack_ids": safeai_meta.get("rule_pack_ids", []),
            "analyzer_versions": safeai_meta.get("analyzer_versions", {}),
            "parser_versions": safeai_meta.get("parser_versions", {}),
            "policy_profile": safeai_meta.get("policy_profile"),
        },
        "project": {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "source_root": project.get("source_root"),
            "repository": project.get("repository") or {},
        },
        "scan": {
            "scan_id": scan_meta.get("scan_id"),
            "started_at": scan_meta.get("started_at"),
            "completed_at": scan_meta.get("completed_at"),
            "files_scanned": int(report.get("files_scanned") or 0),
            "analysis_coverage": {
                "languages": sorted({"python"} & {"python"}) if report.get("semantic_docs") else ["python"],
                "frameworks_detected": sorted(report.get("detected_frameworks") or []),
                "limitations": ["Static analysis only; dynamic/custom wrappers may reduce coverage."],
            },
        },
        "agents": sorted(agents, key=lambda a: a["agent_id"]),
        # v1.1: per-tool capability surface. Which named tool holds which
        # capability, at which access mode — the unit the v1.4 diff compares.
        "tool_surface": sorted(
            report.get("tool_surface") or [],
            key=lambda t: str(t.get("tool_key")),
        ),
        "components": [
            {
                "type": c.get("type", "unknown"),
                "name": c.get("name"),
                "path": normalize_path(c.get("file")),
                "content_hash": c.get("content_hash"),
            }
            for c in (report.get("components") or [])
        ],
        # CE 1.5: referenced external config/credential names (never values).
        "dependency_inventory": [
            {
                "name": e.get("name"),
                "secret": bool(e.get("secret")),
                "source_count": e.get("source_count", 0),
                "sources": [
                    {"path": normalize_path(s.get("file")), "line": int(s.get("line") or 0)}
                    for s in (e.get("sources") or [])
                ],
            }
            for e in (report.get("dependency_inventory") or [])
        ],
        "findings": findings,
        "escalations": _escalation_entries(report),
        "authority_changes": _authority_change_entries(report),
        "exception_evaluations": [
            {
                "exception_id": e.get("exception_id"),
                "target_type": e.get("target_type", "unspecified"),
                "target_id": e.get("target_id") or e.get("finding_or_policy"),
                "state": e.get("state"),
                "risk_owner": e.get("risk_owner"),
                "expires_at": e.get("expires_at"),
            }
            for e in (report.get("exception_evaluations") or [])
        ],
        # v2.5: IaC authority correlation evidence (Lane B review-only).
        # Optional block: absent on scans without IaC sources or on
        # pre-v2.5 reports. Verdicts cite both sides or are UNKNOWN.
        "iac_correlations": _iac_correlations_entry(report),
        "summary": {
            "risk_score": trust.get("overall_ai_risk_score"),
            "severity_counts": severity_counts,
            "capability_counts": _capability_counts(agents, report),
            "agent_count": len(agents),
            "component_count": len(report.get("components") or []),
            "dependency_count": len(report.get("dependency_inventory") or []),
            "iac_grant_count": len((report.get("iac_correlations") or {}).get("grants") or []),
            "iac_verdict_counts": ((report.get("iac_correlations") or {}).get("counts") or {}),
            "policy_decision": policy_decision or {"outcome": "warn", "reasons": ["No policy file supplied; default posture."]},
            "authority_change_counts": _authority_change_counts(report),
            "highest_change_class": (report.get("capability_diff") or {}).get(
                "highest_change_class", "NO_CHANGE"),
        },
        # v1.2: the assurance boundary states what this scan verified and
        # what it structurally cannot. ``limitations`` is kept as the
        # single-line form rather than duplicated prose.
        "assurance_boundary": report.get("assurance_boundary") or build_assurance_boundary(report),
        "limitations": limitations or [STATIC_ANALYSIS_DISCLAIMER],
    }
    # Offline integrity: digest covers the canonical payload (this block
    # itself plus volatile scan-event fields are excluded). See
    # docs/manifest/INTEGRITY.md.
    return stamp_integrity(manifest)


def serialize_manifest(manifest):
    """Serialize a manifest deterministically (sorted keys, 2-space indent)."""
    return json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n"


def write_manifest(manifest, path):
    """Write the manifest to ``path`` with deterministic serialization."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(serialize_manifest(manifest))


def write_digest_sidecar(manifest, manifest_path, digest_path):
    """Write ``<canonical-sha256>  <manifest-basename>`` to ``digest_path``.

    The digest is the canonical payload digest (what ``safeai manifest
    verify`` reports), which excludes the ``integrity`` block and volatile
    scan fields, so the sidecar is deliberately not ``sha256sum -c``
    compatible. Only the basename is recorded so the file is identical
    wherever the manifest is written.
    """
    line = f"{payload_digest(manifest)}  {os.path.basename(manifest_path)}\n"
    with open(digest_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(line)


def manifest_fingerprints(manifest):
    """Return the set of finding fingerprints in a manifest document."""
    return {
        f.get("fingerprint")
        for f in (manifest.get("findings") or [])
        if f.get("fingerprint")
    }
