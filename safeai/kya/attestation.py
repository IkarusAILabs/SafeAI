"""Experimental Agent Authority Attestation (v2.12, plan 2.12-1; ROADMAP B3, Layer 7).

``safeai scan --manifest M --experimental-attestation A`` writes an
in-toto Statement v1 to ``A`` whose subject is the manifest file and
whose predicate restates, per agent and for the repository, what the
scan found, kept in three separate groups:

* ``machine_derived`` — what SafeAI derived from the repository
  (capabilities, tools, delegation edges, Separation-of-Duties
  conflicts, SPIFFE IDs issued by repository IaC);
* ``declared`` — what people wrote down (declared agent identities,
  governance metadata and OAuth client metadata (v0.2), policy
  exceptions with their approval metadata);
* ``unknown`` — fields the scan could not fill, each with its reason.
  Nothing is fabricated to fill a field.

**Experimental.** The predicate type ends in ``-experimental`` and the
predicate carries ``schema_stability: none``: any field may change in
any release until the predicate is published as stable.

The Statement is unsigned. Sign it as an external step (DSSE, for
example with ``cosign attest-blob``; see
``docs/attestation/agent-authority-v0.2-experimental.md``).
Binding to the manifest works both ways, offline:

* the subject digest is the SHA-256 of the manifest file's bytes;
* the manifest's ``authority_attestation.predicate_sha256`` is the
  digest of the canonical predicate, and that block is covered by the
  manifest's own integrity digest.

``safeai manifest verify M --attestation A`` checks all three: manifest
integrity, subject digest and predicate digest. Like the manifest
digest, this shows the documents were not edited apart from each other;
it does not show that the scan was truthful or that the configuration
was deployed.
"""

import hashlib
import json

from safeai.kya.integrity import OK, verify_document

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_BASE = "https://github.com/IkarusAILabs/SafeAI/blob/main/docs/attestation/"
PREDICATE_TYPE = _PREDICATE_BASE + "agent-authority-v0.2-experimental.md"
PREDICATE_VERSION = "0.2-experimental"
#: Predicate types ``manifest verify --attestation`` accepts. v0.1 (SafeAI
#: 2.12-2.14) has no governance fields; its digests still verify.
KNOWN_PREDICATE_TYPES = (PREDICATE_TYPE, _PREDICATE_BASE + "agent-authority-v0.1-experimental.md")
#: Governance fields reported as ``unknown`` when not declared (v0.2).
GOVERNANCE_FIELDS = ("owner", "lifecycle", "purpose", "client_id")

#: ``safeai manifest verify --attestation`` statuses besides ``integrity``'s own.
ATTESTATION_OK = "ok"
NOT_A_STATEMENT = "not-a-statement"
SUBJECT_MISMATCH = "subject-mismatch"
PREDICATE_MISMATCH = "predicate-mismatch"
NO_ATTESTATION_BLOCK = "no-attestation-block"


def predicate_digest(predicate):
    """SHA-256 over the canonical predicate (sorted keys, compact separators)."""
    canonical = json.dumps(predicate, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _norm(framework):
    return str(framework or "").lower().replace("-", "_")


def _agent_entry(agent, delegation, sod):
    identity = agent.get("workload_identity") or {}
    identifiers = identity.get("identifiers") or []
    nodes = [n for n in delegation.get("nodes") or []
             if n.get("name") == agent.get("name")
             and _norm(n.get("framework")) == _norm(agent.get("framework"))]
    node_ids = {n["id"] for n in nodes}
    edges = delegation.get("edges") or []
    holder = f"{_norm(agent.get('framework'))}:{agent.get('name')}"
    machine = {
        "capabilities": sorted(({"name": c.get("name"), "category": c.get("category")}
                                for c in agent.get("capabilities") or []),
                               key=lambda c: str(c["name"])),
        "tools": sorted(agent.get("tools") or []),
        "source_locations": agent.get("source_locations") or [],
        "workload_identity": [i for i in identifiers
                              if i.get("provenance_class") == "repo-iac-observed"],
        "separation_of_duties": [
            {"pair": c["pair"], "first": c.get("first"), "second": c.get("second"),
             "via_delegation": c.get("via_delegation") or []}
            for c in sod.get("conflicts") or [] if c.get("holder") == holder],
    }
    unknown = []
    if nodes:
        machine["delegates_to"] = sorted({e["to"] for e in edges if e["from"] in node_ids})
        machine["delegated_by"] = sorted({e["from"] for e in edges if e["to"] in node_ids})
    else:
        unknown.append({"field": "delegation",
                        "reason": ("agent record not matched by name and framework to a "
                                   "node of the static delegation graph (the repository "
                                   "graph is under repository.machine_derived.delegation)")})
    if identity.get("state", "unknown") == "unknown":
        unknown.append({"field": "workload_identity",
                        "reason": identity.get("unknown_reason") or "no identity evidence"})
    unknown.append({"field": "runtime_identity",
                    "reason": "static scan: SVID issuance is not observable"})
    governance = agent.get("governance") or {}
    for field in GOVERNANCE_FIELDS:
        if not governance.get(field):
            unknown.append({"field": f"governance.{field}",
                            "reason": "not declared in .safeai/config.yml agent_governance"})
    if governance.get("client_id") and not governance.get("client_metadata"):
        unknown.append({"field": "governance.client_metadata",
                        "reason": {"not-in-repository": "the Client ID Metadata Document is "
                                   "not in the repository (the URL is never fetched)",
                                   "ambiguous": "several repository files claim this client_id"}
                        .get(governance.get("client_metadata_state"), "not available")})
    declared_governance = {k: v for k, v in governance.items()
                           if k in (*GOVERNANCE_FIELDS, "client_metadata", "evidence")
                           and v is not None}
    return {
        "agent_id": agent.get("agent_id"),
        "name": agent.get("name"),
        "framework": agent.get("framework"),
        "agent_type": agent.get("agent_type"),
        "machine_derived": machine,
        "declared": {"workload_identity": [i for i in identifiers
                                           if i.get("provenance_class") == "declared"],
                     "governance": declared_governance},
        "unknown": unknown,
    }


def build_predicate(manifest):
    """Assemble the predicate from a built manifest (see module docstring)."""
    delegation = manifest.get("delegation_graph") or {}
    sod = manifest.get("separation_of_duties") or {}
    iac = manifest.get("iac_correlations") or {}
    workload_identity = iac.get("workload_identity")
    summary = manifest.get("summary") or {}
    boundary = manifest.get("assurance_boundary") or {}
    observed = {}
    for assignment in (workload_identity or {}).get("assignments") or []:
        if assignment.get("resolution") in ("resolved", "partially-resolved"):
            observed.setdefault(assignment["spiffe_id"], set()).add(assignment["workload"])

    repo_unknown = [{"field": item, "reason": "not verifiable statically"}
                    for item in boundary.get("not_verifiable_statically") or []]
    if workload_identity is None:
        repo_unknown.append({"field": "workload_identity",
                             "reason": "no workload-identity block (IaC not collected)"})
    exceptions = manifest.get("exception_evaluations") or []
    project = manifest.get("project") or {}
    safeai = manifest.get("safeai") or {}
    return {
        "predicate_version": PREDICATE_VERSION,
        "experimental": True,
        "schema_stability": "none",
        "generator": {"name": "safeai", "version": safeai.get("version"),
                      "ruleset_version": safeai.get("ruleset_version")},
        "project": {"project_id": project.get("project_id"), "name": project.get("name"),
                    "repository": project.get("repository") or {}},
        "agents": [_agent_entry(a, delegation, sod)
                   for a in sorted(manifest.get("agents") or [],
                                   key=lambda a: str(a.get("agent_id")))],
        "repository": {
            "machine_derived": {
                "tool_count": len(manifest.get("tool_surface") or []),
                "workload_identities": [{"id": i, "workloads": sorted(w)}
                                        for i, w in sorted(observed.items())],
                "delegation": {
                    "counts": delegation.get("counts") or {},
                    "edges": [{k: e.get(k) for k in ("from", "to", "kind", "exceeds")}
                              for e in delegation.get("edges") or []],
                    "unresolved": len(delegation.get("unresolved") or []),
                },
                "separation_of_duties": [{"holder": c["holder"], "pair": c["pair"]}
                                         for c in sod.get("conflicts") or []],
                "severity_counts": summary.get("severity_counts") or {},
                "highest_change_class": summary.get("highest_change_class"),
                "verified_statically": boundary.get("verified_statically") or [],
            },
            "declared": {
                "exceptions": [
                    {k: e.get(k) for k in ("exception_id", "target_type", "target_id",
                                           "state", "risk_owner", "expires_at",
                                           "approval", "approval_state")}
                    for e in exceptions],
            },
            "unknown": repo_unknown,
        },
        "policy_decision": (summary.get("policy_decision") or {}).get("outcome"),
    }


def attestation_section(predicate):
    """The manifest's ``authority_attestation`` block for ``predicate``."""
    return {"experimental": True, "predicate_type": PREDICATE_TYPE,
            "predicate_version": PREDICATE_VERSION,
            "predicate_sha256": predicate_digest(predicate)}


def build_statement(predicate, manifest_name, manifest_bytes, commit_sha=None):
    """The in-toto Statement v1 binding ``predicate`` to the manifest file."""
    subjects = [{"name": manifest_name,
                 "digest": {"sha256": hashlib.sha256(manifest_bytes).hexdigest()}}]
    if commit_sha:
        subjects.append({"name": "git-commit", "digest": {"gitCommit": str(commit_sha)}})
    return {"_type": STATEMENT_TYPE, "subject": subjects,
            "predicateType": PREDICATE_TYPE, "predicate": predicate}


def write_statement(statement, path):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(statement, indent=2, sort_keys=True, default=str) + "\n")


def is_statement(document):
    return isinstance(document, dict) and document.get("_type") == STATEMENT_TYPE


def verify_attestation(manifest_bytes, manifest, statement):
    """Check that ``statement`` attests to this manifest. Returns ``(status, detail)``."""
    status, detail = verify_document(manifest)
    if status != OK:
        return status, f"manifest: {detail}"
    if not is_statement(statement) or statement.get("predicateType") not in KNOWN_PREDICATE_TYPES:
        return NOT_A_STATEMENT, ("attestation is not an in-toto Statement v1 with a "
                                 "SafeAI agent-authority predicate type")
    block = manifest.get("authority_attestation")
    if not isinstance(block, dict) or not block.get("predicate_sha256"):
        return NO_ATTESTATION_BLOCK, ("manifest has no authority_attestation block "
                                      "(scanned without --experimental-attestation)")
    if block.get("predicate_type") not in (None, statement["predicateType"]):
        return PREDICATE_MISMATCH, ("predicate type differs from the one the manifest records "
                                    f"({block.get('predicate_type')})")
    file_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if not any(isinstance(s, dict) and (s.get("digest") or {}).get("sha256") == file_digest
               for s in statement.get("subject") or []):
        return SUBJECT_MISMATCH, "no subject digest matches the manifest file's SHA-256"
    if predicate_digest(statement.get("predicate")) != block["predicate_sha256"]:
        return PREDICATE_MISMATCH, ("predicate differs from the one the manifest records "
                                    "(edited after generation)")
    return ATTESTATION_OK, f"manifest sha256:{file_digest}, predicate sha256:{block['predicate_sha256']}"
