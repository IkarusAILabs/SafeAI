"""Workload-identity change types between two scans (v2.10, ROADMAP S2).

Compares the ``iac_correlations.workload_identity`` blocks (v2.10) of a
baseline and a current report. Each change is mapped onto an existing
authority dimension rather than a new one (ROADMAP S2):

=============================  ============  =================================
Change type                    Dimension     Meaning
=============================  ============  =================================
``IDENTITY_ADDED``             identity      a workload is issued a SPIFFE ID
                                             it was not issued before
``IDENTITY_REMOVED``           identity      a SPIFFE ID the workload held is
                                             no longer issued to it
``IDENTITY_BROADENED``         identity      a registration selects more
                                             workloads, or its selector now
                                             matches every pod or namespace
``FEDERATION_ADDED``           destinations  a workload's SVID is now trusted
                                             by another trust domain
``CALLER_ADDED``               identity      an authorization policy newly
                                             admits a workload as a caller
``STATIC_CREDENTIAL_ADDED``    credential    a workload with a SPIFFE ID is
                                             newly handed a static credential
=============================  ============  =================================

Every change is Lane B (``review-only``): none feeds
``--fail-on-authority-change`` or ``--fail-on-escalation`` until its
precision is published (plan 2.11-4). A baseline from before v2.10
carries no workload-identity block; the comparison then reports
``baseline_available: false`` and no changes, never "everything added".

JWT-SVID audiences are chosen by the workload at run time and are not in
a ``ClusterSPIFFEID``, so no audience change type exists here.
"""

#: Change type → authority dimension (``contract.AUTHORITY_DIMENSIONS``).
IDENTITY_CHANGE_TYPES = {
    "IDENTITY_ADDED": "identity",
    "IDENTITY_REMOVED": "identity",
    "IDENTITY_BROADENED": "identity",
    "FEDERATION_ADDED": "destinations",
    "CALLER_ADDED": "identity",
    "STATIC_CREDENTIAL_ADDED": "credential",
}

_RESOLVED_STATES = ("resolved", "partially-resolved")


def _block(report):
    iac = (report or {}).get("iac_correlations")
    if not isinstance(iac, dict):
        return None
    block = iac.get("workload_identity")
    return block if isinstance(block, dict) else None


def _assignments(block):
    """``{(workload, spiffe_id): assignment}`` for issued identities."""
    return {(a["workload"], a["spiffe_id"]): a
            for a in block.get("assignments") or []
            if isinstance(a, dict) and a.get("resolution") in _RESOLVED_STATES}


def _workloads(block):
    return {w["workload"] for w in block.get("workloads") or [] if isinstance(w, dict)}


def _registration_reach(block):
    """``{registration: (workloads matched, all-pods, all-namespaces)}``."""
    reach = {}
    for reg in block.get("registrations") or []:
        if isinstance(reg, dict):
            reach[reg["name"]] = [set(), bool(reg.get("selects_all_pods")),
                                  bool(reg.get("selects_all_namespaces"))]
    for assignment in block.get("assignments") or []:
        if isinstance(assignment, dict) and assignment.get("registration") in reach:
            reach[assignment["registration"]][0].add(assignment["workload"])
    return reach


def _federations(block):
    return {(a["workload"], domain)
            for a in _assignments(block).values()
            for domain in a.get("federates_with") or []}


def _callers(block):
    """``{(caller workload, policy, target workloads)}`` for admitted callers."""
    callers = set()
    for policy in block.get("authorization_policies") or []:
        if not isinstance(policy, dict) or policy.get("action") != "ALLOW":
            continue
        label = f"{policy.get('namespace')}/{policy.get('name')}"
        targets = tuple(sorted(t["workload"] for t in policy.get("targets") or []))
        for principal in policy.get("principals") or []:
            if principal.get("negated"):
                continue
            for caller in principal.get("callers") or []:
                callers.add((caller["workload"], label, targets))
    return callers


def _static_credentials(block):
    return {(item["workload"], cred["name"], cred["source"])
            for item in block.get("static_credentials") or [] if isinstance(item, dict)
            for cred in item.get("credentials") or []}


def _change(change_type, workload, subject, detail, evidence=None):
    return {
        "type": change_type,
        "dimension": IDENTITY_CHANGE_TYPES[change_type],
        "workload": workload,
        "subject": subject,
        "detail": detail,
        "evidence": list(evidence or []),
        "provenance_class": "repo-iac-observed",
        "gateability": "review-only",
    }


def compute_identity_changes(current_report, baseline_report):
    """Workload-identity changes from ``baseline_report`` to ``current_report``."""
    after = _block(current_report)
    before = _block(baseline_report)
    if after is None or before is None:
        return {"lane": "B", "baseline_available": False, "changes": [],
                "counts": {}, "notes": [
                    ("baseline report has no workload_identity block (scanned before "
                     "v2.10 or without IaC collection): identity changes not assessed")]}

    changes = []
    before_ids, after_ids = _assignments(before), _assignments(after)
    for key in sorted(set(after_ids) - set(before_ids)):
        assignment = after_ids[key]
        changes.append(_change(
            "IDENTITY_ADDED", key[0], key[1],
            f"registration {assignment.get('registration')} now issues {key[1]}",
            assignment.get("evidence")))
    for key in sorted(set(before_ids) - set(after_ids)):
        changes.append(_change(
            "IDENTITY_REMOVED", key[0], key[1],
            f"{key[1]} is no longer issued"
            + ("" if key[0] in _workloads(after) else " (workload removed)")))

    before_reach, after_reach = _registration_reach(before), _registration_reach(after)
    for name in sorted(set(before_reach) & set(after_reach)):
        old_matched, old_pods, old_ns = before_reach[name]
        new_matched, new_pods, new_ns = after_reach[name]
        reasons = []
        if new_pods and not old_pods:
            reasons.append("podSelector now matches every pod")
        if new_ns and not old_ns:
            reasons.append("namespaceSelector now matches every namespace")
        gained = sorted(new_matched - old_matched)
        if gained and len(new_matched) > len(old_matched):
            reasons.append("now matches " + ", ".join(gained))
        if reasons:
            changes.append(_change("IDENTITY_BROADENED", "", name, "; ".join(reasons)))

    known_before = {w for w, _ in before_ids}
    for workload, domain in sorted(_federations(after) - _federations(before)):
        detail = f"SVID now trusted by federated trust domain {domain}"
        if workload not in known_before:
            detail += " (workload newly issued an identity)"
        changes.append(_change("FEDERATION_ADDED", workload, domain, detail))

    for workload, policy, targets in sorted(_callers(after) - _callers(before)):
        changes.append(_change(
            "CALLER_ADDED", workload, policy,
            f"admitted by {policy} as a caller of {', '.join(targets) or 'no in-repo workload'}"))

    issued_after = {w for w, _ in after_ids}
    for workload, name, source in sorted(_static_credentials(after)
                                         - _static_credentials(before)):
        if workload in issued_after:
            changes.append(_change(
                "STATIC_CREDENTIAL_ADDED", workload, name,
                f"static credential {name} ({source}) beside a SPIFFE identity"))

    changes.sort(key=lambda c: (c["type"], c["workload"], c["subject"]))
    counts = {}
    for change in changes:
        counts[change["type"]] = counts.get(change["type"], 0) + 1
    return {"lane": "B", "baseline_available": True, "changes": changes,
            "counts": dict(sorted(counts.items())), "notes": []}
