"""IaC authority correlation engine (v2.5 redesign).

Operates on the explicit authority graph — Identities, Grants,
GrantBindings, AgentIdentityLinks — never on bare category families.
Verdict semantics (strict):

- ``MATCH`` — Agent→Identity link statically evidenced, declared
  requirements map to the grant domain, a compatible grant exists, and
  no unresolved material could change the conclusion.
- ``EXCESS_AUTHORITY`` — linked grants strictly exceed what the linked
  agent's requirements need. Unrelated grants are never excess.
- ``AUTHORITY_MISMATCH`` — linked identity visibly lacks a grant the
  requirements need, with authoritative (fully resolved, module-free)
  evidence. Absence alone is never mismatch.
- ``UNVERIFIED_LINK`` — requirements and grants coexist without a
  static link. The most common outcome for ambiguous projects.
- ``UNKNOWN`` — unresolved material, modules, unparsed IaC, or no
  assessable counterpart. Preferred over false mismatch/excess.

Every finding pre-sets ``provenance_class="repo-iac-observed"`` and
``gateability="review-only"`` (Lane B, ADR-0008). Repository IaC is
evidence of declared grants, never proof of deployed permission.
"""

from safeai.iac import semantics
from safeai.iac.model import (
    PARTIALLY_RESOLVED,
    RESOLVED,
    UNRESOLVED,
    verdict,
)

#: Correlation finding rule ids (stable public vocabulary).
RULE_EXCESS = "IAC_EXCESS_AUTHORITY"
RULE_MISMATCH = "IAC_AUTHORITY_MISMATCH"
RULE_UNVERIFIED = "IAC_UNVERIFIED_LINK"

_PROVENANCE = "repo-iac-observed"
_GATEABILITY = "review-only"


def _surface_requirements(report):
    """Build semantic requirements from the tool surface.

    Returns ``[(agent_ref, descriptor, evidence_refs)]``. Capabilities
    without an IaC-mappable domain, or without an access mode, yield
    ``descriptor None`` (uncomparable — forces UNKNOWN when linked,
    ignored otherwise).
    """
    requirements = []
    surface = report.get("tool_surface")
    tools = (surface if isinstance(surface, list)
             else (surface or {}).get("tools") or [])
    for entry in tools:
        if not isinstance(entry, dict):
            continue
        agent_ref = str(entry.get("tool_key") or "<unknown-tool>")
        by_domain = {}
        evidence = {}
        for cap in entry.get("capabilities") or []:
            if not isinstance(cap, dict):
                continue
            descriptor = semantics.normalize_requirement(
                cap.get("name"), cap.get("access_mode"))
            if descriptor is None:
                continue
            domain = (descriptor["provider"], descriptor["service"])
            by_domain.setdefault(domain, set()).update(descriptor["ops"])
            for item in cap.get("evidence") or []:
                if isinstance(item, dict) and item.get("path"):
                    evidence.setdefault(domain, set()).add(
                        f"{item.get('path')}:{item.get('line', 0)}")
        for domain, ops in by_domain.items():
            requirements.append({
                "agent_ref": agent_ref,
                "provider": domain[0],
                "service": domain[1],
                "ops": set(ops),
                "evidence_refs": sorted(evidence.get(domain, ())),
            })
    return requirements


def _grant_domains(grants):
    """Map (provider, service) -> list of grants with descriptors."""
    domains = {}
    for grant in grants or []:
        if not isinstance(grant, dict):
            continue
        descriptor, unresolvable = semantics.grant_descriptor(grant)
        domain = (descriptor["provider"], descriptor["service"])
        domains.setdefault(domain, []).append((grant, descriptor,
                                               unresolvable))
    return domains


def _identity_links_map(links):
    """Map identity key -> list of links."""
    mapped = {}
    for link in links or []:
        if not isinstance(link, dict):
            continue
        ident = link.get("identity") or {}
        key = (str(ident.get("kind") or ""),
               str(ident.get("namespace") or ""),
               str(ident.get("name") or ""))
        mapped.setdefault(key, []).append(link)
    return mapped


def link_refs_for(keys, links_by_identity):
    """Evidence refs for a set of linked identity keys (deterministic)."""
    refs = set()
    for key in keys or []:
        for link in links_by_identity.get(key) or []:
            for ev in link.get("evidence") or []:
                refs.add(f"{ev.get('file')}:{ev.get('line', 0)}")
    return sorted(refs)


def _expand_admin_grants(domains, req_domains):
    """Share bare-star grants across observed AWS domains.

    A literal ``*`` action is provider-wide admin: it genuinely covers
    requirements in any domain. Evaluating it only in its own ``(*,*)``
    bucket would hide privilege behind the wildcard (and fabricate
    MISMATCH next to real coverage). The ``(*,*)`` record itself is
    kept as UNKNOWN inventory; copies participate per-domain. Scoped
    to AWS — the only producer of provider-"*" descriptors.
    """
    star_items = []
    for domain, items in domains.items():
        if domain == ("*", "*"):
            star_items.extend(items)
    if not star_items:
        return domains
    expanded = dict(domains)
    targets = ({d for d in req_domains if d[0] == "aws"}
               | {d for d in domains
                  if d != ("*", "*") and d[0] == "aws"})
    for domain in sorted(targets):
        expanded.setdefault(domain, []).extend(star_items)
    return expanded


def _shadowed_providers(grants):
    """Providers whose grant set contains unresolved material."""
    """Providers whose grant set contains unresolved material.

    An unresolved grant could hide permissions in its provider, so
    absence claims (MISMATCH) are degraded to UNKNOWN there. Empty
    grants fall back to the source family hint (cloud→aws); truly
    unknown origins shadow everything.
    """
    shadowed = set()
    for grant in grants or []:
        if not isinstance(grant, dict):
            continue
        actions = grant.get("actions") or {}
        resources = grant.get("resources") or {}
        if actions.get("resolution") == UNRESOLVED or \
                resources.get("resolution") == UNRESOLVED:
            descriptor, _ = semantics.grant_descriptor(grant)
            provider = descriptor.get("provider") or "*"
            if provider == "*":
                provider = {"cloud": "aws",
                            "kubernetes": "kubernetes"}.get(
                                grant.get("family") or "", "*")
            shadowed.add(provider)
    return shadowed


def _grant_identity_key(grant):
    """Full identity triple for a grant (namespaces isolate)."""
    """Full identity triple for a grant (namespaces isolate)."""
    ident = grant.get("identity") or {}
    return (str(ident.get("kind") or ""), str(ident.get("namespace") or ""),
            str(ident.get("name") or ""))


def correlate_iac_authority(report, graph):
    """Correlate declared requirements against evidenced grants.

    ``graph`` holds ``identities``, ``grants``, ``grant_bindings``,
    ``agent_links``, and ``meta``. Returns ``(findings, summary)`` with
    the v2 ``iac_correlations`` shape. Never raises on malformed input.
    """
    graph = graph or {}
    grants = [g for g in graph.get("grants") or [] if isinstance(g, dict)]
    links = [l for l in graph.get("agent_links") or []
             if isinstance(l, dict)]
    meta = graph.get("meta") or {}

    requirements = _surface_requirements(report)
    domains = _grant_domains(grants)
    links_by_identity = _identity_links_map(links)
    agent_linked = sorted(links_by_identity)
    shadowed = _shadowed_providers(grants)

    req_domains = {}
    for req in requirements:
        req_domains.setdefault((req["provider"], req["service"]), []).append(req)
    # A requirement for "any service" ((aws, *)) applies to every
    # observed service of that provider.
    expanded = {}
    for domain, reqs in req_domains.items():
        provider, service = domain
        if service == "*":
            targets = [o for o in domains
                       if o[0] == provider and o != domain]
            if targets:
                # A wildcard-service requirement is evaluated against
                # each observed service; the bare (provider, *) self
                # domain would only duplicate those verdicts.
                for observed in targets:
                    expanded.setdefault(observed, []).extend(reqs)
                continue
        expanded.setdefault(domain, []).extend(reqs)
    req_domains = expanded

    # Bare-star grants (provider-wide admin from Terraform) genuinely
    # cover requirements in every AWS domain — including domains with
    # no other grants, where they prevent false MISMATCH. Scoped to
    # AWS: only Terraform produces provider-"*" descriptors today, and
    # a TF star is AWS-admin, never Kubernetes-admin.
    domains = _expand_admin_grants(domains, req_domains)

    findings = []
    verdicts = []
    modules = bool(meta.get("has_modules"))
    unparsed = bool(meta.get("unparsed_files"))

    for domain in sorted(set(req_domains) | set(domains)):
        verdict_obj = _decide_domain(
            domain, req_domains.get(domain, []),
            domains.get(domain, []), links_by_identity, agent_linked,
            shadowed,
            authoritative=not (modules or unparsed))
        if verdict_obj is None:
            continue
        verdicts.append(verdict_obj)
        finding = _verdict_finding(verdict_obj)
        if finding is not None:
            findings.append(finding)

    findings.sort(key=lambda f: (f.get("file", ""), int(f.get("line") or 0),
                                 f.get("rule_id", "")))
    counts = {"grants": len(grants), "verdicts": len(verdicts),
              "identities": len(graph.get("identities") or []),
              "agent_links": len(links)}
    for item in verdicts:
        key = str(item.get("verdict") or "UNKNOWN").lower()
        counts[key] = counts.get(key, 0) + 1
    files = dict(meta.get("files") or {})
    summary = {
        "schema_version": 2,
        "correlation_model": "authority-graph v2 (identities, grants, "
                             "bindings, links; ADR-0007/0009)",
        "lane": "B",
        "files": files,
        "identities": graph.get("identities") or [],
        "agent_identity_links": links,
        "grants": grants,
        "grant_bindings": graph.get("grant_bindings") or [],
        "verdicts": verdicts,
        "counts": counts,
    }
    return findings, summary


def _decide_domain(domain, reqs, grant_items, links_by_identity,
                   agent_linked, shadowed, authoritative):
    """Decide one (provider, service) domain. None when nothing to say."""
    provider, service = domain
    domain_name = f"{provider}:{service}"

    linked_grants = []
    linked_identities = []
    for grant, descriptor, unresolvable in grant_items:
        # Exact triple match (kind, namespace, name): namespaces
        # isolate — a same-named identity in another namespace never
        # links. AWS identities carry no namespace on either side.
        key = _grant_identity_key(grant)
        if key not in links_by_identity:
            continue
        link = links_by_identity[key][0]
        linked_grants.append((grant, descriptor, unresolvable, link, key))
        if key not in linked_identities:
            linked_identities.append(key)

    declared_refs = sorted({ref for req in reqs
                            for ref in req.get("evidence_refs") or []}
                           | {req.get("agent_ref") for req in reqs})
    grant_refs = sorted({f"{g.get('source_file')}:{g.get('line', 0)}"
                         for g, _, _ in grant_items})
    link_refs = sorted({ref
                        for _, _, _, link, _ in linked_grants
                        for ev in (link.get("evidence") or [])
                        for ref in [f"{ev.get('file')}:{ev.get('line', 0)}"]})

    required_ops = set()
    for req in reqs:
        required_ops |= set(req.get("ops") or [])

    if reqs and linked_grants:
        return _decide_linked(domain, reqs, required_ops,
                              linked_grants, declared_refs, grant_refs,
                              link_refs, shadowed,
                              authoritative=authoritative)
    if reqs and grant_items:
        return verdict("<repo>", None, domain_name, "UNVERIFIED_LINK",
                       declared_refs, grant_refs, [],
                       PARTIALLY_RESOLVED
                       if any(u for _, _, u in grant_items) else RESOLVED,
                       "Declared requirements and IaC grants coexist in "
                       f"{domain_name} without a static Agent-to-Identity "
                       "link; the grant may or may not reach this agent.")
    if reqs and not grant_items:
        # No grant in this domain. MISMATCH only when the agent is
        # linked, the evidence is authoritative, and no unresolved
        # grant in this provider could hide the permission.
        # Otherwise UNKNOWN — absence alone is never mismatch.
        shadowed_here = (provider in shadowed or "*" in shadowed)
        if agent_linked and authoritative and not shadowed_here:
            names = ", ".join(sorted({k[2] for k in agent_linked}))
            return verdict(
                "<repo>", None, domain_name, "AUTHORITY_MISMATCH",
                declared_refs, [], link_refs_for(agent_linked,
                                                 links_by_identity),
                RESOLVED,
                f"Linked identit{'y' if len(agent_linked) == 1 else 'ies'} "
                f"{names} show no {domain_name} grant in authoritative "
                "repository evidence — probable breakage, or the grant "
                "lives outside this repository.")
        if agent_linked:
            return verdict("<repo>", None, domain_name, "UNKNOWN",
                           declared_refs, [],
                           link_refs_for(agent_linked, links_by_identity),
                           UNRESOLVED,
                           "Requirements exist but unresolved material "
                           "prevents showing an authoritative absence.")
        return verdict("<repo>", None, domain_name, "UNKNOWN",
                       declared_refs, [], [],
                       PARTIALLY_RESOLVED,
                       "Requirements exist but no comparable grant is "
                       "visible and no Agent-to-Identity link establishes "
                       "where to look.")
    if grant_items and not reqs:
        material_unresolved = any(u for _, _, u in grant_items)
        return verdict("<repo>", None, domain_name, "UNKNOWN",
                       [], grant_refs, [],
                       UNRESOLVED if material_unresolved else RESOLVED,
                       f"IaC grants {domain_name} authority with no declared "
                       "capability counterpart — recorded, not excess: "
                       "without a linked requirement there is insufficient "
                       "evidence of over-privilege.")
    return None


def _decide_linked(domain, reqs, required_ops, linked_grants,
                   declared_refs, grant_refs, link_refs, shadowed,
                   authoritative):
    """Decide a domain with linked identity grants (strict semantics)."""
    provider, service = domain
    domain_name = f"{provider}:{service}"
    material_unresolved = any(u for _, _, u, _, _ in linked_grants)
    high_link = any(str(link.get("confidence") or "").lower() == "high"
                    for _, _, _, link, _ in linked_grants)
    identity_ref = {"kind": linked_grants[0][4][0],
                    "namespace": linked_grants[0][4][1],
                    "name": linked_grants[0][4][2]}

    if material_unresolved or not authoritative:
        return verdict("<repo>", identity_ref, domain_name, "UNKNOWN",
                       declared_refs, grant_refs, link_refs, UNRESOLVED,
                       "Unresolved grant content, unparsed IaC, or modules "
                       "could change the conclusion — UNKNOWN preferred "
                       "over a false match/mismatch.")

    covered, excess_union, notes = False, set(), []
    req_like = {"provider": provider, "service": service,
                "ops": required_ops}
    for grant, descriptor, _u, _link, _key in linked_grants:
        grant_cov, grant_excess, grant_notes = semantics.compatible(
            descriptor, req_like)
        notes.extend(grant_notes)
        covered = covered or grant_cov
        excess_union |= grant_excess

    resolution = RESOLVED if high_link else PARTIALLY_RESOLVED
    if covered and not excess_union:
        return verdict("<repo>", identity_ref, domain_name, "MATCH",
                       declared_refs, grant_refs, link_refs, resolution,
                       f"Linked grant covers {domain_name} requirements "
                       f"({', '.join(sorted(required_ops)) or 'none'}) with "
                       "no excess.")
    if covered and excess_union:
        return verdict("<repo>", identity_ref, domain_name,
                       "EXCESS_AUTHORITY", declared_refs, grant_refs,
                       link_refs, resolution,
                       f"Linked grant provides {domain_name} operations "
                       f"({', '.join(sorted(excess_union))}) beyond what "
                       "the declared requirements need.")
    if provider in shadowed or "*" in shadowed:
        return verdict("<repo>", identity_ref, domain_name, "UNKNOWN",
                       declared_refs, grant_refs, link_refs, UNRESOLVED,
                       "Unresolved grants in this provider could hide the "
                       "required permission — UNKNOWN preferred over a "
                       "false mismatch.")
    return verdict("<repo>", identity_ref, domain_name,
                   "AUTHORITY_MISMATCH", declared_refs, grant_refs,
                   link_refs, resolution,
                   f"Linked identity shows no compatible {domain_name} "
                   "grant for the declared requirements.")


def _verdict_finding(verdict_obj):
    """Build the review-only finding for a verdict (None if silent)."""
    name = verdict_obj.get("verdict")
    if name in ("MATCH", "UNKNOWN"):
        return None
    refs = verdict_obj.get("grant_evidence_refs") or []
    link_refs = verdict_obj.get("link_evidence_refs") or []
    first = (refs + link_refs + ["<scan>:1"])[0]
    location = first.rsplit(":", 1)
    reason = verdict_obj.get("reason") or name
    base = {
        "file": location[0] if len(location) == 2 else "<scan>",
        "line": int(location[1]) if len(location) == 2 and
        str(location[1]).isdigit() else 1,
        "risk_category": "Integration",
        "affected_framework": "generic",
        "affected_capability": verdict_obj.get("domain"),
        "provenance_class": _PROVENANCE,
        "gateability": _GATEABILITY,
        "iac_domain": verdict_obj.get("domain"),
        "iac_verdict": name,
        "evidence": (f"verdict={name} domain={verdict_obj.get('domain')} "
                     f"refs={', '.join(refs) or 'none'}"),
    }
    if name == "EXCESS_AUTHORITY":
        base.update({
            "rule_id": RULE_EXCESS,
            "severity": "medium",
            "message": "Linked IaC grant exceeds the declared requirement",
            "owasp_llm": "LLM06",
            "reason": reason,
            "remediation": (
                "Narrow the grant to the required operations, or declare "
                "and justify the wider capability; re-review on IaC change."
            ),
            "confidence": 0.65,
            "score_contribution": 6,
        })
    elif name == "AUTHORITY_MISMATCH":
        base.update({
            "rule_id": RULE_MISMATCH,
            "severity": "low",
            "message": "Linked identity lacks a grant the agent requires",
            "reason": reason,
            "remediation": (
                "Add the missing grant, or confirm it is granted outside "
                "this repository and record that link explicitly."
            ),
            "confidence": 0.55,
            "score_contribution": 3,
        })
    else:  # UNVERIFIED_LINK
        base.update({
            "rule_id": RULE_UNVERIFIED,
            "severity": "low",
            "message": "Declared requirement and IaC grant lack a static link",
            "reason": reason,
            "remediation": (
                "Establish which identity the agent assumes (workload "
                "service account, role reference) and record it; without "
                "that link this stays review-only."
            ),
            "confidence": 0.55,
            "score_contribution": 3,
        })
    return base
