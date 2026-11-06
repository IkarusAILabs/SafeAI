"""SPIFFE / WIMSE identity field on agent records (v2.12, plan 2.12-2; ROADMAP S4).

Each KYA agent record gets a ``workload_identity`` field that says which
workload identifier the agent runs as, and where that claim comes from.
Two provenance classes are emitted, and kept apart:

* ``declared`` — the repository says so, in ``.safeai/config.yml``::

      agent_identities:
        - agent: support-bot
          id: spiffe://example.org/ns/agents/sa/support-bot

  ``id`` is a SPIFFE ID (``spiffe://``) or a WIMSE identifier
  (``wimse://``). ``agent`` is the agent's ``name`` or ``agent_id`` as
  the manifest's ``agents`` list reports it.
* ``repo-iac-observed`` — the same identifier is issued, in the
  repository's own manifests, by a ``ClusterSPIFFEID`` registration
  (v2.10 collector). It is only ever added *beside* a declared entry for
  the same identifier: the collector links identities to workloads, not
  to agents, so an observed SPIFFE ID is never attached to an agent on
  its own (that would be a guess).

Workload-to-agent links (v2.15, plan 2.15-1) attribute the SPIFFE IDs a
Kubernetes workload is issued to the agent that workload runs, from two
kinds of repository evidence only:

* ``workload-annotation``: the workload's pod template (or the workload
  itself) is annotated ``ai.safeai.dev/agent: <name or agent_id>``. That
  is a declaration in the repository, so the identity is listed as
  ``declared`` (evidence: the workload) and, being issued there, as
  ``repo-iac-observed``; the state is ``corroborated``.
* ``workload-entrypoint``: a container ``command`` / ``args`` starts the
  Python file in which this agent, and no other, is defined. Only the
  ``repo-iac-observed`` entry is added; nothing was declared, so the
  state stays what the declarations make it (``unknown`` without any).

Each linked identifier carries ``link: {type, workload}``. A file that
defines several agents, or an entrypoint matching several files, links
nothing. Name coincidence never links.

``runtime-unverified`` is reserved (``RESERVED_IDENTITY_PROVENANCE``) for
issuance evidence supplied from outside the scan (for example a SPIRE
server export). SafeAI never emits it; readers must accept it.

States: ``corroborated`` (declared and observed), ``declared`` (declared,
not observed in the repository), ``unknown`` (nothing declared; the
``unknown_reason`` says whether the repository issues identities that
are not attributed to agents). ``runtime_verified`` is always ``false``:
nothing here shows that an SVID was actually issued.
"""

import os
import re

import yaml

from safeai.iac.spiffe import AGENT_ANNOTATION
from safeai.kya.contract import (  # noqa: F401
    IDENTITY_PROVENANCE_CLASSES,
    IDENTITY_STATES,
)

CONFIG_PATH = ".safeai/config.yml"

#: Identity provenance classes this scanner emits; the rest of
#: ``IDENTITY_PROVENANCE_CLASSES`` is reserved (ROADMAP S4).
IDENTITY_PROVENANCE = ("declared", "repo-iac-observed")
RESERVED_IDENTITY_PROVENANCE = tuple(c for c in IDENTITY_PROVENANCE_CLASSES
                                     if c not in IDENTITY_PROVENANCE)

_SPIFFE_RE = re.compile(r"^spiffe://[a-z0-9._-]+(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$")
_WIMSE_RE = re.compile(r"^wimse://[A-Za-z0-9._-]+(/[^\s/]+)*$")


class AgentIdentityError(ValueError):
    """Raised for a malformed ``agent_identities`` declaration."""


def _scheme(identifier):
    if _SPIFFE_RE.match(identifier):
        return "spiffe"
    if _WIMSE_RE.match(identifier):
        return "wimse"
    return None


def load_declared_identities(root):
    """Read ``agent_identities`` from ``.safeai/config.yml``.

    Returns a list of ``{agent, id, scheme, evidence}``. A missing file or
    key yields ``[]``; a malformed entry raises ``AgentIdentityError``.
    """
    path = os.path.join(root, ".safeai", "config.yml")
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return []
    try:
        document = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise AgentIdentityError(f"{CONFIG_PATH}: unreadable YAML: {exc}") from exc
    raw = document.get("agent_identities") if isinstance(document, dict) else None
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise AgentIdentityError(f"{CONFIG_PATH}: 'agent_identities' must be a list")
    lines = text.splitlines()
    declared = []
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise AgentIdentityError(f"{CONFIG_PATH}: agent_identities #{index} must be a mapping")
        agent = str(item.get("agent") or "").strip()
        identifier = str(item.get("id") or "").strip()
        if not agent or not identifier:
            raise AgentIdentityError(
                f"{CONFIG_PATH}: agent_identities #{index} needs both 'agent' and 'id'")
        scheme = _scheme(identifier)
        if scheme is None:
            raise AgentIdentityError(
                f"{CONFIG_PATH}: agent_identities #{index}: 'id' must be a SPIFFE ID "
                f"(spiffe://trust-domain/path) or a WIMSE identifier (wimse://...)")
        line = next((n for n, text_line in enumerate(lines, 1) if identifier in text_line), 1)
        declared.append({"agent": agent, "id": identifier, "scheme": scheme,
                         "evidence": [{"file": CONFIG_PATH, "line": line}]})
    return declared


def _observed(workload_identity):
    """``{spiffe_id: [assignment, ...]}`` for identities the repository issues."""
    observed = {}
    for assignment in (workload_identity or {}).get("assignments") or []:
        if isinstance(assignment, dict) and assignment.get("resolution") in (
                "resolved", "partially-resolved"):
            observed.setdefault(assignment["spiffe_id"], []).append(assignment)
    return observed


def _agent_paths(agent):
    return {str(loc.get("path")) for loc in agent.get("source_locations") or []
            if isinstance(loc, dict) and loc.get("path")}


def _entrypoint_matches(entrypoint, path):
    entry = entrypoint.replace("\\", "/").lstrip("/")
    return entry == path or entry.endswith("/" + path)


def workload_links(agents, workload_identity):
    """``{agent_id: [link]}`` from workload annotations and entrypoints (2.15-1).

    A link is ``{type, workload, evidence}``. Ambiguous evidence links nothing.
    """
    links = {}
    by_key = {}
    for agent in agents:
        for key in (agent.get("name"), agent.get("agent_id")):
            if key:
                by_key.setdefault(key, []).append(agent)
    for state in (workload_identity or {}).get("workloads") or []:
        hints = state.get("agent_hints") if isinstance(state, dict) else None
        if not hints:
            continue
        evidence = list(hints.get("evidence") or [])
        if hints.get("annotation"):
            # An annotation is the workload's own statement: when it names no
            # single agent, nothing is linked (no fallback to the entrypoint).
            named = by_key.get(hints["annotation"]) or []
            if len({a.get("agent_id") for a in named}) == 1:
                links.setdefault(named[0]["agent_id"], []).append(
                    {"type": "workload-annotation", "workload": state["workload"],
                     "evidence": evidence})
            continue
        matched = {}
        for entrypoint in hints.get("entrypoints") or []:
            for agent in agents:
                for path in _agent_paths(agent):
                    if _entrypoint_matches(entrypoint, path):
                        matched.setdefault(path, set()).add(agent.get("agent_id"))
        if len(matched) == 1:
            (agent_ids,) = matched.values()
            if len(agent_ids) == 1:
                links.setdefault(next(iter(agent_ids)), []).append(
                    {"type": "workload-entrypoint", "workload": state["workload"],
                     "evidence": evidence})
    return links


def identity_field(agent, declared, workload_identity, links=None):
    """The ``workload_identity`` field for one agent record (see module docstring)."""
    observed = _observed(workload_identity)
    keys = {agent.get("name"), agent.get("agent_id")} - {None}
    identifiers = []
    issued = {}
    for assignment in (workload_identity or {}).get("assignments") or []:
        if isinstance(assignment, dict) and assignment.get("resolution") in (
                "resolved", "partially-resolved"):
            issued.setdefault(assignment["workload"], []).append(assignment)
    for link in links or []:
        for assignment in issued.get(link["workload"]) or []:
            spiffe_id = assignment["spiffe_id"]
            tag = {"type": link["type"], "workload": link["workload"]}
            if link["type"] == "workload-annotation":
                identifiers.append({"id": spiffe_id, "scheme": "spiffe",
                                    "provenance_class": "declared",
                                    "evidence": list(link["evidence"]), "link": tag})
            identifiers.append({
                "id": spiffe_id, "scheme": "spiffe", "provenance_class": "repo-iac-observed",
                "evidence": sorted(({"file": ref["file"], "line": int(ref.get("line") or 1)}
                                    for ref in assignment.get("evidence") or []),
                                   key=lambda r: (r["file"], r["line"])),
                "workloads": [link["workload"]],
                "registrations": [assignment["registration"]], "link": tag})
    for item in declared:
        if item["agent"] not in keys:
            continue
        identifiers.append({"id": item["id"], "scheme": item["scheme"],
                            "provenance_class": "declared",
                            "evidence": list(item["evidence"])})
        assignments = observed.get(item["id"]) or []
        if assignments:
            evidence = sorted({(ref["file"], int(ref.get("line") or 1))
                               for a in assignments for ref in a.get("evidence") or []})
            identifiers.append({
                "id": item["id"], "scheme": item["scheme"],
                "provenance_class": "repo-iac-observed",
                "evidence": [{"file": f, "line": n} for f, n in evidence],
                "workloads": sorted({a["workload"] for a in assignments}),
                "registrations": sorted({a["registration"] for a in assignments}),
            })
    unique = {}
    for item in identifiers:
        key = (item["id"], item["provenance_class"], (item.get("link") or {}).get("workload", ""))
        unique.setdefault(key, item)
    identifiers = [unique[k] for k in sorted(unique)]
    declared_ids = {i["id"] for i in identifiers if i["provenance_class"] == "declared"}
    observed_ids = {i["id"] for i in identifiers if i["provenance_class"] == "repo-iac-observed"}
    if declared_ids & observed_ids:
        state, reason = "corroborated", ""
    elif declared_ids:
        state, reason = "declared", ""
    elif any(i.get("link") for i in identifiers):
        state = "unknown"
        reason = ("no declared identity; the repository issues the listed SPIFFE ID(s) "
                  "to a workload whose entrypoint is this agent's file (annotate the "
                  f"workload with {AGENT_ANNOTATION!r} or declare the identity to confirm)")
    elif observed:
        state = "unknown"
        reason = (f"no declared identity; the repository issues {len(observed)} "
                  "SPIFFE ID(s) that are not attributed to individual agents")
    else:
        state, reason = "unknown", "no declared identity and none issued in the repository"
    return {"state": state, "identifiers": identifiers, "unknown_reason": reason,
            "runtime_verified": False}


def attach_identities(agents, declared, workload_identity):
    """Set ``workload_identity`` on every agent record; return declaration notes.

    A declaration naming no reported agent is returned as a note rather
    than dropped, so a typo in the agent name is visible.
    """
    names = {key for agent in agents for key in (agent.get("name"), agent.get("agent_id"))}
    links = workload_links(agents, workload_identity)
    for agent in agents:
        agent["workload_identity"] = identity_field(agent, declared, workload_identity,
                                                    links.get(agent.get("agent_id")))
    notes = [f"{CONFIG_PATH}: agent_identities names agent {item['agent']!r}, "
             "which this scan did not report" for item in declared
             if item["agent"] not in names]
    for state in (workload_identity or {}).get("workloads") or []:
        annotation = ((state.get("agent_hints") or {}).get("annotation")
                      if isinstance(state, dict) else "")
        if not annotation:
            continue
        matches = {a.get("agent_id") for a in agents
                   if annotation in (a.get("name"), a.get("agent_id"))}
        if len(matches) != 1:
            notes.append(f"{state['workload']}: {AGENT_ANNOTATION} names {annotation!r}, which "
                         + ("matches several agents (use the agent_id)" if matches
                            else "this scan did not report")
                         + "; no identity linked")
    return notes
