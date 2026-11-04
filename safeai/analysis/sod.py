"""Separation of Duties (v2.10, ROADMAP B2, plan item 2.11-2).

A Separation-of-Duties conflict is one holder of authority able to do
both halves of a pair that an organisation normally splits between two
parties: create a transaction and approve it, change code and merge it,
act and erase the audit record, or hold authority and rewrite its own
permission policy.

A *holder* is anything whose authority is stated in one place: the
Claude Code session (its ``allow`` rules), a Claude Code subagent (its
``tools``), an MCP server (its declared tool names), an OpenAI Agents
SDK, CrewAI, LangGraph or AutoGen agent (its tool names, and through the
delegation graph the tools of the agents it can hand work to), an AWS IAM
role (its grant actions), or a Kubernetes ServiceAccount (its RBAC verbs
on resources, v2.14).

Kubernetes pairs (v2.14): creating a CertificateSigningRequest and
approving one (``certificatesigningrequests/approval``, or ``approve`` on
``signers``) is ``SOD-REQUEST-APPROVE``; ``escalate`` or ``bind`` on
Roles / ClusterRoles, or ``impersonate``, is ``SOD-SELF-GRANT``; deleting
Events while holding any write verb is ``SOD-ACT-ERASE-AUDIT``. A plain
write to a Role or RoleBinding is not self-grant: Kubernetes refuses a
binding or rule that grants more than the writer already holds.

An organisation adds its own pairs in ``.safeai/config.yml`` (v2.14)::

    separation_of_duties:
      pairs:
        - id: ORG-DEPLOY-APPROVE
          title: deploy a release and approve it
          first: ["deploy_*", "Bash(kubectl apply:*)"]
          second: ["approve_release"]
          why: releases need a second approver

Patterns are case-insensitive globs over the holder's authority items
(tool names, Claude Code allow entries, IAM actions, Kubernetes
``"<verb> <resource>"``). A pair conflicts when one holder has an item
matching ``first`` and an item matching ``second``.

Each half is matched only on authority that *names* the operation:
``Bash(gh pr merge:*)``, an MCP tool ``approve_invoice``, the IAM action
``cloudtrail:StopLogging``. A broad grant (``Bash``, ``Write(*)``, IAM
``*``) can do both halves of every pair; reading a specific conflict into
it would be a guess, and its breadth is already reported elsewhere.

Findings are ``SOD_CONFLICTING_AUTHORITY``: low severity and review-only
(Lane B, ADR-0008) until precision on the benchmark is published.
"""

import fnmatch
import os
import re

import yaml

from safeai.analysis.delegation import PYTHON_FRAMEWORKS

RULE_SOD = "SOD_CONFLICTING_AUTHORITY"

#: Pair catalogue: id → (title, first half, second half, why).
PAIRS = {
    "SOD-REQUEST-APPROVE": (
        "create and approve the same kind of transaction",
        "request", "approve",
        ("the same holder can raise a transaction and approve it, so no second "
         "party ever sees it")),
    "SOD-CHANGE-MERGE": (
        "change code and merge or approve that change",
        "code-change", "merge-approve",
        "the same holder can write a change and land it without independent review"),
    "SOD-ACT-ERASE-AUDIT": (
        "act and erase or disable the audit trail",
        "act", "erase-audit",
        "the same holder can make changes and remove the record of them"),
    "SOD-SELF-GRANT": (
        "rewrite its own permission policy",
        "act", "self-grant",
        "the holder can widen its own permissions without anyone approving it"),
}

CONFIG_PATH = ".safeai/config.yml"
#: Organisation pair IDs: upper case, digits and dashes; never a built-in ID.
_ORG_ID_RE = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")


class SodCatalogueError(ValueError):
    """Raised for a malformed ``separation_of_duties.pairs`` declaration."""


def load_org_pairs(root):
    """Read the organisation pair catalogue from ``.safeai/config.yml``.

    Returns ``[{id, title, first, second, why, evidence}]``; a missing file
    or key yields ``[]``. A malformed entry raises ``SodCatalogueError``.
    """
    try:
        with open(os.path.join(root, ".safeai", "config.yml"), encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return []
    try:
        document = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise SodCatalogueError(f"{CONFIG_PATH}: unreadable YAML: {exc}") from exc
    section = document.get("separation_of_duties") if isinstance(document, dict) else None
    if section is None:
        return []
    raw = section.get("pairs") if isinstance(section, dict) else None
    if not isinstance(raw, list):
        raise SodCatalogueError(f"{CONFIG_PATH}: 'separation_of_duties.pairs' must be a list")
    lines = text.splitlines()
    pairs, seen = [], set()
    for index, item in enumerate(raw, 1):
        where = f"{CONFIG_PATH}: separation_of_duties.pairs #{index}"
        if not isinstance(item, dict):
            raise SodCatalogueError(f"{where} must be a mapping")
        pair_id = str(item.get("id") or "").strip()
        if not _ORG_ID_RE.match(pair_id) or pair_id in PAIRS or pair_id in seen:
            raise SodCatalogueError(
                f"{where}: 'id' must be unique, upper case (A-Z, 0-9, '-') and not a "
                f"built-in pair ({', '.join(sorted(PAIRS))})")
        seen.add(pair_id)
        title = str(item.get("title") or "").strip()
        halves = [item.get("first"), item.get("second")]
        if not title or not all(isinstance(h, list) and h and all(
                isinstance(x, str) and x.strip() for x in h) for h in halves):
            raise SodCatalogueError(
                f"{where}: needs 'title' and non-empty 'first' and 'second' pattern lists")
        line = next((n for n, text_line in enumerate(lines, 1) if pair_id in text_line), 1)
        pairs.append({"id": pair_id, "title": title,
                      "first": [x.strip() for x in halves[0]],
                      "second": [x.strip() for x in halves[1]],
                      "why": str(item.get("why") or "").strip()
                      or "the organisation's pair catalogue keeps these duties apart",
                      "evidence": {"file": CONFIG_PATH, "line": line}})
    return pairs


def _org_conflicts(items, org_pairs):
    """``[(pair_id, first_items, second_items)]`` for organisation pairs."""
    def matching(patterns):
        return sorted(i for i in items if any(
            fnmatch.fnmatchcase(str(i).lower(), p.lower()) for p in patterns))
    found = []
    for pair in org_pairs:
        firsts, seconds = matching(pair["first"]), matching(pair["second"])
        if firsts and seconds:
            found.append((pair["id"], firsts, seconds))
    return found


_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
_REQUEST_VERBS = {"create", "submit", "request", "issue", "initiate", "raise", "draft",
                  "open"}
_APPROVE_VERBS = {"approve", "authorize", "authorise", "release", "signoff", "countersign"}
#: Objects that make create/approve a *transaction* pair (not create_issue + approve_pr).
_GENERIC_NOUNS = {"a", "an", "the", "new", "item", "request", "record", "tool", "mcp"}
_CODE_CHANGE_TOOLS = {"create_or_update_file", "push_files", "create_commit", "commit_files",
                      "update_file", "write_file", "edit_file"}
_MERGE_TOOLS = {"merge_pull_request", "merge_pr", "approve_pull_request",
                "create_pull_request_review", "approve_pr", "enable_auto_merge"}

_FILE_WRITE_ENTRIES = re.compile(r"^(Write|Edit|MultiEdit)(\((?P<arg>.*)\))?$")
_BASH_ENTRY = re.compile(r"^Bash\((?P<arg>.+)\)$")
_MERGE_COMMANDS = ("gh pr merge", "gh pr review", "git push origin main",
                   "git push origin master", "git merge")
_COMMIT_COMMANDS = ("git commit", "git push", "git apply", "git am")
_SETTINGS_PATHS = (".claude/settings.json", ".claude/settings.local.json", ".claude/**",
                   ".claude/*", ".claude/")

#: IAM actions that erase or switch off the audit record.
_AUDIT_ERASE_ACTIONS = {
    "cloudtrail:stoplogging", "cloudtrail:deletetrail", "cloudtrail:updatetrail",
    "cloudtrail:putEventSelectors".lower(), "cloudtrail:*",
    "logs:deleteloggroup", "logs:deletelogstream", "logs:putretentionpolicy", "logs:*",
    "config:stopconfigurationrecorder", "config:deleteconfigurationrecorder",
    "guardduty:deletedetector", "guardduty:updatedetector",
}
_WRITE_PREFIXES = ("put", "create", "delete", "update", "modify", "attach", "run", "invoke",
                   "start", "terminate", "write", "send", "publish")

#: Kubernetes RBAC (v2.14). Items are ``"<verb> <resource>"``.
_K8S_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
_K8S_CSR = ("certificatesigningrequest",)


def _tokens(name):
    return [t.lower() for t in _SPLIT_RE.split(str(name or "")) if t]


# --- role predicates -----------------------------------------------------------

def _tool_name_roles(name):
    """Roles a tool *name* names, with the transaction object for request/approve."""
    roles = set()
    lowered = str(name or "").lower()
    tokens = _tokens(name)
    objects = tuple(t for t in tokens if t not in _REQUEST_VERBS | _APPROVE_VERBS
                    and t not in _GENERIC_NOUNS)
    if lowered in _CODE_CHANGE_TOOLS:
        roles.add(("code-change", None))
    if lowered in _MERGE_TOOLS:
        roles.add(("merge-approve", None))
    if tokens and objects and lowered not in _MERGE_TOOLS:
        if tokens[0] in _REQUEST_VERBS or (len(tokens) > 1 and tokens[-1] in _REQUEST_VERBS):
            roles.add(("request", objects))
        if tokens[0] in _APPROVE_VERBS or (len(tokens) > 1 and tokens[-1] in _APPROVE_VERBS):
            roles.add(("approve", objects))
    return roles


def _claude_entry_roles(entry):
    """Roles a Claude Code allow entry (or subagent tool) names."""
    text = str(entry or "").strip()
    roles = set()
    match = _FILE_WRITE_ENTRIES.match(text)
    if match:
        arg = (match.group("arg") or "").strip()
        if arg and arg not in ("*", "**", "**/*", "./**"):
            roles.add(("code-change", None))
            normalized = arg.removeprefix("./")
            if any(normalized == p or normalized.startswith(".claude/")
                   for p in _SETTINGS_PATHS):
                roles.add(("self-grant", None))
        return roles
    match = _BASH_ENTRY.match(text)
    if match:
        command = match.group("arg").replace(":*", "").strip().strip("*").strip()
        if command.startswith(_MERGE_COMMANDS):
            roles.add(("merge-approve", None))
        if command.startswith(_COMMIT_COMMANDS):
            roles.add(("code-change", None))
        if roles:
            roles.add(("act", None))
        return roles
    if text.startswith("mcp__"):
        tool = text.split("__", 2)[2] if text.count("__") >= 2 else ""
        return _tool_name_roles(tool)
    return roles


def _action_roles(action):
    lowered = str(action or "").lower()
    roles = set()
    if lowered in _AUDIT_ERASE_ACTIONS:
        roles.add(("erase-audit", None))
    elif ":" in lowered and lowered != "*":
        verb = lowered.split(":", 1)[1]
        if verb.startswith(_WRITE_PREFIXES):
            roles.add(("act", None))
    return roles


def _k8s_roles(item):
    """Roles one Kubernetes ``"<verb> <resource>"`` item names. Wildcards name none."""
    verb, _, resource = str(item or "").partition(" ")
    if verb == "*" or resource in ("", "*") or resource.startswith("*"):
        return set()
    base = resource.split("/", 1)[0]
    roles = set()
    if resource == "certificatesigningrequests" and verb == "create":
        roles.add(("request", _K8S_CSR))
    if (resource == "certificatesigningrequests/approval" and verb in ("update", "patch")) \
            or (resource == "signers" and verb == "approve"):
        roles.add(("approve", _K8S_CSR))
    if (verb in ("escalate", "bind") and base in ("roles", "clusterroles")) \
            or (verb == "impersonate" and base in ("users", "groups", "serviceaccounts")):
        roles.add(("self-grant", None))
    if base == "events" and verb in ("delete", "deletecollection"):
        roles.add(("erase-audit", None))
    elif verb in _K8S_WRITE_VERBS:
        roles.add(("act", None))
    return roles


# --- conflicts -----------------------------------------------------------------

def _conflicts(items):
    """``[(pair_id, first_items, second_items)]`` for one holder.

    ``items`` maps an authority item (entry, tool name, action) to its roles.
    """
    found = []
    for pair_id, (_title, first, second, _why) in sorted(PAIRS.items()):
        firsts = {i: r for i, roles in items.items() for (role, r) in roles if role == first}
        seconds = {i: r for i, roles in items.items() for (role, r) in roles if role == second}
        if pair_id == "SOD-REQUEST-APPROVE":
            # Same transaction object on both sides, or it is two duties
            # over different things (create_issue + approve_invoice).
            hits = [(a, b) for a, oa in firsts.items() for b, ob in seconds.items()
                    if a != b and set(oa or ()) & set(ob or ())]
            if hits:
                found.append((pair_id, sorted({a for a, _ in hits}),
                              sorted({b for _, b in hits})))
            continue
        if pair_id == "SOD-SELF-GRANT":
            # Editing its own permission file lets a holder grant itself
            # anything: a conflict on its own. Its other authority is context.
            if seconds:
                found.append((pair_id, sorted(i for i in items if i not in seconds),
                              sorted(seconds)))
            continue
        # One item may carry both roles (``git push origin main`` changes and
        # lands code in one step): still a conflict.
        if firsts and seconds:
            found.append((pair_id, sorted(firsts), sorted(seconds)))
    return found


def _claude_holders(report):
    graph = report.get("delegation_graph") or {}
    holders = []
    for node in graph.get("nodes") or []:
        if node.get("framework") != "claude_code":
            continue
        holders.append({"holder": f"claude_code:{node['name']}", "kind": node["kind"],
                        "items": list(node.get("authority") or []),
                        "file": node.get("source_file") or "", "line": 1,
                        "provenance_class": "detected", "role_fn": _claude_entry_roles,
                        "via": {}})
    return holders


def _agent_holders(report):
    graph = report.get("delegation_graph") or {}
    nodes = {n["id"]: n for n in graph.get("nodes") or []
             if n.get("framework") in PYTHON_FRAMEWORKS}
    adjacency = {}
    for edge in graph.get("edges") or []:
        if edge.get("from") in nodes and edge.get("to") in nodes:
            adjacency.setdefault(edge["from"], set()).add(edge["to"])
    holders = []
    for node_id, node in sorted(nodes.items()):
        via = {}
        seen, stack = {node_id}, [node_id]
        while stack:
            for nxt in sorted(adjacency.get(stack.pop(), ())):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
                    for tool in nodes[nxt].get("authority") or []:
                        if tool not in (node.get("authority") or []):
                            via.setdefault(tool, nodes[nxt]["name"])
        items = sorted(set(node.get("authority") or []) | set(via))
        holders.append({"holder": f"{node['framework']}:{node['name']}", "kind": "agent",
                        "items": items, "file": node.get("source_file") or "",
                        "line": int(node.get("line") or 1), "provenance_class": "inferred",
                        "role_fn": _tool_name_roles, "via": via})
    return holders


def _mcp_holders(report):
    holders = []
    for tool in report.get("tool_surface") or []:
        key = str(tool.get("tool_key") or "")
        if not key.startswith("mcp_server:"):
            continue
        names, files = [], []
        for cap in tool.get("capabilities") or []:
            name = str(cap.get("name") or "")
            if name.startswith("mcp_tool:"):
                names.append(name.split(":", 1)[1])
            for ref in cap.get("evidence") or []:
                if isinstance(ref, dict) and ref.get("path"):
                    files.append((ref["path"], int(ref.get("line") or 1)))
        if names:
            path, line = (sorted(files) or [("", 1)])[0]
            holders.append({"holder": key, "kind": "mcp_server", "items": sorted(set(names)),
                            "file": path, "line": line, "provenance_class": "inferred",
                            "role_fn": _tool_name_roles, "via": {}})
    return holders


def _iac_holders(report):
    by_identity = {}
    for grant in (report.get("iac_correlations") or {}).get("grants") or []:
        ident = grant.get("identity") or {}
        if ident.get("kind") != "aws_iam_role" and not str(ident.get("kind", "")).startswith(
                "aws"):
            continue
        key = f"{ident.get('kind')}:{ident.get('name')}"
        entry = by_identity.setdefault(key, {"items": set(), "file": grant.get("source_file"),
                                             "line": int(grant.get("line") or 1)})
        entry["items"].update((grant.get("actions") or {}).get("values") or [])
    return [{"holder": key, "kind": "iac_identity", "items": sorted(v["items"]),
             "file": v["file"] or "", "line": v["line"], "provenance_class": "repo-iac-observed",
             "role_fn": _action_roles, "via": {}}
            for key, v in sorted(by_identity.items())]


def _k8s_holders(report):
    by_identity = {}
    for grant in (report.get("iac_correlations") or {}).get("grants") or []:
        ident = grant.get("identity") or {}
        if ident.get("kind") != "kubernetes_service_account":
            continue
        key = f"kubernetes_service_account:{ident.get('namespace') or ''}/{ident.get('name')}"
        entry = by_identity.setdefault(key, {"items": set(), "file": grant.get("source_file"),
                                             "line": int(grant.get("line") or 1)})
        verbs = (grant.get("actions") or {}).get("values") or []
        resources = (grant.get("resources") or {}).get("values") or []
        entry["items"].update(f"{verb} {resource}" for verb in verbs for resource in resources)
    return [{"holder": key, "kind": "iac_identity", "items": sorted(v["items"]),
             "file": v["file"] or "", "line": v["line"], "provenance_class": "repo-iac-observed",
             "role_fn": _k8s_roles, "via": {}}
            for key, v in sorted(by_identity.items())]


def analyze_separation_of_duties(report, org_pairs=None):
    """Return ``(findings, summary)`` for one assembled report. Never raises.

    ``org_pairs`` is the organisation catalogue from ``load_org_pairs``.
    """
    org_pairs = list(org_pairs or [])
    org = {pair["id"]: pair for pair in org_pairs}
    holders = (_claude_holders(report) + _mcp_holders(report) + _agent_holders(report)
               + _iac_holders(report) + _k8s_holders(report))
    conflicts, findings = [], []
    for holder in holders:
        items = {item: holder["role_fn"](item) for item in holder["items"]}
        for pair_id, firsts, seconds in _conflicts(items) + _org_conflicts(items, org_pairs):
            if pair_id in org:
                title, why = org[pair_id]["title"], org[pair_id]["why"]
            else:
                title, _first, _second, why = PAIRS[pair_id]
            via = sorted({holder["via"][i] for i in firsts + seconds if i in holder["via"]})
            record = {"holder": holder["holder"], "holder_kind": holder["kind"],
                      "pair": pair_id, "first": firsts, "second": seconds,
                      "via_delegation": via, "file": holder["file"], "line": holder["line"],
                      "provenance_class": holder["provenance_class"],
                      "catalogue": "organisation" if pair_id in org else "built-in"}
            conflicts.append(record)
            through = f" (through delegation to {', '.join(via)})" if via else ""
            findings.append({
                "rule_id": RULE_SOD,
                "severity": "low",
                "message": f"{holder['holder']} can {title}{through}",
                "file": holder["file"] or "<scan>",
                "line": holder["line"],
                "risk_category": "Governance",
                "affected_framework": holder["holder"].split(":", 1)[0],
                "affected_capability": pair_id,
                "provenance_class": holder["provenance_class"],
                "gateability": "review-only",
                "evidence": (f"pair={pair_id} holder={holder['holder']} "
                             f"first={', '.join(firsts)} second={', '.join(seconds)}"
                             + (f" via={', '.join(via)}" if via else "")
                             + (f" catalogue={CONFIG_PATH}" if pair_id in org else "")),
                "reason": why,
                "remediation": ("Split the two duties between holders that a second party "
                                "controls, or require an approval step between them, and "
                                "record why if the combination is intended."),
                "confidence": 0.6 if holder["provenance_class"] == "detected" else 0.45,
                "score_contribution": 3,
            })
    conflicts.sort(key=lambda c: (c["holder"], c["pair"]))
    findings.sort(key=lambda f: (f["file"], f["line"], f["evidence"]))
    summary = {"lane": "B", "pairs": sorted(set(PAIRS) | set(org)), "conflicts": conflicts,
               "holders_checked": len(holders)}
    if org_pairs:
        summary["organisation_pairs"] = [
            {"id": pair["id"], "title": pair["title"], "first": pair["first"],
             "second": pair["second"], "evidence": pair["evidence"]}
            for pair in sorted(org_pairs, key=lambda pair: pair["id"])]
    return findings, summary
