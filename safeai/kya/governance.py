"""Declared agent governance metadata and OAuth Client ID Metadata Documents (v2.15, plan 2.15-2).

Each agent may carry a ``governance`` field restating what the repository
declares about it in ``.safeai/config.yml``::

    agent_governance:
      - agent: support-bot            # name or agent_id, as the manifest reports it
        owner: support-team@example.com
        lifecycle: production         # one of LIFECYCLE_STATES
        purpose: Answer order questions for signed-in customers
        client_id: https://support.example.com/oauth/client.json

``client_id`` is the agent's OAuth client identifier in the Client ID
Metadata Document form (an ``https`` URL that serves the client's
metadata; CIMD, draft-ietf-oauth-client-id-metadata-document). When a
JSON file in the repository *is* that document (its own ``client_id``
equals the declared URL), its metadata fields are copied into
``governance.client_metadata`` with the file as evidence; otherwise
``client_metadata_state`` says why there is none. Nothing is fetched:
the URL is never dereferenced.

Everything here is ``declared``: SafeAI checks the shape, not the truth,
of what was written. No risk tier is read or emitted.
"""

import json
import os
import re

import yaml

CONFIG_PATH = ".safeai/config.yml"
LIFECYCLE_STATES = ("proposed", "development", "testing", "production", "deprecated",
                    "retired")
#: CIMD / OAuth dynamic client registration metadata fields copied when present.
CLIENT_METADATA_FIELDS = ("client_id", "client_name", "client_uri", "logo_uri",
                          "redirect_uris", "grant_types", "response_types",
                          "token_endpoint_auth_method", "jwks_uri", "scope", "contacts",
                          "software_id", "software_version", "tos_uri", "policy_uri")
_MARKER_FIELDS = ("redirect_uris", "client_name", "grant_types", "token_endpoint_auth_method",
                  "jwks_uri")
_CLIENT_ID_RE = re.compile(r"^https://[^\s/?#]+/[^\s#]*$")
_MAX_FILES = 300
_MAX_BYTES = 256 * 1024
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


class GovernanceError(ValueError):
    """Raised for a malformed ``agent_governance`` declaration."""


def load_declared_governance(root):
    """Read ``agent_governance`` from ``.safeai/config.yml``; ``[]`` when absent."""
    try:
        with open(os.path.join(root, ".safeai", "config.yml"), encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return []
    try:
        document = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise GovernanceError(f"{CONFIG_PATH}: unreadable YAML: {exc}") from exc
    raw = document.get("agent_governance") if isinstance(document, dict) else None
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise GovernanceError(f"{CONFIG_PATH}: 'agent_governance' must be a list")
    lines = text.splitlines()
    declared, seen = [], set()
    for index, item in enumerate(raw, 1):
        where = f"{CONFIG_PATH}: agent_governance #{index}"
        if not isinstance(item, dict):
            raise GovernanceError(f"{where} must be a mapping")
        agent = str(item.get("agent") or "").strip()
        if not agent or agent in seen:
            raise GovernanceError(f"{where} needs a unique 'agent'")
        seen.add(agent)
        entry = {"agent": agent}
        for key in ("owner", "purpose"):
            value = item.get(key)
            if value is not None and not (isinstance(value, str) and value.strip()):
                raise GovernanceError(f"{where}: '{key}' must be a non-empty string")
            entry[key] = value.strip() if value else None
        lifecycle = item.get("lifecycle")
        if lifecycle is not None and lifecycle not in LIFECYCLE_STATES:
            raise GovernanceError(
                f"{where}: 'lifecycle' must be one of {', '.join(LIFECYCLE_STATES)}")
        entry["lifecycle"] = lifecycle
        client_id = item.get("client_id")
        if client_id is not None and not (isinstance(client_id, str)
                                          and _CLIENT_ID_RE.match(client_id)):
            raise GovernanceError(
                f"{where}: 'client_id' must be an https URL with a path (a Client ID "
                "Metadata Document URL)")
        entry["client_id"] = client_id
        if not any(entry[k] for k in ("owner", "lifecycle", "purpose", "client_id")):
            raise GovernanceError(
                f"{where} declares nothing (owner, lifecycle, purpose or client_id)")
        line = next((n for n, text_line in enumerate(lines, 1)
                     if re.search(rf"agent:\s*['\"]?{re.escape(agent)}['\"]?\s*$", text_line)), 1)
        entry["evidence"] = [{"file": CONFIG_PATH, "line": line}]
        declared.append(entry)
    return declared


def collect_client_metadata_documents(root, excluded_paths=None):
    """``{client_id: {fields, evidence}}`` for CIMD-shaped JSON files in the repository.

    A file counts when its top level has an ``https`` ``client_id`` and at
    least one other client-metadata field. Two files claiming one
    ``client_id`` cancel each other (``None``): which is served is unknown.
    """
    found, seen = {}, 0
    excluded = [str(p).replace("\\", "/").strip("/") for p in excluded_paths or []]
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for filename in sorted(filenames):
            if not filename.endswith(".json"):
                continue
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if any(rel == e or rel.startswith(e + "/") for e in excluded):
                continue
            seen += 1
            if seen > _MAX_FILES:
                return found
            try:
                if os.path.getsize(full) > _MAX_BYTES:
                    continue
                with open(full, encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, UnicodeDecodeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            client_id = data.get("client_id")
            if not (isinstance(client_id, str) and _CLIENT_ID_RE.match(client_id)
                    and any(k in data for k in _MARKER_FIELDS)):
                continue
            record = {"fields": {k: data[k] for k in CLIENT_METADATA_FIELDS if k in data},
                      "evidence": [{"file": rel, "line": 1}]}
            found[client_id] = None if client_id in found else record
    return found


def governance_field(item, documents):
    """The ``governance`` field for one declared agent (see module docstring)."""
    field = {k: item.get(k) for k in ("owner", "lifecycle", "purpose", "client_id")}
    field["provenance_class"] = "declared"
    field["evidence"] = list(item["evidence"])
    field["client_metadata"] = None
    if not item.get("client_id"):
        field["client_metadata_state"] = "no-client-id"
    elif item["client_id"] not in documents:
        field["client_metadata_state"] = "not-in-repository"
    elif documents[item["client_id"]] is None:
        field["client_metadata_state"] = "ambiguous"
    else:
        field["client_metadata_state"] = "in-repository"
        field["client_metadata"] = documents[item["client_id"]]
    return field


def attach_governance(agents, declared, documents):
    """Set ``governance`` on each agent a declaration names; return notes."""
    notes = []
    for item in declared:
        matches = [a for a in agents if item["agent"] in (a.get("name"), a.get("agent_id"))]
        if len({a.get("agent_id") for a in matches}) != 1:
            notes.append(f"{CONFIG_PATH}: agent_governance names agent {item['agent']!r}, which "
                         + ("matches several agents (use the agent_id)" if matches
                            else "this scan did not report"))
            continue
        matches[0]["governance"] = governance_field(item, documents)
    return notes
