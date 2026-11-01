"""Per-tool capability surface: the unit the v1.4 diff compares.

``normalized_capabilities`` answers *what can this repository do?*. It
cannot answer *which tool gained that authority?*, because it collapses
every source into one ``(name, category)`` bucket. The tool surface keeps
the attribution: one entry per tool / MCP server / skill, each holding
its own capabilities and their access modes.

The surface is built from data already present in the scan report — no
new parsing, no file access, no execution — and is fully sorted so that
serialising it is byte-deterministic.
"""

import json

from safeai.analysis.capabilities import (
    access_mode_rank,
    max_access_mode,
    normalize_access_mode,
    resolve_access_mode,
)
from safeai.analysis.tool_identity import (
    UNATTRIBUTED,
    identity_summary,
    make_tool_identity,
    tool_key,
)

TOOL_SURFACE_SCHEMA_VERSION = 1

# Domain inference for MCP tool names. Data, not branches, so it stays
# reviewable and can move to YAML later without a code change.
_DOMAIN_TERMS = (
    ("filesystem", "Filesystem", ("file", "filesystem", "directory", "path", "fs_")),
    ("shell", "Shell", ("shell", "exec", "command", "terminal", "subprocess", "bash")),
    ("databases", "Databases", ("sql", "query", "db_", "database", "postgres", "mysql", "sqlite", "table")),
    ("cloud", "Cloud", ("aws", "azure", "gcp", "s3", "blob", "bucket", "cloud")),
    ("github", "GitHub", ("github", "git_", "pull_request", "repo")),
    ("slack", "Slack", ("slack", "channel")),
    ("email", "Email", ("email", "mail", "smtp")),
    ("browser", "Browser", ("browser", "playwright", "selenium", "puppeteer")),
    ("memory", "Memory", ("memory", "embed", "vector", "recall")),
    ("rag", "RAG", ("rag", "retriev", "index", "knowledge")),
    ("external_apis", "External APIs", ("http", "https", "api_", "request", "webhook", "fetch_url")),
    ("human_approval", "Human Approval", ("approval", "approve", "confirm")),
)

_WRITE_VERBS = ("create", "write", "update", "insert", "upsert", "add", "send", "post", "put", "patch", "upload", "publish", "set")
_MUTATE_VERBS = ("delete", "remove", "drop", "destroy", "purge", "revoke", "truncate", "overwrite", "cancel", "terminate")
_EXECUTE_VERBS = ("exec", "run", "shell", "command", "invoke", "eval", "spawn")


def _mode_from_tool_name(text):
    """Infer an access mode from an MCP/tool name or description."""
    low = str(text or "").lower()
    if any(verb in low for verb in _EXECUTE_VERBS):
        return "execute"
    if any(verb in low for verb in _MUTATE_VERBS):
        return "mutate"
    if any(verb in low for verb in _WRITE_VERBS):
        return "write"
    return "read"


def _domains_for(text):
    low = str(text or "").lower()
    return [
        (name, label)
        for name, label, terms in _DOMAIN_TERMS
        if any(term in low for term in terms)
    ]


def _evidence_entry(path, line):
    return {"path": str(path).replace("\\", "/") if path else None, "line": int(line or 0)}


def _sorted_evidence(entries):
    unique = {(e.get("path"), int(e.get("line") or 0)) for e in entries if e}
    return [{"path": p, "line": ln} for p, ln in sorted(unique, key=lambda x: (x[0] or "", x[1]))]


class _ToolAccumulator:
    """Mutable builder for one tool's surface entry."""

    def __init__(self, identity):
        self.identity = identity
        self.key = tool_key(identity)
        self.capabilities = {}

    def add(self, name, category, access_mode, confidence, evidence, inferred=False,
            targets=None, credentials=None):
        cap_name = str(name or "capability").strip().lower()
        entry = self.capabilities.get(cap_name)
        mode = normalize_access_mode(access_mode)
        if entry is None:
            self.capabilities[cap_name] = {
                "name": cap_name,
                "category": category or "Capability",
                "access_mode": mode,
                "confidence": round(float(confidence or 0.6), 4),
                "inferred": bool(inferred),
                "evidence": list(evidence or []),
                "targets": set(targets or ()),
                "credentials": set(credentials or ()),
            }
            return
        # Keep the strongest observed authority and the highest confidence;
        # accumulate evidence. Inference only survives if every contributor
        # was inferred.
        if access_mode_rank(mode) > access_mode_rank(entry["access_mode"]):
            entry["access_mode"] = mode
        entry["confidence"] = round(max(entry["confidence"], float(confidence or 0.6)), 4)
        entry["inferred"] = bool(entry["inferred"] and inferred)
        entry["evidence"].extend(evidence or [])
        entry["targets"].update(targets or ())
        entry["credentials"].update(credentials or ())

    def finalize(self):
        capabilities = []
        for cap in self.capabilities.values():
            cap = dict(cap)
            cap["evidence"] = _sorted_evidence(cap["evidence"])[:5]
            # v2.9: present only when non-empty, so existing surfaces are unchanged.
            for key in ("targets", "credentials"):
                if cap[key]:
                    cap[key] = sorted(cap[key])
                else:
                    del cap[key]
            capabilities.append(cap)
        capabilities.sort(key=lambda c: (c["name"], c["access_mode"]))
        return {
            "tool_key": self.key,
            "tool": identity_summary(self.identity),
            "capabilities": capabilities,
            "access_summary": max_access_mode(c["access_mode"] for c in capabilities),
        }


def _identity_from_capability(capability):
    identity = capability.get("tool_identity")
    return identity if isinstance(identity, dict) else None


def _collect_from_agent_models(report, accumulators):
    for model in report.get("agent_models") or []:
        path = model.get("file")
        data = model.get("data") or {}
        for capability in data.get("capabilities") or []:
            if not isinstance(capability, dict):
                continue
            identity = _identity_from_capability(capability) or UNATTRIBUTED
            mode = resolve_access_mode(capability)
            key = tool_key(identity)
            acc = accumulators.get(key)
            if acc is None:
                acc = accumulators[key] = _ToolAccumulator(identity)
            acc.add(
                capability.get("name"),
                capability.get("category"),
                mode,
                capability.get("confidence", 0.7),
                [_evidence_entry(path, capability.get("line"))],
                inferred=bool(capability.get("access_mode_inferred")),
                targets=capability.get("targets"),
                credentials=capability.get("credentials"),
            )


def _server_entries(asset):
    """Yield ``(server_name, server_payload)`` pairs from an MCP asset."""
    servers = asset.get("servers") or []
    if isinstance(servers, dict):
        servers = [{"name": k, **(v if isinstance(v, dict) else {})} for k, v in servers.items()]
    for server in servers:
        if isinstance(server, dict):
            name = server.get("name") or server.get("id") or server.get("server")
            yield (str(name) if name else None), server
        elif server:
            yield str(server), {}


def _tool_texts(payload, asset):
    tools = payload.get("tools")
    if tools is None:
        tools = asset.get("tools") or []
    if isinstance(tools, dict):
        tools = [{"name": k, **(v if isinstance(v, dict) else {})} for k, v in tools.items()]
    texts = []
    for tool in tools or []:
        if isinstance(tool, dict):
            name = tool.get("name") or tool.get("id") or ""
            desc = tool.get("description") or ""
            texts.append((str(name), f"{name} {desc}".strip()))
        elif tool:
            texts.append((str(tool), str(tool)))
    return texts


def _collect_from_mcp_assets(report, accumulators):
    for asset in report.get("mcp_assets") or []:
        if not isinstance(asset, dict):
            continue
        path = asset.get("file")
        servers = list(_server_entries(asset))
        if not servers:
            # A config that declares no named server tells us nothing about
            # which server holds the authority. Naming one after the file
            # would invent a server that does not exist, so the capability
            # is recorded as unattributed instead.
            servers = [(None, {})]
        for name, payload in servers:
            identity = (
                make_tool_identity("mcp_server", name, "mcp", source_path=path)
                if name else UNATTRIBUTED
            )
            key = tool_key(identity)
            acc = accumulators.get(key)
            if acc is None:
                acc = accumulators[key] = _ToolAccumulator(identity)

            tool_texts = _tool_texts(payload, asset)
            modes = []
            for tool_name, text in tool_texts:
                mode = _mode_from_tool_name(text)
                modes.append(mode)
                for domain, label in _domains_for(text):
                    acc.add(domain, label, mode, 0.8, [_evidence_entry(path, 0)])
                acc.add(
                    f"mcp_tool:{tool_name.lower()}",
                    "MCP",
                    mode,
                    0.85,
                    [_evidence_entry(path, 0)],
                )
            acc.add("mcp", "MCP", max_access_mode(modes) if modes else "read", 0.85,
                    [_evidence_entry(path, 0)])

            command = payload.get("command") or payload.get("args")
            if command:
                acc.add("shell", "Shell", "execute", 0.75, [_evidence_entry(path, 0)])


def build_tool_surface(report):
    """Return the sorted per-tool capability surface for ``report``."""
    accumulators = {}
    _collect_from_agent_models(report, accumulators)
    _collect_from_mcp_assets(report, accumulators)
    entries = [acc.finalize() for acc in accumulators.values()]
    entries.sort(key=lambda e: e["tool_key"])
    return entries


def surface_index(surface):
    """Index a tool surface by ``tool_key`` for diffing."""
    return {entry["tool_key"]: entry for entry in surface or []}


def serialize_surface(surface):
    """Deterministic JSON serialisation, used for registry persistence."""
    return json.dumps(surface, sort_keys=True, separators=(",", ":"), default=str)
