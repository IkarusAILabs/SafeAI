"""Claude Code settings discovery and defensive parsing.

Scope boundary (v1.4): **only configuration inside the scanned repository
is read.** ``~/.claude/``, ``~/.claude.json``, and any other user-level or
machine-global configuration are deliberately out of scope — including
them would leak a developer's personal environment into a CI artifact.
This module therefore never opens a file: it reads only the scan's
in-memory file cache, which contains repository files exclusively.

Malformed configuration degrades to a reported finding, never a crash.
"""

import json
import re

#: Project-scope settings files, in Claude Code's own precedence order
#: (later entries override earlier ones).
SETTINGS_PRECEDENCE = (
    ".claude/settings.json",
    ".claude/settings.local.json",
)

#: Project MCP server configuration.
MCP_CONFIG = ".mcp.json"

_COMMENT_RE = re.compile(r"(?<!:)//[^\n\"]*$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


def relative_path(root, path):
    """Repository-relative, forward-slash path used for provenance."""
    normalized = str(path).replace("\\", "/")
    root_norm = str(root).replace("\\", "/").rstrip("/")
    if root_norm and normalized.startswith(root_norm + "/"):
        return normalized[len(root_norm) + 1:]
    return normalized


def is_claude_config(rel_path):
    """True for repository paths that hold Claude Code authority."""
    if rel_path in SETTINGS_PRECEDENCE or rel_path == MCP_CONFIG:
        return True
    return rel_path.startswith(".claude/")


def loads_lenient(text):
    """Parse JSON, tolerating comments and trailing commas.

    Returns ``(data, error)``. ``error`` is a short, source-private
    description — never the offending source text.
    """
    try:
        return json.loads(text), None
    except ValueError as exc:
        first_error = str(exc).split(":")[0]
    cleaned = _TRAILING_COMMA_RE.sub(r"\1", _COMMENT_RE.sub("", text))
    try:
        return json.loads(cleaned), None
    except ValueError:
        return None, first_error


def line_of(text, needle):
    """1-based line number of ``needle``'s first occurrence, else 1.

    Used to give a permission entry real provenance without storing the
    surrounding source.
    """
    if not needle:
        return 1
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return 1


def _as_list(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def extract_permission_entries(data):
    """Collect ``(decision, entry)`` pairs from a settings document.

    Handles both the nested ``permissions.allow/deny/ask`` form and the
    flat ``allowedTools`` / ``disallowedTools`` form.
    """
    entries = []
    if not isinstance(data, dict):
        return entries

    permissions = data.get("permissions")
    if isinstance(permissions, dict):
        for decision in ("allow", "deny", "ask"):
            for entry in _as_list(permissions.get(decision)):
                entries.append((decision, entry))

    for entry in _as_list(data.get("allowedTools")):
        entries.append(("allow", entry))
    for entry in _as_list(data.get("disallowedTools")):
        entries.append(("deny", entry))
    return entries


def extract_permission_modes(data):
    """Collect ``(key, value)`` pairs that control the approval gate."""
    modes = []
    if not isinstance(data, dict):
        return modes
    permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    for source in (data, permissions):
        for key in ("defaultMode", "mode", "permissionMode"):
            if key in source:
                modes.append((key, source[key]))
        for key in ("dangerouslySkipPermissions", "dangerously-skip-permissions", "autoApprove"):
            if source.get(key) is True:
                modes.append((key, "bypassPermissions"))
    return modes


def extract_enabled_mcp_servers(data):
    """Servers explicitly enabled by settings (``enabledMcpjsonServers``)."""
    if not isinstance(data, dict):
        return []
    return sorted(set(_as_list(data.get("enabledMcpjsonServers"))))


def extract_mcp_servers(data):
    """Server names declared in ``.mcp.json``."""
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        return sorted(str(name) for name in servers)
    if isinstance(servers, list):
        return sorted(
            str(s.get("name")) for s in servers if isinstance(s, dict) and s.get("name")
        )
    return []


def extract_env_names(data):
    """Names of the environment variables a settings file sets for the session.

    Only the names are returned. Values can be credentials and never leave
    this function.
    """
    env = data.get("env") if isinstance(data, dict) else None
    if not isinstance(env, dict):
        return []
    return sorted(str(name) for name in env if isinstance(name, str) and name)


def extract_hooks(data):
    """Flatten the ``hooks`` block into ``(event, command)`` pairs.

    Claude Code allows several shapes here; each is walked structurally
    and only string ``command`` values are collected.
    """
    hooks = (data or {}).get("hooks") if isinstance(data, dict) else None
    collected = []

    def walk(event, node, under_command=False):
        if isinstance(node, dict):
            command = node.get("command")
            if isinstance(command, str) and command.strip():
                collected.append((event, command.strip()))
            for key, value in sorted(node.items()):
                if key == "command":
                    continue
                # Only descend into containers. Scalar metadata such as
                # ``"type": "command"`` is not itself a hook command.
                if isinstance(value, (dict, list)):
                    walk(event, value, under_command=key in {"command", "commands"})
        elif isinstance(node, list):
            for item in node:
                walk(event, item, under_command=under_command)
        elif isinstance(node, str) and node.strip() and under_command:
            collected.append((event, node.strip()))

    if isinstance(hooks, dict):
        for event, node in sorted(hooks.items()):
            walk(str(event), node, under_command=isinstance(node, (str, list)))
    elif isinstance(hooks, list):
        walk("hooks", hooks, under_command=True)
    # Deduplicate while preserving deterministic order.
    seen = []
    for item in collected:
        if item not in seen:
            seen.append(item)
    return sorted(seen)


def collect_settings(file_cache, root):
    """Return parsed Claude Code configuration found in the repository.

    Result: ``{"documents": [...], "errors": [...]}``. Documents are
    ordered by Claude Code's precedence; ``errors`` carries one entry per
    file that could not be parsed.
    """
    documents = []
    errors = []

    by_rel = {}
    for path, content in file_cache.items():
        rel = relative_path(root, path)
        if is_claude_config(rel) and rel.endswith(".json"):
            by_rel[rel] = (path, content)

    def order_key(rel):
        if rel in SETTINGS_PRECEDENCE:
            return (0, SETTINGS_PRECEDENCE.index(rel), rel)
        if rel == MCP_CONFIG:
            return (1, 0, rel)
        return (2, 0, rel)

    for rel in sorted(by_rel, key=order_key):
        path, content = by_rel[rel]
        data, error = loads_lenient(content)
        if error is not None:
            errors.append({"path": rel, "abs_path": path, "error": error})
            continue
        documents.append({
            "path": rel,
            "abs_path": path,
            "content": content,
            "data": data if isinstance(data, dict) else {},
            "kind": "mcp" if rel == MCP_CONFIG else "settings",
        })
    return {"documents": documents, "errors": errors}
