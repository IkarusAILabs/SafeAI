"""Canonical capability categories, access modes, and convenience builders.

Capabilities represent what an AI agent can *do* (shell execution,
filesystem access, database queries, memory, etc.). These categories
are used by all framework parsers and the capability analyzer to
produce a consistent risk picture.

Since v1.4 a capability may additionally carry:

``tool_identity``
    Which tool / MCP server / skill holds the capability
    (see :mod:`safeai.analysis.tool_identity`).
``access_mode``
    How much authority the capability grants, on the ordered scale
    :data:`ACCESS_MODES`.

Both are **optional keyword-only** additions: every pre-1.4 adapter that
calls ``make_capability`` positionally keeps working unchanged.
"""

import re

CAPABILITY_CATEGORIES = {
    "filesystem": "Filesystem",
    "shell": "Shell",
    "browser": "Browser",
    "planner": "Planner",
    "delegation": "Delegation",
    "memory": "Memory",
    "rag": "RAG",
    "github": "GitHub",
    "slack": "Slack",
    "email": "Email",
    "databases": "Databases",
    "cloud": "Cloud",
    "external_apis": "External APIs",
    "mcp": "MCP",
    "human_approval": "Human Approval",
    "multi_agent": "Multi-Agent",
    "container": "Container",
    "collaboration": "Collaboration",
    "untrusted_input": "Untrusted Input",
    "package_manager": "Package Manager",
}

#: Ordered by ascending severity of the authority granted.
ACCESS_MODES = ["none", "read", "write", "mutate", "execute"]

_ACCESS_RANK = {mode: index for index, mode in enumerate(ACCESS_MODES)}

# --- Heuristic vocabulary for infer_access_mode -------------------------
# Keep these as data, not branching logic, so the inference stays auditable.

_EXECUTE_CATEGORIES = {"shell", "container"}
_EXECUTE_TERMS = (
    "shell", "exec", "subprocess", "command", "terminal", "bash", "sh(",
    "eval", "compile", "spawn", "popen", "system(", "run_code", "code_exec",
)
_MUTATE_TERMS = (
    "delete", "drop", "destroy", "remove", "purge", "revoke", "truncate",
    "mutate", "overwrite", "rotate", "terminate",
)
_WRITE_TERMS = (
    "write", "create", "update", "insert", "upsert", "patch", "put", "post",
    "send", "publish", "upload", "commit", "push", "merge", "modify", "set_",
    "append", "save", "store", "provision", "deploy",
)
_READONLY_TERMS = (
    "read", "get", "list", "search", "query", "fetch", "retrieve", "describe",
    "view", "lookup", "inspect",
)
_NONE_CATEGORIES = {"human_approval"}


def access_mode_rank(mode):
    """Return the ordinal severity of ``mode``; unknown values rank as ``none``."""
    return _ACCESS_RANK.get(str(mode or "none").strip().lower(), 0)


def normalize_access_mode(mode):
    """Coerce an arbitrary value to a member of :data:`ACCESS_MODES`."""
    candidate = str(mode or "").strip().lower()
    return candidate if candidate in _ACCESS_RANK else "none"


def is_escalation(before, after):
    """True when ``after`` grants strictly more authority than ``before``."""
    return access_mode_rank(after) > access_mode_rank(before)


def max_access_mode(modes):
    """Return the highest access mode in ``modes`` (``"none"`` when empty)."""
    highest = "none"
    for mode in modes or []:
        if access_mode_rank(mode) > access_mode_rank(highest):
            highest = normalize_access_mode(mode)
    return highest


def make_capability(
    name,
    category,
    framework,
    evidence,
    confidence=0.7,
    risk_weight=1.0,
    source="ast",
    resolved_definition=None,
    *,
    tool_identity=None,
    access_mode=None,
    line=None,
    targets=None,
    credentials=None,
):
    """Create a standardized capability dict consumed by the aggregation pipeline.

    The positional signature is frozen for backward compatibility with the
    framework adapters shipped before v1.4. ``tool_identity``,
    ``access_mode`` and ``line`` are keyword-only and default to ``None``.
    Since v2.9, ``targets`` lists the dependency routes the capability
    confers (see :mod:`safeai.analysis.package_managers`) and
    ``credentials`` the credential *names* bound to it; both are omitted
    when empty.
    """
    capability = {
        "name": name,
        "category": category,
        "source_framework": framework,
        "evidence": evidence,
        "confidence": confidence,
        "risk_weight": risk_weight,
        "source": source,
        "resolved_definition": resolved_definition,
    }
    if tool_identity is not None:
        capability["tool_identity"] = tool_identity
    if access_mode is not None:
        capability["access_mode"] = normalize_access_mode(access_mode)
    if line is not None:
        try:
            capability["line"] = int(line)
        except (TypeError, ValueError):
            capability["line"] = 0
    if targets:
        capability["targets"] = sorted(set(targets))
    if credentials:
        capability["credentials"] = sorted(set(credentials))
    return capability


def _capability_text(capability):
    parts = [
        capability.get("name"),
        capability.get("category"),
        capability.get("resolved_definition"),
    ]
    evidence = capability.get("evidence")
    if isinstance(evidence, (list, tuple)):
        parts.extend(str(item) for item in evidence)
    else:
        parts.append(evidence)
    return " ".join(str(p) for p in parts if p).lower()


def infer_access_mode(capability):
    """Conservatively infer an access mode for a capability that lacks one.

    Adapters that have not yet been taught access modes still need a value
    so the diff can compare like with like. The heuristic reads only the
    capability's own name, category and evidence text.

    When the evidence carries no directional signal at all the function
    returns ``"read"`` (the least-alarming defensible value) and sets
    ``access_mode_inferred = True`` on the capability. Downstream,
    escalations derived from an inferred value are capped below
    ``critical`` — a guess must never be presented as a certainty.
    """
    if not isinstance(capability, dict):
        return "read"

    explicit = capability.get("access_mode")
    if explicit:
        return normalize_access_mode(explicit)

    category = str(capability.get("category") or "").strip().lower()
    name = str(capability.get("name") or "").strip().lower()
    text = _capability_text(capability)

    capability["access_mode_inferred"] = True
    if category in _NONE_CATEGORIES or name in _NONE_CATEGORIES:
        return "none"
    if category in _EXECUTE_CATEGORIES or name in _EXECUTE_CATEGORIES:
        return "execute"
    if any(term in text for term in _EXECUTE_TERMS):
        return "execute"
    if any(term in text for term in _MUTATE_TERMS):
        return "mutate"
    if any(re.search(rf"\b{re.escape(term)}", text) for term in _WRITE_TERMS):
        return "write"
    if any(term in text for term in _READONLY_TERMS):
        return "read"
    return "read"


def resolve_access_mode(capability):
    """Return ``capability``'s access mode, inferring and recording it if absent.

    Mutates the capability in place so the inference is visible to every
    later stage (diff, escalation, assurance boundary).
    """
    if not isinstance(capability, dict):
        return "read"
    if capability.get("access_mode"):
        capability["access_mode"] = normalize_access_mode(capability["access_mode"])
        capability.setdefault("access_mode_inferred", False)
        return capability["access_mode"]
    mode = infer_access_mode(capability)
    capability["access_mode"] = mode
    capability.setdefault("access_mode_inferred", False)
    return mode


def dedupe_capabilities(caps):
    """Remove duplicate capabilities within a single parser result.

    Keyed by name, category, framework, resolved definition and — since
    v1.4 — the owning tool and the access mode, so that the same
    capability held by two different tools is no longer collapsed.
    """
    from safeai.analysis.tool_identity import tool_key

    out = []
    seen = set()
    for c in caps:
        identity = c.get("tool_identity")
        key = (
            c.get("name"),
            c.get("category"),
            c.get("source_framework"),
            c.get("resolved_definition"),
            tool_key(identity) if identity else None,
            c.get("access_mode"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out
