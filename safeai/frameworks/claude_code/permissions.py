"""Claude Code permission model → capabilities with identity and access mode.

A Claude Code permission entry looks like ``Tool(argument)`` — for example
``Bash(npm run test:*)``, ``Write(*)``, ``Read(~/.zshrc)`` — or a bare tool
name such as ``Bash``, or an MCP-scoped grant ``mcp__github__create_issue``.

Each entry is translated into a capability carrying a stable tool identity
and an access mode, so the Workstream 1 diff can say *which named tool*
gained authority rather than only that "a permission changed".

Everything here is pure string analysis. Nothing is executed, no file is
opened, and no path outside the scanned repository is consulted.
"""

import re

from safeai.analysis import package_managers
from safeai.analysis.capabilities import make_capability
from safeai.analysis.tool_identity import make_tool_identity
from safeai.kya.util import redact_secrets

#: ``Tool(argument)`` or a bare ``Tool``.
_ENTRY_RE = re.compile(r"^\s*(?P<tool>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\((?P<arg>.*)\)\s*)?$", re.DOTALL)

#: ``mcp__<server>`` or ``mcp__<server>__<tool>``. Segments are split on the
#: literal ``__`` separator rather than matched with a greedy character
#: class, so ``mcp__github__create_issue`` resolves to the *github* server
#: and not to a server literally named ``github__create_issue``.
_MCP_SEGMENT_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def split_mcp_entry(text):
    """Return ``(server, tool)`` for an MCP grant, or ``None``.

    ``tool`` is ``None`` when the grant covers the whole server. Tool names
    may themselves contain ``__``; only the first two segments are fixed.
    """
    parts = str(text or "").split("__")
    if len(parts) < 2 or parts[0] != "mcp":
        return None
    server = parts[1]
    if not _MCP_SEGMENT_RE.match(server):
        return None
    tool = "__".join(parts[2:]) or None
    return server, tool

#: Built-in Claude Code tools → (capability name, category, access mode).
#:
#: Access modes follow the tool's *documented* effect, not a guess: ``Bash``
#: executes, ``Write`` writes, ``Read`` reads. Anything not listed here is
#: recorded as an unknown tool at ``read`` and marked inferred by the
#: capability layer, so it can never drive a critical verdict on its own.
BUILTIN_TOOLS = {
    "bash": ("shell", "Shell", "execute"),
    "bashoutput": ("shell", "Shell", "read"),
    "killshell": ("shell", "Shell", "execute"),
    "write": ("filesystem", "Filesystem", "write"),
    "edit": ("filesystem", "Filesystem", "write"),
    "multiedit": ("filesystem", "Filesystem", "write"),
    "notebookedit": ("filesystem", "Filesystem", "write"),
    "read": ("filesystem", "Filesystem", "read"),
    "glob": ("filesystem", "Filesystem", "read"),
    "grep": ("filesystem", "Filesystem", "read"),
    "ls": ("filesystem", "Filesystem", "read"),
    "webfetch": ("external_apis", "External APIs", "read"),
    "websearch": ("external_apis", "External APIs", "read"),
    "task": ("delegation", "Delegation", "execute"),
    "agent": ("delegation", "Delegation", "execute"),
    "todowrite": ("memory", "Memory", "write"),
}

#: Tools whose authority is a write or worse. Used for scope checks.
WRITE_TOOLS = {name for name, (_, _, mode) in BUILTIN_TOOLS.items() if mode in {"write", "mutate", "execute"}}

#: MCP tool-name stems that indicate a mutating (not read-only) operation.
_MCP_MUTATE_STEMS = (
    "create", "update", "delete", "remove", "write", "merge", "push", "put",
    "post", "patch", "set", "add", "close", "publish", "deploy", "revoke",
)

#: Settings values that disable the human approval gate entirely.
BYPASS_VALUES = {"bypasspermissions", "bypass", "dangerously-skip-permissions", "yolo"}

#: Permissive but not fully bypassing — reported at a reduced severity.
PERMISSIVE_MODES = {"acceptedits", "acceptall", "auto"}

_OUTSIDE_ROOT_RE = re.compile(r"^\s*(?:/|~|\.\./)|(?:^|/)\.\./")


def _wildcard(argument):
    """True when the argument grants the tool's full surface."""
    if argument is None:
        return True  # a bare `Bash` grant is unconstrained
    stripped = argument.strip().strip("\"'")
    return stripped in {"", "*", "**", "*:*", "//*"}


def mcp_access_mode(tool_name):
    """Infer read vs mutate for an MCP tool from its verb stem."""
    lowered = str(tool_name or "").lower()
    if any(stem in lowered for stem in _MCP_MUTATE_STEMS):
        return "mutate"
    return "read"


def parse_entry(entry):
    """Split a permission entry into ``(tool, argument)``.

    Returns ``(None, None)`` when the entry is not in a recognized form,
    so the caller can record it as unparsed rather than guessing.
    """
    text = str(entry or "").strip()
    if not text:
        return None, None
    match = _ENTRY_RE.match(text)
    if not match:
        return None, None
    return match.group("tool"), match.group("arg")


def classify_entry(entry, decision, path, line=0):
    """Translate one permission entry into a structured record.

    ``decision`` is ``allow``, ``deny``, or ``ask``. The returned record
    carries provenance (path/line), the resolved tool identity, and the
    access mode the grant confers.
    """
    text = str(entry or "").strip()
    redacted_text = redact_secrets(text, full_mask=True)
    mcp_match = split_mcp_entry(text)
    if mcp_match:
        server, mcp_tool = mcp_match
        identity = make_tool_identity("mcp_server", server, "claude_code", source_path=path)
        return {
            "entry": redacted_text,
            "decision": decision,
            "tool": f"mcp__{server}",
            "argument": mcp_tool,
            "capability": "mcp",
            "category": "MCP",
            "access_mode": mcp_access_mode(mcp_tool) if mcp_tool else "mutate",
            "wildcard": mcp_tool in (None, "*"),
            "mcp_server": server,
            "identity": identity,
            "path": path,
            "line": line,
            "recognized": True,
        }

    tool, argument = parse_entry(text)
    if not tool:
        return {
            "entry": redacted_text,
            "decision": decision,
            "tool": None,
            "argument": None,
            "capability": None,
            "category": None,
            "access_mode": "read",
            "wildcard": False,
            "mcp_server": None,
            "identity": make_tool_identity("unknown", None, "claude_code", source_path=path),
            "path": path,
            "line": line,
            "recognized": False,
        }

    capability, category, access_mode = BUILTIN_TOOLS.get(
        tool.lower(), ("tool_grant", "Collaboration", "read")
    )
    return {
        "entry": redacted_text,
        "decision": decision,
        "tool": tool,
        "argument": argument,
        "capability": capability,
        "category": category,
        "access_mode": access_mode,
        "wildcard": _wildcard(argument),
        "mcp_server": None,
        "identity": make_tool_identity("tool", tool, "claude_code", source_path=path),
        "path": path,
        "line": line,
        "recognized": tool.lower() in BUILTIN_TOOLS,
    }


def capability_for(record, evidence_prefix="claude code permission"):
    """Build a SafeAI capability from a classified permission record.

    Only ``allow`` grants confer authority. ``deny`` and ``ask`` entries
    are recorded for shadowing analysis but never add capability.
    """
    if record["decision"] != "allow" or not record["capability"]:
        return None
    return make_capability(
        record["capability"],
        record["category"],
        "claude_code",
        f"{evidence_prefix}: {record['entry']}",
        confidence=0.9 if record["recognized"] else 0.6,
        source="config",
        tool_identity=record["identity"],
        access_mode=record["access_mode"],
        line=record.get("line", 0),
    )


#: Built-in tools whose argument is a file path pattern that writes.
_FILE_WRITE_TOOLS = {"write", "edit", "multiedit"}


def capabilities_for(record, evidence_prefix="claude code permission", credentials=()):
    """All capabilities an ``allow`` grant confers, as a list (v2.9).

    The first is :func:`capability_for`'s, unchanged except that a write
    grant naming a dependency manifest carries that manifest as a target.
    A ``Bash`` grant whose command runs a package manager adds a
    ``package_manager`` capability on the same tool, carrying its routes
    as targets and the registry ``credentials`` names given (from the same
    settings file). A broad ``Bash`` or ``Write(*)`` grant adds nothing:
    its shell or filesystem authority is already reported, and reading a
    dependency route into it would be a guess.
    """
    primary = capability_for(record, evidence_prefix=evidence_prefix)
    if primary is None:
        return []
    tool = str(record.get("tool") or "").lower()
    argument = record.get("argument")
    if tool in _FILE_WRITE_TOOLS and not record.get("wildcard"):
        targets = package_managers.manifest_targets(argument)
        if targets:
            primary["targets"] = targets
    capabilities = [primary]
    if tool == "bash" and not record.get("wildcard"):
        targets = package_managers.command_targets(argument)
        if targets:
            capabilities.append(make_capability(
                "package_manager", "Package Manager", "claude_code",
                f"{evidence_prefix}: {record['entry']}",
                confidence=0.9, source="config",
                tool_identity=record["identity"],
                access_mode=package_managers.access_mode_for(targets),
                line=record.get("line", 0),
                targets=targets,
                credentials=package_managers.registry_credentials(credentials),
            ))
    return capabilities


def argument_covers(broad, narrow):
    """True when permission argument ``broad`` subsumes ``narrow``.

    Deliberately conservative: only a wildcard, an exact match, or an
    explicit ``prefix*`` glob counts as coverage. Anything cleverer risks
    claiming a shadow that does not exist.
    """
    if _wildcard(broad):
        return True
    if narrow is None:
        return False
    broad_s = str(broad).strip().strip("\"'")
    narrow_s = str(narrow).strip().strip("\"'")
    if broad_s == narrow_s:
        return True
    if broad_s.endswith("*"):
        return narrow_s.startswith(broad_s[:-1])
    return False


#: Claude Code's documented rule evaluation order.
#:
#: Source: https://code.claude.com/docs/en/permissions
#:   "Rules are evaluated in order: deny, then ask, then allow. The first match
#:    in that order determines the outcome, and rule specificity doesn't change
#:    the order."
#:
#: Two consequences this module previously modelled the wrong way round:
#:
#: * Specificity is irrelevant. A broad ``Bash(aws *)`` deny blocks a call that
#:   also matches a narrower ``Bash(aws s3 ls)`` allow — "a deny rule can't
#:   carry allowlist exceptions".
#: * Scope is irrelevant. "If a tool is denied at any level, no other level can
#:   allow it", and "a user-level deny blocks a project-level allow, because
#:   deny rules from any scope are evaluated before allow rules".
DECISION_PRECEDENCE = ("deny", "ask", "allow")


def _broadest(rules):
    """The rule in ``rules`` that decides the widest set of calls.

    A wildcard argument covers everything, so it wins; otherwise fall back to
    the shortest argument, which is the most general prefix. Ties break on
    (path, entry) so the choice is stable across runs.
    """
    def sort_key(rule):
        argument = rule.get("argument")
        return (
            0 if _wildcard(argument) else 1,
            len(str(argument or "")),
            str(rule.get("path") or ""),
            str(rule.get("entry") or ""),
        )

    return min(rules, key=sort_key)


def resolve_effective_rules(records):
    """Return the effective rule per tool, per the documented evaluation order.

    Maps a lowercased tool name to ``{"decision", "rule", "overridden"}``, where
    ``rule`` is the record that decides the outcome and ``overridden`` lists the
    records that can never apply because a higher-precedence tier matched first.

    Scope depth is deliberately NOT a parameter. The documentation is explicit
    that a deny at any level beats an allow at any other, so resolving by scope
    would model a precedence Claude Code does not implement.

    This answers "which tier decides this tool", not "what happens to one exact
    command": the argument patterns are matched by
    :func:`argument_covers`, which is conservative by design.
    """
    by_tool = {}
    for record in records or []:
        tool = str(record.get("tool") or "").strip().lower()
        if not tool or record.get("decision") not in DECISION_PRECEDENCE:
            continue
        by_tool.setdefault(tool, []).append(record)

    effective = {}
    for tool, rules in by_tool.items():
        tiers = {
            decision: [r for r in rules if r["decision"] == decision]
            for decision in DECISION_PRECEDENCE
        }
        for decision in DECISION_PRECEDENCE:
            if not tiers[decision]:
                continue
            lower = [
                rule
                for later in DECISION_PRECEDENCE[DECISION_PRECEDENCE.index(decision) + 1:]
                for rule in tiers[later]
            ]
            effective[tool] = {
                "decision": decision,
                "rule": _broadest(tiers[decision]),
                "overridden": sorted(
                    lower, key=lambda r: (str(r.get("path") or ""), str(r.get("entry") or ""))
                ),
            }
            break
    return effective


def deny_is_effective(records, deny):
    """True when ``deny`` decides its tool — which, per the docs, is always.

    Kept as a named predicate rather than inlined ``True`` so the claim is
    greppable and carries its citation: nothing an allow rule can say, at any
    scope or any specificity, prevents a matching deny from blocking the call.
    """
    tool = str(deny.get("tool") or "").strip().lower()
    resolved = resolve_effective_rules(records).get(tool)
    return bool(resolved) and resolved["decision"] == "deny"


def ineffective_allows(records):
    """Return ``(allow_record, deny_record)`` pairs where the ALLOW cannot apply.

    The inverse of what :func:`shadowed_denials` used to claim. An allow whose
    tool also carries a deny is dead configuration: the deny is evaluated first
    and its match ends the decision, so the allow widens nothing.
    """
    denies = [r for r in records if r.get("decision") == "deny" and r.get("tool")]
    pairs = []
    for allow in sorted(
        (r for r in records if r.get("decision") == "allow" and r.get("tool")),
        key=lambda r: (str(r.get("path") or ""), str(r.get("entry") or "")),
    ):
        for deny in sorted(denies, key=lambda r: (str(r.get("path") or ""), str(r.get("entry") or ""))):
            if deny["tool"].lower() != allow["tool"].lower():
                continue
            if argument_covers(deny["argument"], allow["argument"]):
                pairs.append((allow, deny))
                break
    return pairs


def shadowed_denials(records):
    """Return ``(deny_record, allow_record)`` pairs whose arguments overlap.

    NOTE: an allow never "wins" over a deny. This function used to be
    documented that way and the finding built on it was inverted. Per
    :data:`DECISION_PRECEDENCE`, deny is evaluated first and a matching deny
    ends the decision at any scope and any specificity, so the overlap this
    reports is a sign the ALLOW is dead configuration — see
    :func:`ineffective_allows`, which returns the pair the right way round.

    Kept because the overlap itself is still worth surfacing: two rules that
    contradict each other are a maintenance problem even when the outcome is
    unambiguous. The severity it carries is decided by the caller.
    """
    allows = [r for r in records if r["decision"] == "allow" and r["tool"]]
    pairs = []
    for deny in sorted(
        (r for r in records if r["decision"] == "deny" and r["tool"]),
        key=lambda r: (r["path"], r["entry"]),
    ):
        for allow in sorted(allows, key=lambda r: (r["path"], r["entry"])):
            if allow["tool"].lower() != deny["tool"].lower():
                continue
            if argument_covers(allow["argument"], deny["argument"]):
                pairs.append((deny, allow))
                break
    return pairs


def writes_outside_root(record):
    """True when a write-capable grant targets a path outside the project."""
    if record["decision"] != "allow":
        return False
    if not record["tool"] or record["tool"].lower() not in WRITE_TOOLS:
        return False
    argument = record.get("argument")
    if argument is None:
        return False
    return bool(_OUTSIDE_ROOT_RE.search(str(argument).strip().strip("\"'")))


def bypass_severity(value):
    """Classify a permission-mode value: critical, medium, or None."""
    lowered = str(value or "").strip().lower().replace("_", "").replace(" ", "")
    if lowered in BYPASS_VALUES or lowered.replace("-", "") in {
        v.replace("-", "") for v in BYPASS_VALUES
    }:
        return "critical"
    if lowered in PERMISSIVE_MODES:
        return "medium"
    return None
