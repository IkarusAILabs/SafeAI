"""Claude Code framework adapter.

Detects Claude Code projects via ``CLAUDE.md``, ``.claude/`` configuration,
and ``claude-code`` references in source, and extracts the authority those
files actually confer.

Since v1.4 this adapter is a thin coordinator: settings discovery lives in
``settings.py``, the permission model in ``permissions.py``, and slash
commands and subagents in ``commands.py``. Every extracted capability
carries a tool identity and an access mode, so a change can be attributed
to a named tool rather than to the project as a whole.

Scope boundary: only files inside the scanned repository are read. This
module never opens a file itself — it receives content from the scanner.
"""

import json
import re

import yaml

from safeai.analysis.capabilities import make_capability
from safeai.analysis.tool_identity import make_tool_identity
from safeai.frameworks import register_parser
from safeai.frameworks.claude_code import commands as cc_commands
from safeai.frameworks.claude_code import permissions as cc_permissions
from safeai.frameworks.claude_code import settings as cc_settings


def _rel(path):
    normalized = str(path).replace("\\", "/")
    marker = "/.claude/"
    if marker in normalized:
        return ".claude/" + normalized.split(marker, 1)[1]
    basename = normalized.rsplit("/", 1)[-1]
    return basename


@register_parser
class ClaudeCodeParser:
    name = "claude_code"

    def detect(self, path, content, scan_ctx=None):
        fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if fname == "claude.md":
            return True
        if ".claude/" in path.replace("\\", "/"):
            return True
        return bool("claude-code" in content.lower() or "claude_code" in content.lower())

    def parse(self, path, content, scan_ctx=None):
        result = {
            "framework": "claude_code",
            "agents": [],
            "tools": [],
            "models": [],
            "mcp_assets": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "filename" if path.lower().endswith("claude.md") else "content",
            "parser_confidence": 0.82,
            "detection_evidence": [],
        }

        fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        result["detection_evidence"].append(fname)
        rel = _rel(path)

        if rel.startswith(cc_commands.COMMANDS_PREFIX) and rel.endswith(".md"):
            self._parse_slash_command(rel, content, result)
        elif rel.startswith(cc_commands.AGENTS_PREFIX) and rel.endswith((".md", ".yaml", ".yml")):
            self._parse_subagent(rel, content, result)
        elif rel.endswith(".json") and cc_settings.is_claude_config(rel):
            self._parse_settings_file(rel, content, result)
        elif fname == "claude.md":
            self._parse_claude_md(content, result)
        elif path.endswith((".yaml", ".yml")):
            self._parse_yaml_config(content, result)
        elif path.endswith(".json"):
            self._parse_json_config(content, result)
        elif path.endswith(".py"):
            self._parse_python(content, result)

        result["capabilities"].sort(key=lambda c: (str(c.get("name")), str(c.get("evidence"))))
        result["tools"] = sorted(set(result["tools"]))
        return result

    # --- settings and permissions ---------------------------------------

    def _parse_settings_file(self, rel, content, result):
        """Extract permission grants, MCP servers, and hooks."""
        data, error = cc_settings.loads_lenient(content)
        if error is not None:
            # The analyzer raises the unparseable-configuration finding; the
            # parser simply contributes no unfounded capability.
            result["parser_confidence"] = 0.4
            return
        data = data if isinstance(data, dict) else {}

        env_names = cc_settings.extract_env_names(data)
        for decision, entry in cc_settings.extract_permission_entries(data):
            line = cc_settings.line_of(content, entry)
            record = cc_permissions.classify_entry(entry, decision, rel, line)
            if record["tool"]:
                result["tools"].append(record["tool"])
            result["capabilities"].extend(
                cc_permissions.capabilities_for(record, credentials=env_names)
            )

        for server in cc_settings.extract_mcp_servers(data):
            result["mcp_assets"].append({"type": "server", "name": server, "source": rel})
            result["capabilities"].append(make_capability(
                "mcp", "MCP", "claude_code",
                f"claude code MCP server: {server}",
                confidence=0.85, source="config",
                tool_identity=make_tool_identity("mcp_server", server, "claude_code", source_path=rel),
                access_mode="mutate",
                line=cc_settings.line_of(content, server),
            ))

        for event, command in cc_settings.extract_hooks(data):
            identity = make_tool_identity("tool", f"hook:{event}", "claude_code", source_path=rel)
            result["capabilities"].append(make_capability(
                "shell", "Shell", "claude_code",
                f"claude code hook on {event}",
                confidence=0.9, source="config",
                tool_identity=identity,
                access_mode="execute",
                line=cc_settings.line_of(content, command),
            ))

    # --- slash commands ---------------------------------------------------

    def _parse_slash_command(self, rel, content, result):
        """A stored instruction that runs with the agent's full authority."""
        command = cc_commands.parse_command(rel, content)
        identity = make_tool_identity(
            "tool", f"command:{command['name']}", "claude_code", source_path=rel
        )
        result["tools"].append(f"/{command['name']}")

        for entry in command["allowed_tools"]:
            record = cc_permissions.classify_entry(entry, "allow", rel, 1)
            result["capabilities"].extend(cc_permissions.capabilities_for(
                record, evidence_prefix=f"/{command['name']} allowed-tools"
            ))

        for shell in command["shell_invocations"]:
            result["capabilities"].append(make_capability(
                "shell", "Shell", "claude_code",
                f"/{command['name']} shell invocation",
                confidence=0.9, source="config",
                tool_identity=identity,
                access_mode="execute",
                line=shell["line"],
            ))

        # $ARGUMENTS is caller-supplied text. Recording it as an untrusted
        # input capability on the same tool identity is what lets the
        # escalation layer combine it with shell authority.
        if command["argument_uses"]:
            result["capabilities"].append(make_capability(
                "untrusted_input", "Untrusted Input", "claude_code",
                f"/{command['name']} interpolates caller arguments",
                confidence=0.9, source="config",
                tool_identity=identity,
                access_mode="read",
                line=command["argument_uses"][0]["line"],
            ))

        if command["file_references"]:
            result["capabilities"].append(make_capability(
                "filesystem", "Filesystem", "claude_code",
                f"/{command['name']} inlines referenced files",
                confidence=0.8, source="config",
                tool_identity=identity,
                access_mode="read",
                line=command["file_references"][0]["line"],
            ))

    def _parse_subagent(self, rel, content, result):
        subagent = cc_commands.parse_subagent(rel, content)
        result["agents"].append(subagent["name"])
        identity = make_tool_identity(
            "agent", subagent["name"], "claude_code", source_path=rel
        )
        for entry in subagent["tools"]:
            record = cc_permissions.classify_entry(entry, "allow", rel, 1)
            record["identity"] = identity
            result["capabilities"].extend(cc_permissions.capabilities_for(
                record, evidence_prefix=f"subagent {subagent['name']} tool"
            ))
            if record["tool"]:
                result["tools"].append(record["tool"])
        if subagent["tools"]:
            result["capabilities"].append(make_capability(
                "delegation", "Delegation", "claude_code",
                f"subagent {subagent['name']} delegation target",
                confidence=0.85, source="config",
                tool_identity=identity,
                access_mode="execute",
                line=1,
            ))

    # --- legacy surfaces (unchanged behaviour) ---------------------------

    def _parse_claude_md(self, content, result):
        """Extract agent, tool, and model references from CLAUDE.md."""
        for m in re.finditer(r"@([a-z][a-z0-9_-]+)", content):
            result["tools"].append(m.group(1))
        for m in re.finditer(r"tool:\s*([a-z][a-z0-9_-]+)", content, re.IGNORECASE):
            result["tools"].append(m.group(1))

        for m in re.finditer(r"claude-(sonnet|opus|haiku)-[\d-]+", content, re.IGNORECASE):
            result["models"].append(m.group(0))

        for m in re.finditer(r"agent:\s*(.+)", content, re.IGNORECASE):
            result["agents"].append(m.group(1).strip())

        if re.search(r"\bmcp\b", content, re.IGNORECASE):
            result["mcp_assets"].append({"type": "reference", "source": "claude.md"})

        low = content.lower()
        if re.search(r"shell|exec|command|subprocess", low):
            result["capabilities"].append(
                make_capability("shell", "Shell", "claude_code", "CLAUDE.md shell reference", confidence=0.75, source="config")
            )
        if re.search(r"file|filesystem|read.*file|write.*file", low):
            result["capabilities"].append(
                make_capability("filesystem", "Filesystem", "claude_code", "CLAUDE.md file reference", confidence=0.75, source="config")
            )
        if re.search(r"mcp|model.context.protocol", low):
            result["capabilities"].append(
                make_capability("mcp", "MCP", "claude_code", "CLAUDE.md MCP reference", confidence=0.75, source="config")
            )

    def _parse_yaml_config(self, content, result):
        try:
            data = yaml.safe_load(content)
        except Exception:
            return
        if isinstance(data, dict):
            if "model" in data:
                result["models"].append(str(data["model"]))
            if "tools" in data:
                tools = data["tools"]
                if isinstance(tools, list):
                    result["tools"].extend(str(t) for t in tools)
            if "agents" in data:
                agents = data["agents"]
                if isinstance(agents, list):
                    result["agents"].extend(str(a) for a in agents)

    def _parse_json_config(self, content, result):
        try:
            data = json.loads(content)
        except Exception:
            return
        if isinstance(data, dict):
            if "model" in data:
                result["models"].append(str(data["model"]))
            if "tools" in data:
                tools = data["tools"]
                if isinstance(tools, list):
                    result["tools"].extend(str(t) for t in tools)

    def _parse_python(self, content, result):
        for m in re.finditer(r"claude-(sonnet|opus|haiku)-[\d-]+", content, re.IGNORECASE):
            result["models"].append(m.group(0))
        if re.search(r"\bmcp\b", content, re.IGNORECASE):
            result["mcp_assets"].append({"type": "reference", "source": "python"})
