"""Tool ↔ Implementation Mapping (CE 1.5 completion).

Correlates declared tools (from MCP configs, skill definitions, and
workflow nodes) with their implementations (tool definitions found via
static analysis).  Surfaces two orphan states:

- **Declared but unimplemented** — a tool is referenced in configuration
  but no corresponding implementation was found in the scanned codebase.
- **Implemented but undeclared** — a tool implementation exists but is
  not referenced by any declared configuration.

Both states are informational; they help reviewers understand the gap
between what an agent *says* it uses and what the code actually provides.

The unattributed bucket (capabilities SafeAI could not tie to a tool) is
not a tool, so it is never reported as an orphan.
"""

from safeai.analysis.tool_identity import UNATTRIBUTED_KEY


def _tool_refs_from_surface(tool_surface):
    """Extract tool references with provenance from the per-tool capability surface."""
    refs = {}
    for entry in (tool_surface or []):
        key = entry.get("tool_key")
        if not key:
            continue
        tool = entry.get("tool") or {}
        # Get provenance from the first evidence item if available
        path = None
        line = None
        for cap in entry.get("capabilities") or []:
            for ev in cap.get("evidence") or []:
                if ev.get("path"):
                    path = ev["path"]
                    line = ev.get("line")
                    break
            if path:
                break
        refs[key] = {
            "tool_key": key,
            "kind": tool.get("kind", "tool"),
            "name": tool.get("name", ""),
            "source": "tool_surface",
            "path": path,
            "line": line,
        }
    return refs


def _tool_refs_from_components(components):
    """Extract tool references with provenance from component definitions."""
    refs = {}
    for comp in (components or []):
        if comp.get("type") != "tool":
            continue
        name = comp.get("name") or ""
        if not name:
            continue
        key = f"tool:{name}"
        refs[key] = {
            "tool_key": key,
            "kind": "tool",
            "name": name,
            "source": "component",
            "path": comp.get("path") or comp.get("file"),
            "line": comp.get("line"),
        }
    return refs


def _tool_refs_from_skills(components):
    """Extract tool references with provenance from skill components."""
    refs = {}
    for comp in (components or []):
        if comp.get("type") != "skill":
            continue
        data = comp.get("data") or {}
        skill_path = comp.get("path") or comp.get("file")
        skill_line = comp.get("line")
        for tool_ref in data.get("tools") or []:
            if isinstance(tool_ref, str):
                name = tool_ref
            elif isinstance(tool_ref, dict):
                name = tool_ref.get("name") or tool_ref.get("tool")
            else:
                continue
            if not name:
                continue
            key = f"tool:{name}"
            if key not in refs:
                refs[key] = {
                    "tool_key": key,
                    "kind": "tool",
                    "name": name,
                    "source": "skill",
                    "path": skill_path,
                    "line": skill_line,
                }
    return refs


def _tool_refs_from_workflows(components):
    """Extract tool references with provenance from workflow components."""
    refs = {}
    for comp in (components or []):
        if comp.get("type") != "workflow":
            continue
        data = comp.get("data") or {}
        wf_path = comp.get("path") or comp.get("file")
        wf_line = comp.get("line")
        for step in data.get("steps") or []:
            tool_name = step.get("tool") or step.get("tool_name")
            if not tool_name:
                continue
            key = f"tool:{tool_name}"
            if key not in refs:
                refs[key] = {
                    "tool_key": key,
                    "kind": "tool",
                    "name": tool_name,
                    "source": "workflow",
                    "path": wf_path,
                    "line": wf_line,
                }
    return refs


def map_tool_implementations(report):
    """Map declared tools to implementations and surface orphan states.

    Returns ``(findings, summary)`` where findings is a list of
    ``TOOL_ORPHAN_*`` finding dicts and summary is a dict with counts
    and deterministic mappings.
    """
    tool_surface = report.get("tool_surface") or []
    components = report.get("components") or []

    # Tool references with provenance from each source
    surface_refs = _tool_refs_from_surface(tool_surface)
    component_refs = _tool_refs_from_components(components)
    skill_refs = _tool_refs_from_skills(components)
    workflow_refs = _tool_refs_from_workflows(components)

    # All declared tool references (skills + workflows)
    declared_refs = {}
    declared_refs.update(skill_refs)
    declared_refs.update(workflow_refs)

    # Implementation refs = tools found in code (surface + component defs)
    implementation_refs = {}
    implementation_refs.update(surface_refs)
    implementation_refs.update(component_refs)

    # MCP server keys (special handling)
    mcp_keys = {k for k in surface_refs if k.startswith("mcp_server:")}

    findings = []
    mappings = []

    # Build deterministic mapping for all known tool keys
    all_keys = sorted(set(declared_refs.keys()) | set(implementation_refs.keys()))

    for key in all_keys:
        if key.startswith(("mcp:", "mcp_server:")) or key == UNATTRIBUTED_KEY:
            continue

        decl = declared_refs.get(key)
        impl = implementation_refs.get(key)

        if decl and impl:
            # Matched: both declared and implemented
            mappings.append({
                "tool_key": key,
                "declarations": [_provenance_dict(decl)],
                "implementations": [_provenance_dict(impl)],
                "status": "matched",
            })
        elif decl:
            # Declared but not implemented
            mappings.append({
                "tool_key": key,
                "declarations": [_provenance_dict(decl)],
                "implementations": [],
                "status": "orphan_declared",
            })
            findings.append({
                "rule_id": "TOOL_ORPHAN_DECLARED",
                "severity": "medium",
                "owasp_llm": "LLM06",
                "risk_category": "Capability",
                "affected_capability": "Tool",
                "message": f"Tool '{key}' is declared in configuration but no implementation found",
                "confidence": 0.7,
                "source": "tool_implementation_mapping",
                "file": decl.get("path") or "",
                "line": decl.get("line") or 0,
                "remediation": (
                    "Ensure the tool implementation exists in the scanned codebase, "
                    "or remove the declaration if the tool is no longer needed."
                ),
            })
        elif impl:
            # Implemented but not declared
            mappings.append({
                "tool_key": key,
                "declarations": [],
                "implementations": [_provenance_dict(impl)],
                "status": "orphan_implemented",
            })
            findings.append({
                "rule_id": "TOOL_ORPHAN_IMPLEMENTED",
                "severity": "low",
                "owasp_llm": "LLM06",
                "risk_category": "Capability",
                "affected_capability": "Tool",
                "message": f"Tool '{key}' is implemented but not declared in any skill, workflow, or MCP configuration",
                "confidence": 0.6,
                "source": "tool_implementation_mapping",
                "file": impl.get("path") or "",
                "line": impl.get("line") or 0,
                "remediation": (
                    "Declare the tool in the relevant skill/workflow configuration, "
                    "or remove the dead implementation if it is no longer used."
                ),
            })

    summary = {
        "declared_tools": len([k for k in all_keys if k in declared_refs]),
        "implemented_tools": len([k for k in all_keys if k in implementation_refs]),
        "mcp_tools": len(mcp_keys),
        "orphaned_declared": sum(1 for f in findings if f["rule_id"] == "TOOL_ORPHAN_DECLARED"),
        "orphaned_implemented": sum(1 for f in findings if f["rule_id"] == "TOOL_ORPHAN_IMPLEMENTED"),
        "mappings": mappings,
    }

    return findings, summary


def _provenance_dict(ref):
    """Create a deterministic provenance dict from a tool reference."""
    return {
        "tool_key": ref.get("tool_key"),
        "kind": ref.get("kind"),
        "name": ref.get("name"),
        "source": ref.get("source"),
        "path": ref.get("path"),
        "line": ref.get("line"),
    }
