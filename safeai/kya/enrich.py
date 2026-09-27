"""Finding and agent-record normalization for KYA.

Adds the Release 1.3 fields to scan results without changing existing
behaviour: stable fingerprints, finding IDs, confidence labels,
provenance records, remediation defaults, and status classification.
All additions are additive keys — existing consumers of the report dict
are unaffected.
"""

from safeai.kya.fingerprints import fingerprint_finding, normalize_path
from safeai.kya.identity import derive_agent_id
from safeai.kya.util import confidence_label, redact_secrets

# Concise, actionable remediation guidance for the highest-value rules.
# Analyzers that already emit remediation keep their own text.
DEFAULT_REMEDIATION = {
    "PROMPT_INJECTION": "Validate and sanitize all untrusted input before it reaches the prompt; use parameterized prompt templates.",
    "PROMPT_DELIMITER": "Insert explicit delimiters between system instructions and user-controlled content.",
    "PROMPT_SYSTEM_LEAK": "Avoid embedding sensitive system prompt content where user input can expose it.",
    "PROMPT_ROLE_OVERRIDE": "Reject or escape role-override phrases in user-controlled prompt content.",
    "DATA_LEAKAGE": "Remove the hardcoded secret, rotate it, and load credentials from a secure secret store.",
    "CAP_shell": "Remove shell execution or constrain it behind strict allowlists and human approval.",
    "CAP_subprocess_shell": "Avoid shell=True; pass argument arrays and validate every interpolated value.",
    "CAP_code_exec": "Eliminate dynamic exec/eval on agent-controlled input or sandbox it strictly.",
    "CAP_AUTONOMY": "Bound autonomous loops with iteration limits, timeouts, and human-in-the-loop checkpoints.",
}

_ANALYZER_BY_RULE_PREFIX = {
    "CAP_": "capability",
    "PROMPT_FILE_": "prompt_file",
    "PROMPT_": "prompt",
    "DATA_LEAKAGE": "data_leakage",
    "ENV_DEP_": "env_dependency",
    "DEP_": "env_dependency",
    "IAC_": "iac",
    "MCP_": "mcp",
    "SKILL_": "skill",
    "TOOL_DEF_": "tool_def",
    "MODEL_CONFIG_": "model_config",
    "WORKFLOW_": "workflow",
}


def _analyzer_for_rule(rule_id):
    rid = str(rule_id or "")
    for prefix, analyzer in _ANALYZER_BY_RULE_PREFIX.items():
        if rid.startswith(prefix):
            return analyzer
    return "unknown"


# Analyzers whose evidence is a human-authored declaration (config files,
# permission grants, tool definitions) rather than inferred code behavior.
# Findings from these analyzers carry provenance_class "declared" when
# they are structured (non-heuristic); everything else structured is
# "detected", regex-fallback evidence is "inferred", and evidence-less
# findings are "unknown" — never overstated.
_DECLARED_ANALYZERS = frozenset({
    "mcp",
    "model_config",
    "claude_code",
    "prompt_file",
    "skill",
    "tool_def",
    "workflow",
})

#: Gateability vocabulary: Lane-A deterministic gates may only consume
#: "deterministic" findings; "review-only" findings (inferred or unknown
#: provenance) can raise Lane-B review events but never fail a gate alone.
GATEABILITY_DETERMINISTIC = "deterministic"
GATEABILITY_REVIEW_ONLY = "review-only"

PROVENANCE_CLASSES = ("declared", "detected", "inferred", "unknown",
                      "repo-iac-observed")
GATEABILITY_VALUES = (GATEABILITY_DETERMINISTIC, GATEABILITY_REVIEW_ONLY)


def provenance_class_for(finding, analyzer, heuristic):
    """Return the field-level provenance class for a normalized finding."""
    evidence = finding.get("evidence") or finding.get("message")
    if not evidence and not finding.get("file"):
        return "unknown"
    if heuristic:
        return "inferred"
    if analyzer in _DECLARED_ANALYZERS:
        return "declared"
    return "detected"


def gateability_for(finding, provenance_class):
    """Return the gateability for a normalized finding.

    Heuristic or unknown-provenance findings are review-only: no heuristic
    may fail a Lane-A deterministic gate on its own. Repository-IaC
    evidence is review-only by construction (ADR-0008): grants observed
    in IaC can inform human review but never fail a gate.
    """
    if provenance_class in ("inferred", "unknown", "repo-iac-observed"):
        return GATEABILITY_REVIEW_ONLY
    return GATEABILITY_DETERMINISTIC


def normalize_findings(findings):
    """Normalize findings in place: fingerprint, IDs, confidence, provenance.

    Returns the same list for chaining. Existing keys are never removed;
    only missing KYA fields are filled in.
    """
    for finding in findings:
        fingerprint_finding(finding)
        rule_id = finding.get("rule_id", "UNKNOWN")

        finding["confidence_label"] = confidence_label(finding.get("confidence"))
        finding.setdefault("status", "new")

        if not finding.get("remediation"):
            finding["remediation"] = DEFAULT_REMEDIATION.get(
                rule_id,
                "Review the flagged configuration and apply least-privilege constraints.",
            )

        if not finding.get("provenance"):
            heuristic = bool(finding.get("regex_fallback")) or finding.get("source") == "regex"
            analyzer = _analyzer_for_rule(rule_id)
            finding["provenance"] = {
                "analyzer": analyzer,
                "heuristic": heuristic,
                "evidence": [redact_secrets(str(finding.get("evidence") or finding.get("message") or ""))],
            }
        else:
            heuristic = bool(finding["provenance"].get("heuristic"))
            analyzer = finding["provenance"].get("analyzer") or _analyzer_for_rule(rule_id)

        # Field-level provenance class + gateability (v2.4 evidence
        # hardening). Custom analyzers may pre-set these; we never
        # overwrite an explicit value.
        finding.setdefault(
            "provenance_class",
            provenance_class_for(finding, analyzer, heuristic),
        )
        finding.setdefault(
            "gateability",
            gateability_for(finding, finding["provenance_class"]),
        )

        # Evidence persisted to manifests/registry is always redacted.
        if finding.get("evidence"):
            finding["evidence"] = redact_secrets(str(finding["evidence"]))

        finding["file"] = normalize_path(finding.get("file"))
    return findings


def _locations_for_model(model, project_root=None):
    path = normalize_path(model.get("file"))
    line = model.get("data", {}).get("line") or model.get("line") or 0
    location = {"path": path, "line_start": int(line or 0), "line_end": int(line or 0)}
    return [location] if path else []


def build_agent_records(report, project_id, first_seen=None):
    """Build KYA agent records from unified parser models in a report.

    Agent identity is deterministic (project + framework + name + primary
    path + type). ``first_seen`` is supplied by the registry when the
    agent was observed before; new agents use the scan timestamp.
    """
    records = {}
    models = report.get("unified_models") or []

    for model in models:
        # unified_models shape: {file, frameworks, framework_confidence,
        # discovery_methods, artifacts: {agents, workflows, tools, ...},
        # capabilities}
        artifacts = model.get("artifacts") or {}
        data = {
            "agents": artifacts.get("agents") or [],
            "workflows": artifacts.get("workflows") or [],
            "tools": artifacts.get("tools") or [],
            "capabilities": model.get("capabilities") or [],
        }
        frameworks = model.get("frameworks") or ([model["framework"]] if model.get("framework") else ["unknown"])
        framework = frameworks[0] if frameworks else "unknown"
        conf_map = model.get("framework_confidence") or {}
        parser_confidence = max(conf_map.values()) if conf_map else model.get("parser_confidence")
        methods = model.get("discovery_methods") or []
        discovery = "+".join(methods) if methods else "regex"

        named = []
        for kind, agent_type in (("agents", "agent"), ("workflows", "workflow")):
            for item in data.get(kind) or []:
                if isinstance(item, dict):
                    named.append((item.get("name") or item.get("id"), agent_type, item))
                else:
                    named.append((str(item), agent_type, {"name": str(item)}))

        if not named:
            named = [(None, "unknown", {})]

        for name, agent_type, item in named:
            path = normalize_path(model.get("file"))
            agent_id = derive_agent_id(project_id, framework, name, path, agent_type)
            record = records.get(agent_id)
            if record is None:
                record = {
                    "agent_id": agent_id,
                    "name": name or f"{framework}-{agent_type or 'entity'}",
                    "agent_type": agent_type,
                    "framework": framework,
                    "source_locations": [],
                    "first_seen": first_seen,
                    "capabilities": [],
                    "tools": [],
                    "resources": [],
                    "mcp_assets": [],
                    "autonomy_signals": [],
                    "governance_evidence": [],
                    "authority_evidence": [],
                    "confidence": confidence_label(
                        item.get("confidence", parser_confidence),
                        default="low" if "regex" in str(discovery) else "medium",
                    ),
                    "provenance": [{
                        "framework": framework,
                        "discovery_method": discovery,
                        "note": "detected in source/configuration (static evidence)",
                    }],
                }
                records[agent_id] = record

            for loc in _locations_for_model(model):
                if loc not in record["source_locations"]:
                    record["source_locations"].append(loc)

            for cap in data.get("capabilities") or []:
                cap_name = cap.get("name") if isinstance(cap, dict) else str(cap)
                if cap_name and cap_name not in [c.get("name") for c in record["capabilities"]]:
                    record["capabilities"].append({
                        "name": cap_name,
                        "category": cap.get("category", "Capability") if isinstance(cap, dict) else "Capability",
                    })
            for tool in data.get("tools") or []:
                tool_name = tool.get("name") if isinstance(tool, dict) else str(tool)
                if tool_name and tool_name not in record["tools"]:
                    record["tools"].append(tool_name)

    # Attach MCP assets to the project-level pseudo records via evidence;
    # assets without a clear owning agent are surfaced at manifest level.
    for record in records.values():
        if not record["capabilities"]:
            for cap in report.get("normalized_capabilities") or []:
                frameworks = cap.get("source_frameworks") or []
                if record["framework"] in frameworks:
                    entry = {"name": cap.get("name"), "category": cap.get("category", "Capability")}
                    if entry not in record["capabilities"]:
                        record["capabilities"].append(entry)

    return sorted(records.values(), key=lambda r: r["agent_id"])
