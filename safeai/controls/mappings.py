"""Control mappings — maps SafeAI rule IDs to control framework entries.

Provides a structured mapping layer between SafeAI's internal rule taxonomy
and external control frameworks (OWASP LLM, OWASP Agentic, NIST AI RMF).

This is a taxonomy-only layer — never a compliance or coverage claim.
"""

from safeai.controls.catalogs import ALL_CATALOGS, FRAMEWORKS

# Rule-to-control mapping table.
# Each entry maps a SafeAI rule_id to a list of (framework, control_id) pairs.
RULE_MAPPINGS = {
    # Prompt injection
    "PROMPT_INJECTION": [
        ("owasp_llm", "LLM01"),
        ("owasp_agentic", "AGENTIC01"),
        ("nist_ai_rmf", "GOVERN_1"),
    ],
    # Capability detection
    "CAP_shell": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_code_exec": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "CAP_http": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_filesystem": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_db": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_docker": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "CAP_kubernetes": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "CAP_redis": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_s3": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "CAP_slack": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC06"),
    ],
    "CAP_ms_teams": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC06"),
    ],
    "CAP_jira": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC06"),
    ],
    "CAP_browser": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_browser_playwright": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_browser_selenium": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_browser_use": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_gcp": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    # Data leakage
    "DATA_private_key": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "DATA_aws_key": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "DATA_connection_string": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "DATA_jwt": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    # Governance signals
    "GOV_TIMEOUT_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_RETRY_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_APPROVAL_MISSING": [
        ("owasp_agentic", "AGENTIC05"),
        ("nist_ai_rmf", "GOVERN_3"),
    ],
    "GOV_AUDIT_MISSING": [
        ("owasp_agentic", "AGENTIC10"),
        ("nist_ai_rmf", "GOVERN_2"),
    ],
    "GOV_RATE_LIMIT_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_CIRCUIT_BREAKER_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_BACKPRESSURE_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_HEALTH_CHECK_MISSING": [
        ("owasp_agentic", "AGENTIC10"),
        ("nist_ai_rmf", "GOVERN_2"),
    ],
    "GOV_MAX_ITERATIONS_MISSING": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_RECURSION_GUARD_MISSING": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    # Environment dependencies
    "ENV_DEP_INVENTORY": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    # Component analysis
    "SKILL_RISKY_TOOL": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "SKILL_IMPLICIT_DEPENDENCY": [
        ("owasp_llm", "LLM03"),
        ("owasp_agentic", "AGENTIC09"),
    ],
    "TOOL_ORPHAN_DECLARED": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC09"),
    ],
    "TOOL_ORPHAN_IMPLEMENTED": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC09"),
    ],
    # MCP analysis
    "MCP_UNTRUSTED_CONFIG": [
        ("owasp_llm", "LLM03"),
        ("owasp_agentic", "AGENTIC06"),
    ],
    # Escalation detections
    "ESC_NEW_CAPABILITY": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "ESC_SEVERITY_INCREASE": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
        ("nist_ai_rmf", "MEASURE_2"),
    ],
    "ESC_RECURRING_RISK": [
        ("owasp_llm", "LLM09"),
        ("nist_ai_rmf", "MANAGE_2"),
    ],
    # Data-flow analysis
    "DATAFLOW_prompt": [
        ("owasp_llm", "LLM01"),
        ("owasp_agentic", "AGENTIC01"),
    ],
    "DATAFLOW_tool_call": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "DATAFLOW_shell": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
        ("nist_ai_rmf", "MAP_5"),
    ],
    "DATAFLOW_file_write": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "DATAFLOW_http_request": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "DATAFLOW_database": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
}


def map_rule_to_controls(rule_id, severity=None):
    """Map a SafeAI rule ID to its control framework entries.

    Args:
        rule_id: The SafeAI rule ID (e.g., "PROMPT_INJECTION")
        severity: Optional severity for context (not used in mapping)

    Returns:
        List of dicts with keys: framework, control_id, family, title, description
    """
    mappings = RULE_MAPPINGS.get(rule_id, [])
    results = []
    seen = set()

    for framework, control_id in mappings:
        key = (framework, control_id)
        if key in seen:
            continue
        seen.add(key)

        control = ALL_CATALOGS.get(control_id)
        if control:
            results.append({
                "framework": framework,
                "control_id": control_id,
                "family": control["family"],
                "title": control["title"],
                "description": control["description"],
            })

    return results


def map_findings_to_controls(findings):
    """Enrich a list of findings with control mapping metadata.

    Adds a ``control_mappings`` key to each finding with the mapped controls.
    """
    for finding in findings:
        rule_id = finding.get("rule_id", "")
        severity = finding.get("severity")
        finding["control_mappings"] = map_rule_to_controls(rule_id, severity)

    return findings


def get_framework_summary():
    """Get a summary of available control frameworks."""
    return [
        {
            "id": fid,
            "name": f["name"],
            "version": f["version"],
            "control_count": len(f["controls"]),
        }
        for fid, f in FRAMEWORKS.items()
    ]


def rule_coverage_summary():
    """Report control-mapping coverage per rule category.

    Groups every built-in rule (from ``rules/base_rules.yaml``) by its
    category prefix -- the token before the first underscore, e.g. ``CAP``,
    ``GOV``, ``DATAFLOW`` -- and reports how many rules in that category have
    a ``RULE_MAPPINGS`` entry and how many do not.

    This is informational only: it is not a compliance or coverage claim,
    and a "mapped" rule is not weighted by how often it actually fires.

    Returns
    -------
    list[dict]
        One entry per category, sorted by category name, each with
        ``category``, ``mapped_count``, ``unmapped_count``, and
        ``unmapped_rules`` (sorted rule IDs).
    """
    from safeai.rules.loader import load_rules

    rules, _metadata = load_rules()
    rule_ids = {r["id"] for r in rules if isinstance(r, dict) and "id" in r}
    mapped_ids = set(RULE_MAPPINGS)

    by_category = {}
    for rule_id in rule_ids:
        category = rule_id.split("_", 1)[0]
        entry = by_category.setdefault(category, {"mapped": 0, "unmapped": []})
        if rule_id in mapped_ids:
            entry["mapped"] += 1
        else:
            entry["unmapped"].append(rule_id)

    return [
        {
            "category": category,
            "mapped_count": data["mapped"],
            "unmapped_count": len(data["unmapped"]),
            "unmapped_rules": sorted(data["unmapped"]),
        }
        for category, data in sorted(by_category.items())
    ]
