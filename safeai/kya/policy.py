"""Minimal, deterministic policy-as-code evaluation (``.safeai/policy.yml``).

Intentionally constrained — this is not OPA/Rego/Cedar. Policies select
on static scan evidence (rule IDs, severities, capabilities, frameworks,
agents, paths, MCP posture) and map to one of four actions:

    allow < warn < require_review < deny

The overall outcome is the highest-precedence action across all matched
policies (``default_action`` when nothing matches). A ``deny`` outcome
never means "the application is unsafe"; a ``pass``/``allow`` outcome
never means "the application is safe or compliant". It is a statement
about *static evidence matched against local policy* only.
"""

import os

import yaml

from safeai.kya.fingerprints import path_glob_matches
from safeai.severity import rank as _severity_rank

DEFAULT_POLICY_PATH = os.path.join(".safeai", "policy.yml")

ACTIONS = ("allow", "warn", "require_review", "deny")
_ACTION_RANK = {action: index for index, action in enumerate(ACTIONS)}

#: Canonical report outcomes (``safeai.kya.contract.POLICY_OUTCOMES``).
#: Policy files keep the action DSL; published decisions use outcome
#: vocabulary so manifests validate against Contract v1. Lane A prints
#: machine verdicts (gates); Lane B prints human questions (mandatory
#: review, never auto-passes).
ACTION_OUTCOME = {
    "allow": "pass",
    "warn": "warn",
    "require_review": "review-required",
    "deny": "block",
}
LANE_OF_ACTION = {
    "allow": "A",
    "warn": "A",
    "require_review": "B",
    "deny": "A",
}

#: Rule families whose *new-or-changed* findings are definition changes
#: (prompts, agent configs, tool/skill/model/workflow definitions,
#: Claude Code permissions). They resolve to at least require_review —
#: never pass — even with zero other matches.
_REVIEW_FLOOR_PREFIXES = (
    "PROMPT_",
    "PROMPT_FILE_",
    "SKILL_",
    "TOOL_DEF_",
    "MODEL_CONFIG_",
    "WORKFLOW_",
    "CC_",
)

#: Finding statuses that count as new-or-changed for the review floor.
_NEWISH_STATUSES = frozenset({"new", "introduced", "reopened", "regressed"})


def lane_of_finding(finding):
    """Return the review-decision lane for a finding: ``"B"`` when its
    gateability is review-only (heuristic or unknown provenance), else
    ``"A"``. Lane B items are questions for a human, never gate verdicts.
    """
    if str(finding.get("gateability", "")).lower() == "review-only":
        return "B"
    return "A"


def _is_review_floor_trigger(finding):
    """True when a finding is a new-or-changed prompt/config definition —
    the review floor applies (outcome at least require_review)."""
    rule_id = str(finding.get("rule_id") or "")
    if not rule_id.startswith(_REVIEW_FLOOR_PREFIXES):
        return False
    return str(finding.get("status", "new")) in _NEWISH_STATUSES

#: Built-in profile names and their bundled YAML files.
_BUILTIN_PROFILES = {
    "developer": "developer.yml",
    "strict-ci": "strict-ci.yml",
    "mcp": "mcp.yml",
    "rag": "rag.yml",
    "production-agent": "production-agent.yml",
}


class PolicyError(Exception):
    """Raised for invalid policy files."""


def load_profile(name):
    """Load a built-in policy profile by name. Returns the profile dict
    (with ``policies`` list) or ``None`` if the name is unknown.

    Built-in profiles are bundled in ``safeai/policy_profiles/`` as YAML
    files. The profile's policies are composable: they extend (not replace)
    the user's ``.safeai/policy.yml`` policies.
    """
    filename = _BUILTIN_PROFILES.get(name)
    if not filename:
        return None
    profile_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy_profiles")
    path = os.path.join(profile_dir, filename)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            document = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"Unable to read profile {name!r}: {exc}") from exc
    if not isinstance(document, dict):
        raise PolicyError(f"Profile {name!r}: document must be a mapping.")
    policies = document.get("policies") or []
    if not isinstance(policies, list):
        raise PolicyError(f"Profile {name!r}: 'policies' must be a list.")
    validated = []
    for index, raw in enumerate(policies, 1):
        if not isinstance(raw, dict):
            raise PolicyError(f"Profile {name!r} policy #{index}: entry must be a mapping.")
        action = str(raw.get("action", "")).lower()
        if action not in _ACTION_RANK:
            raise PolicyError(f"Profile {name!r} policy #{index}: invalid action {action!r}.")
        if not raw.get("id"):
            raise PolicyError(f"Profile {name!r} policy #{index}: missing required 'id'.")
        validated.append({
            "id": str(raw["id"]),
            "when": raw.get("when") or {},
            "action": action,
            "message": raw.get("message") or raw.get("reason") or "",
        })
    return {
        "version": str(document.get("version", "1")),
        "description": document.get("description") or "",
        "default_action": str(document.get("default_action", "warn")).lower(),
        "policies": validated,
    }


def merge_profile(profile, user_policy):
    """Merge a built-in profile into a user policy document.

    Returns a new policy dict with the profile's policies prepended to the
    user's policies. The user's ``default_action`` is preserved. Profile
    policy IDs are prefixed with the profile name to avoid collisions.
    """
    if profile is None:
        return user_policy
    prefix = profile.get("description", "").split(".")[0].lower().replace(" ", "_")[:16] or "profile"
    profile_policies = []
    for pol in profile.get("policies") or []:
        merged = dict(pol)
        merged["id"] = f"{prefix}:{pol['id']}"
        merged["profile"] = True
        profile_policies.append(merged)
    user_policies = user_policy.get("policies") if user_policy else []
    user_authority = (user_policy or {}).get("authority") or {}
    profile_authority = profile.get("authority") or {}
    if not user_authority and isinstance(profile_authority, dict):
        unknown = str(profile_authority.get("unknown") or "").lower()
        if unknown in _ACTION_RANK:
            user_authority = {"unknown": unknown}
    merged_doc = {
        "version": "1",
        "default_action": (user_policy or {}).get("default_action",
profile.get("default_action", "warn")),
        "policies": profile_policies + list(user_policies),
        "authority": user_authority,
    }
    return merged_doc

def default_policy_path(root):
    return os.path.join(root, DEFAULT_POLICY_PATH)


def load_policy(path):
    """Load and validate a policy file. Returns ``None`` when absent."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            document = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"Unable to read policy file {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise PolicyError(f"Policy file {path}: top-level document must be a mapping.")

    default_action = str(document.get("default_action", "warn")).lower()
    if default_action not in _ACTION_RANK:
        raise PolicyError(f"Policy file {path}: invalid default_action {default_action!r}.")

    policies = document.get("policies") or []
    if not isinstance(policies, list):
        raise PolicyError(f"Policy file {path}: 'policies' must be a list.")

    validated = []
    for index, raw in enumerate(policies, 1):
        if not isinstance(raw, dict):
            raise PolicyError(f"Policy #{index}: entry must be a mapping.")
        action = str(raw.get("action", "")).lower()
        if action not in _ACTION_RANK:
            raise PolicyError(f"Policy #{index}: invalid or missing action {action!r}.")
        if not raw.get("id"):
            raise PolicyError(f"Policy #{index}: missing required 'id'.")
        validated.append({
            "id": str(raw["id"]),
            "when": raw.get("when") or {},
            "action": action,
            "message": raw.get("message") or raw.get("reason") or "",
        })

    authority = document.get("authority") or {}
    if not isinstance(authority, dict):
        raise PolicyError(f"Policy file {path}: 'authority' must be a mapping.")
    unknown_action = authority.get("unknown")
    if unknown_action is not None:
        unknown_action = str(unknown_action).lower()
        if unknown_action not in _ACTION_RANK:
            raise PolicyError(
                f"Policy file {path}: 'authority.unknown' must be one of "
                f"{', '.join(ACTIONS)}, got {unknown_action!r}."
            )
    authority_policy = {"unknown": unknown_action} if unknown_action else {}

    return {
        "version": str(document.get("version", "1")),
        "default_action": default_action,
        "policies": validated,
        "authority": authority_policy,
    }


def _finding_capabilities(report, finding):
    """Capabilities relevant to a finding: its own affected capability plus
    all normalized project capabilities (static, project-wide evidence)."""
    caps = set()
    affected = finding.get("affected_capability")
    if affected:
        caps.add(str(affected).lower())
    for cap in report.get("normalized_capabilities") or []:
        if cap.get("name"):
            caps.add(str(cap["name"]).lower())
    return caps


def _matches_when(when, finding, report):
    """Evaluate one policy's ``when`` block against a finding. Returns a
    list of human-readable match reasons (empty when not matched)."""
    reasons = []

    finding_ids = when.get("finding_ids") or when.get("rule_ids") or []
    if finding_ids:
        rid = str(finding.get("rule_id", ""))
        if rid not in [str(x) for x in finding_ids]:
            return []
        reasons.append(f"rule_id={rid}")

    severity = when.get("severity")
    if severity:
        wanted = [str(s).lower() for s in (severity if isinstance(severity, list) else [severity])]
        if str(finding.get("severity", "")).lower() not in wanted:
            return []
        reasons.append(f"severity={finding.get('severity')}")

    min_severity = when.get("min_severity")
    if min_severity:
        if _severity_rank(finding.get("severity")) < _severity_rank(min_severity):
            return []
        reasons.append(f"severity>={min_severity}")

    capabilities_all = when.get("capabilities_all") or []
    capabilities_any = when.get("capabilities_any") or []
    if capabilities_all or capabilities_any:
        caps = _finding_capabilities(report, finding)
        caps |= {str(c.get("category", "")).lower() for c in report.get("normalized_capabilities") or []}
        if capabilities_all and not all(str(c).lower() in caps for c in capabilities_all):
            return []
        if capabilities_any and not any(str(c).lower() in caps for c in capabilities_any):
            return []
        reasons.append("capability-match")

    frameworks = when.get("frameworks") or []
    if frameworks:
        fw = str(finding.get("affected_framework", "")).lower()
        detected = {str(f).lower() for f in report.get("detected_frameworks") or []}
        wanted = {str(f).lower() for f in frameworks}
        if fw not in wanted and not (detected & wanted):
            return []
        reasons.append(f"framework={fw or 'detected'}")

    agent = when.get("agent")
    if agent:
        agent_models = report.get("agent_models") or []
        names = set()
        for model in agent_models:
            for item in (model.get("data", {}).get("agents") or []):
                names.add(str(item.get("name") if isinstance(item, dict) else item).lower())
        if str(agent).lower() not in names:
            return []
        reasons.append(f"agent={agent}")

    path_glob = when.get("path_glob")
    if path_glob:
        finding_path = str(finding.get("file") or "").replace("\\", "/")
        if not path_glob_matches(finding_path, path_glob):
            return []
        reasons.append(f"path={finding_path}")

    mcp = when.get("mcp")
    if mcp:
        assets = report.get("mcp_assets") or []
        matched_asset = None
        for asset in assets:
            if "remote" in mcp:
                is_remote = bool(asset.get("remote")) or str(asset.get("transport", "")).lower() in {"http", "sse", "streamable-http"}
                if is_remote != bool(mcp["remote"]):
                    continue
            auth_req = mcp.get("authentication_evidence")
            if auth_req:
                has_auth = bool(asset.get("authentication") or asset.get("auth") or asset.get("auth_evidence"))
                if auth_req == "absent" and has_auth:
                    continue
                if auth_req == "present" and not has_auth:
                    continue
            matched_asset = asset
            break
        if matched_asset is None:
            return []
        reasons.append("mcp-posture-match")

    return reasons or ["matched"]


def evaluate_policy(policy, report):
    """Evaluate a policy document against a scan report.

    Suppressed findings do not contribute to blocking outcomes but are
    still recorded in match details for auditability. Evaluation order is
    deterministic (file order), and the outcome uses action precedence.

    Returns a decision dict: ``outcome`` (canonical POLICY_OUTCOMES
    vocabulary), ``action`` (winning policy-DSL action), ``lane``
    (``"A"`` verdict or ``"B"`` question), ``lanes`` (match counts per
    lane), ``reasons``, ``matches`` (each carrying its ``lane``).

    New-or-changed prompt/config-definition findings floor the outcome
    at require_review: they print as Lane-B questions, never pass.
    """
    if policy is None:
        return {
            "outcome": "warn",
            "action": "warn",
            "lane": "A",
            "lanes": {"A": 0, "B": 0},
            "reasons": ["No policy file supplied; default posture 'warn'."],
            "matches": [],
        }

    matches = []
    highest = _ACTION_RANK[policy["default_action"]]
    action = policy["default_action"]

    for pol in policy["policies"]:
        matched_findings = []
        for finding in report.get("findings") or []:
            reasons = _matches_when(pol["when"], finding, report)
            if reasons:
                matched_findings.append({
                    "fingerprint": finding.get("fingerprint"),
                    "rule_id": finding.get("rule_id"),
                    "status": finding.get("status", "unknown"),
                    "lane": lane_of_finding(finding),
                    "reasons": reasons,
                })
        if not matched_findings:
            continue

        active = [m for m in matched_findings if m["status"] != "suppressed"]
        match_record = {
            "policy_id": pol["id"],
            "action": pol["action"],
            "lane": LANE_OF_ACTION[pol["action"]],
            "message": pol["message"],
            "matched": matched_findings,
        }
        matches.append(match_record)

        if active and _ACTION_RANK[pol["action"]] > highest:
            highest = _ACTION_RANK[pol["action"]]
            action = pol["action"]

    # Review floor: new-or-changed prompt/config definitions never pass.
    floor_triggered = any(
        _is_review_floor_trigger(f)
        for f in report.get("findings") or []
        if f.get("status") != "suppressed"
    )
    if floor_triggered and highest < _ACTION_RANK["require_review"]:
        highest = _ACTION_RANK["require_review"]
        action = "require_review"

    # Authority UNKNOWN governance (opt-in): organizations decide what
    # unattributable authority means. Default (absent) changes nothing.
    unknown_tools = [
        t.get("tool_key")
        for t in ((report.get("capability_diff") or {}).get("tools") or [])
        if t.get("change_class") == "UNKNOWN"
    ]
    unknown_action = (policy.get("authority") or {}).get("unknown")
    if unknown_action and unknown_tools:
        matches.append({
            "policy_id": "authority:unknown",
            "action": unknown_action,
            "lane": LANE_OF_ACTION[unknown_action],
            "message": (
                f"Tool authority could not be attributed to the baseline "
                f"({len(unknown_tools)} tool(s))."
            ),
            "matched": [{"tool_key": key} for key in sorted(
                str(k) for k in unknown_tools if k)],
        })
        if _ACTION_RANK[unknown_action] > highest:
            highest = _ACTION_RANK[unknown_action]
            action = unknown_action

    outcome = ACTION_OUTCOME[action]
    lanes = {"A": 0, "B": 0}
    for m in matches:
        lanes[m["lane"]] = lanes.get(m["lane"], 0) + 1
    if floor_triggered and not matches:
        lanes["B"] += 1

    reasons = []
    for m in matches:
        if m["policy_id"] == "authority:unknown":
            reasons.append(
                f"Authority UNKNOWN on {len(m['matched'])} tool(s) -> {m['action']}: "
                f"tool authority could not be attributed to the baseline."
            )
        else:
            reasons.append(
                f"Policy '{m['policy_id']}' matched {len(m['matched'])} finding(s) "
                f"-> {m['action']}"
            )
    if floor_triggered:
        reasons.append(
            "New-or-changed prompt/config definition requires human review "
            "(outcome floor: require_review)."
        )
    if not reasons:
        reasons.append(f"No policies matched; default action '{policy['default_action']}'.")

    return {
        "outcome": outcome,
        "action": action,
        "lane": LANE_OF_ACTION[action],
        "lanes": lanes,
        "reasons": reasons,
        "matches": matches,
    }
