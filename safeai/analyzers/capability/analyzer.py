"""Capability analyzer — detects dangerous agent capabilities.

Operates in two passes:
  1. **Framework arbitration pass** — aggregates capabilities reported by
     framework parsers, merges duplicates via confidence arbitration.
  2. **Regex fallback pass** — scans raw file content with patterns for
     shell, filesystem, HTTP, database, and code execution capabilities.
     Also detects autonomous agent loop patterns.
"""

import ast
import re

from safeai.analyzers import register_analyzer

CAP_PATTERNS = {
    "shell": re.compile(r"subprocess|os\.system|popen", re.IGNORECASE),
    "filesystem": re.compile(r"open\(|os\.remove|os\.write|pathlib", re.IGNORECASE),
    "external_apis": re.compile(r"requests|httpx|urllib", re.IGNORECASE),
    "databases": re.compile(r"sqlite3|psycopg2|mysql|postgres|sqlalchemy", re.IGNORECASE),
    "code_exec": re.compile(r"exec\(|eval\(", re.IGNORECASE),
    "docker": re.compile(r"import docker|from docker|DockerClient|docker\.run|containers\.run", re.IGNORECASE),
    "kubernetes": re.compile(r"import kubernetes|from kubernetes|kubectl|kube_config|KubeConfig|k8s", re.IGNORECASE),
    "redis": re.compile(r"import redis|from redis|Redis\(|redis\.StrictRedis|redis\.Redis", re.IGNORECASE),
    "s3": re.compile(r"import boto3|from boto3|boto3\.client.*s3|boto3\.resource.*s3|S3Client|s3\.put|s3\.get", re.IGNORECASE),
    "slack": re.compile(r"import slack|from slack|SlackClient|slack_sdk|slack\.WebClient|slack\.SocketModeClient", re.IGNORECASE),
    "ms_teams": re.compile(r"(?:\bimport\s+teams\b|\bfrom\s+teams\s+import\b|\bTeamsClient\b|\bteams_sdk\b|\bimport\s+pymsteams\b|\bfrom\s+pymsteams\b|\bpymsteams\.(?:connectorcard|cardsection)\b)", re.IGNORECASE),
    "jira": re.compile(r"import jira|from jira|JIRA\(|jira\.Client|jira\.JIRA", re.IGNORECASE),
    "browser_playwright": re.compile(r"import playwright|from playwright|Playwright", re.IGNORECASE),
    "browser_selenium": re.compile(r"import selenium|from selenium|webdriver|WebDriver", re.IGNORECASE),
    "browser_use": re.compile(r"from browser_use|import browser_use|browser_use\.Agent", re.IGNORECASE),
    "gcp": re.compile(r"import google\.cloud|from google\.cloud|google\.cloud\.\w+|GCP|gcsfs|BigQuery", re.IGNORECASE),
}

# Higher-risk variants detected in addition to the base capability patterns.
SUBPROCESS_SHELL_RE = re.compile(r"subprocess[\s\S]{0,200}?shell\s*=\s*True", re.IGNORECASE)

# subprocess entry points that accept ``shell=``.
SUBPROCESS_SHELL_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}


def _subprocess_shell_calls(content):
    """Return ``(lineno, evidence)`` for subprocess calls passing ``shell=True``.

    The per-line regex cannot see a call whose ``shell=True`` sits on a
    later line than ``subprocess.run(`` — the usual black/ruff wrapping of
    long calls. This AST pass resolves ``import subprocess [as x]`` and
    ``from subprocess import run [as y]`` bindings and reports each call at
    its first line. Only a literal ``True`` counts; ``**kwargs`` or
    computed values stay unresolved. Unparseable sources yield nothing.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    modules, functions = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    modules.add(alias.asname or "subprocess")
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            for alias in node.names:
                if alias.name in SUBPROCESS_SHELL_FUNCS:
                    functions.add(alias.asname or alias.name)
    if not modules and not functions:
        return []

    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_subprocess = (
            isinstance(func, ast.Attribute)
            and func.attr in SUBPROCESS_SHELL_FUNCS
            and isinstance(func.value, ast.Name)
            and func.value.id in modules
        ) or (isinstance(func, ast.Name) and func.id in functions)
        if not is_subprocess:
            continue
        if any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        ):
            segment = ast.get_source_segment(content, node) or ""
            calls.append((node.lineno, " ".join(segment.split())[:200]))
    return sorted(calls)
FILE_WRITE_RE = re.compile(r"\bopen\([^)]*[\"'](?:w|a|x)[bt+]?[\"']", re.IGNORECASE)

RULE_BY_CAP = {
    "shell": "CAP_shell",
    "filesystem": "CAP_filesystem",
    "external_apis": "CAP_http",
    "databases": "CAP_db",
    "code_exec": "CAP_code_exec",
    "docker": "CAP_docker",
    "kubernetes": "CAP_kubernetes",
    "redis": "CAP_redis",
    "s3": "CAP_s3",
    "slack": "CAP_slack",
    "ms_teams": "CAP_ms_teams",
    "jira": "CAP_jira",
    "browser_playwright": "CAP_browser_playwright",
    "browser_selenium": "CAP_browser_selenium",
    "browser_use": "CAP_browser_use",
    "gcp": "CAP_gcp",
}

CATEGORY_BY_CAP = {
    "shell": "Shell",
    "filesystem": "Filesystem",
    "external_apis": "External APIs",
    "databases": "Databases",
    "code_exec": "Capability",
    "docker": "Container",
    "kubernetes": "Container",
    "redis": "Databases",
    "s3": "Cloud",
    "slack": "Collaboration",
    "ms_teams": "Collaboration",
    "jira": "Collaboration",
    "browser_playwright": "Browser",
    "browser_selenium": "Browser",
    "browser_use": "Browser",
    "gcp": "Cloud",
}


def _finding(rule_id, rule, message, path, line, capability, framework="generic", evidence=None, confidence=0.6, score_contribution=8):
    return {
        "rule_id": rule_id,
        "evidence_type": "static-pattern",  # #94 - regex fallback pass over raw file content
        "severity": rule.get("severity", "medium"),
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", "LLM06"),
        "evidence": evidence or message,
        "reason": f"Capability inference indicates {capability} behavior.",
        "risk_category": "Capability",
        "affected_framework": framework,
        "affected_capability": capability,
        "score_contribution": score_contribution,
        "remediation": "Constrain tool permissions and apply least privilege for this capability.",
        "confidence": confidence,
    }


def _iter_evidence(value):
    if isinstance(value, list):
        for item in value:
            if item is not None:
                yield str(item)
        return
    if value is not None:
        yield str(value)


@register_analyzer
class CapabilityAnalyzer:
    name = "capability"

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}
        seen = set()

        arbitration = {}
        for model in agent_models or []:
            path = model.get("file")
            framework = model.get("framework") or "generic"
            data = model.get("data", {})
            capabilities = data.get("capabilities") or []
            for cap in capabilities:
                cap_name = cap.get("name", "capability")
                cap_category = cap.get("category", "Capability")
                key = (path, str(cap_name).lower(), str(cap_category).lower())
                entry = arbitration.setdefault(key, {
                    "path": path,
                    "cap_name": cap_name,
                    "cap_category": cap_category,
                    "frameworks": set(),
                    "evidence": set(),
                    "confidence": 0.0,
                    "risk_weight": 1.0,
                    "sources": set(),
                    "resolved_definitions": set(),
                })
                entry["frameworks"].add(framework)
                if cap.get("source_framework"):
                    for fw in _iter_evidence(cap.get("source_framework")):
                        entry["frameworks"].add(fw)
                for ev in _iter_evidence(cap.get("evidence") or cap_name):
                    entry["evidence"].add(ev)
                for rv in _iter_evidence(cap.get("resolved_definition") or cap.get("resolved_definitions")):
                    entry["resolved_definitions"].add(rv)
                for src in _iter_evidence(cap.get("source") or cap.get("sources")):
                    entry["sources"].add(src)
                entry["confidence"] = max(entry["confidence"], float(cap.get("confidence", 0.7)))
                entry["risk_weight"] = max(entry["risk_weight"], float(cap.get("risk_weight", 1.0)))

        for entry in arbitration.values():
            path = entry["path"]
            cap_name = entry["cap_name"]
            cap_category = entry["cap_category"]
            normalized = cap_name.split("_", 1)[0] if "_" in cap_name else cap_name
            normalized = normalized if normalized in RULE_BY_CAP else cap_name
            rule_id = RULE_BY_CAP.get(normalized, "CAP_filesystem")
            rule = rule_map.get(rule_id, {})
            key = (path, cap_name, cap_category)
            if key in seen:
                continue
            seen.add(key)

            frameworks = sorted(entry["frameworks"])
            evidence_all = sorted(entry["evidence"]) or [cap_name]
            sources = sorted(entry["sources"])
            resolved_values = sorted(entry["resolved_definitions"])

            findings.append({
                "rule_id": rule_id,
                "evidence_type": "static-pattern",  # #94 - regex fallback pass over raw file content
                "severity": rule.get("severity", "medium"),
                "message": f"Capability discovered: {cap_name}",
                "file": path,
                "line": 1,
                "owasp_llm": rule.get("owasp_llm", "LLM06"),
                "evidence": evidence_all[0],
                "reason": "Capability derived from confidence-arbitrated framework semantic discovery.",
                "risk_category": "Capability",
                "affected_framework": ", ".join(frameworks) if frameworks else "generic",
                "affected_capability": cap_category,
                "score_contribution": int(8 * entry["risk_weight"]),
                "remediation": "Review this capability and restrict access paths where possible.",
                "confidence": entry["confidence"],
                "source": ", ".join(sources) if sources else "ast",
                "resolved_definition": ", ".join(resolved_values) if resolved_values else None,
                "evidence_all": evidence_all,
                "provenance_frameworks": frameworks,
            })

        for path, content in file_cache.items():
            try:
                lines = content.splitlines()
                for i, line in enumerate(lines, 1):
                    # Escalated variant: subprocess invoked with shell=True.
                    if SUBPROCESS_SHELL_RE.search(line):
                        key = (path, "subprocess_shell", i)
                        if key not in seen:
                            seen.add(key)
                            rule = rule_map.get("CAP_subprocess_shell", {})
                            findings.append(_finding(
                                "CAP_subprocess_shell",
                                rule,
                                "subprocess invoked with shell=True",
                                path,
                                i,
                                "Shell",
                                evidence=line.strip(),
                                confidence=0.7,
                                score_contribution=15,
                            ))

                    # Escalated variant: file opened for writing/appending.
                    if FILE_WRITE_RE.search(line):
                        key = (path, "file_write", i)
                        if key not in seen:
                            seen.add(key)
                            rule = rule_map.get("CAP_file_write", {})
                            findings.append(_finding(
                                "CAP_file_write",
                                rule,
                                "File opened in write mode",
                                path,
                                i,
                                "Filesystem",
                                evidence=line.strip(),
                                confidence=0.55,
                                score_contribution=7,
                            ))

                    for cap, pattern in CAP_PATTERNS.items():
                        if not pattern.search(line):
                            continue
                        key = (path, cap, i)
                        if key in seen:
                            continue
                        seen.add(key)
                        rule_id = RULE_BY_CAP.get(cap, "CAP_filesystem")
                        rule = rule_map.get(rule_id, {})
                        findings.append(_finding(
                            rule_id,
                            rule,
                            f"Capability detected by fallback pattern: {cap}",
                            path,
                            i,
                            CATEGORY_BY_CAP.get(cap, "Capability"),
                            evidence=line.strip(),
                            confidence=0.45,
                            score_contribution=6,
                        ))

                    low = line.lower()
                    if ("while true" in low or "for _ in range(" in low) and "agent" in content.lower():
                        key = (path, "autonomy", i)
                        if key in seen:
                            continue
                        seen.add(key)
                        rule = rule_map.get("CAP_AUTONOMY", {})
                        findings.append({
                            "rule_id": "CAP_AUTONOMY",
                            "evidence_type": "static-pattern",  # #94 - regex fallback pass over raw file content
                            "severity": rule.get("severity", "high"),
                            "message": "Potential autonomous agent loop detected",
                            "file": path,
                            "line": i,
                            "owasp_llm": rule.get("owasp_llm", "LLM06"),
                            "evidence": line.strip(),
                            "reason": "Long-running autonomous loops can increase unchecked action risk.",
                            "risk_category": "Autonomy",
                            "affected_framework": "generic",
                            "affected_capability": "Planner",
                            "score_contribution": 12,
                            "remediation": "Introduce iteration limits and human approval checkpoints.",
                        })

                # Multi-line subprocess calls the per-line regex missed.
                # Single-line hits are already in ``seen`` (same key), so
                # their line, evidence, and fingerprint are unchanged.
                if path.endswith(".py"):
                    for lineno, evidence in _subprocess_shell_calls(content):
                        key = (path, "subprocess_shell", lineno)
                        if key in seen:
                            continue
                        seen.add(key)
                        rule = rule_map.get("CAP_subprocess_shell", {})
                        findings.append(_finding(
                            "CAP_subprocess_shell",
                            rule,
                            "subprocess invoked with shell=True",
                            path,
                            lineno,
                            "Shell",
                            evidence=evidence,
                            confidence=0.7,
                            score_contribution=15,
                        ))
            except Exception:
                continue

        return findings
