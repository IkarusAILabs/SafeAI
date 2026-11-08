"""n8n framework adapter.

Detects n8n workflow JSON exports and ``n8n`` references in code.
Extracts workflow nodes, connections, tool references, and
webhook / HTTP integrations.
"""

import json
import re

from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.frameworks import register_parser

_N8N_NODE = re.compile(r"^(?:n8n-nodes-base\.|@n8n/n8n-nodes-)")
_N8N_WORD = re.compile(r"\bn8n\b", re.IGNORECASE)


@register_parser
class N8nParser:
    name = "n8n"

    def detect(self, path, content, scan_ctx=None):
        # A JSON file is an n8n workflow only by its structure: nodes and
        # connections, with at least one n8n node type. Mentioning n8n is
        # not enough (``package.json`` depending on ``@n8n/...``).
        if path.endswith(".json"):
            if "n8n" not in content:
                return False
            try:
                data = json.loads(content)
            except Exception:
                return False
            if isinstance(data, dict) and "nodes" in data and "connections" in data:
                nodes = data.get("nodes")
                return isinstance(nodes, list) and any(
                    isinstance(node, dict) and _N8N_NODE.match(str(node.get("type", "")))
                    for node in nodes
                )
            return False
        # Python code that talks to n8n, outside comments.
        if path.endswith(".py"):
            return any(_N8N_WORD.search(line) for line in content.splitlines()
                       if not line.lstrip().startswith("#"))
        return False

    def parse(self, path, content, scan_ctx=None):
        result = {
            "framework": "n8n",
            "agents": [],
            "tools": [],
            "workflows": [],
            "models": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "config",
            "parser_confidence": 0.80,
            "detection_evidence": [],
        }

        caps = []

        if path.endswith(".json"):
            try:
                data = json.loads(content)
            except Exception:
                data = None
            if isinstance(data, dict):
                self._parse_workflow(data, result, caps)
        elif path.endswith(".py"):
            self._parse_python(content, result, caps)

        result["capabilities"] = dedupe_capabilities(caps)
        return result

    def _parse_workflow(self, data, result, caps):
        if "name" in data:
            result["workflows"].append(str(data["name"]))
            result["detection_evidence"].append(f"Workflow: {data['name']}")

        nodes = data.get("nodes", [])
        if isinstance(nodes, list):
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                node_type = node.get("type", "")
                node_name = node.get("name", "")
                if node_name:
                    result["tools"].append(str(node_name))

                # Capability inference from node types
                node_type_lower = node_type.lower()
                if re.search(r"http|webhook|api", node_type_lower):
                    caps.append(make_capability(
                        "external_apis", "External APIs", "n8n",
                        f"node type: {node_type}", confidence=0.75, source="config",
                    ))
                if re.search(r"database|postgres|mysql|mongodb|redis", node_type_lower):
                    caps.append(make_capability(
                        "databases", "Databases", "n8n",
                        f"node type: {node_type}", confidence=0.75, source="config",
                    ))
                if re.search(r"shell|exec|command|function", node_type_lower):
                    caps.append(make_capability(
                        "shell", "Shell", "n8n",
                        f"node type: {node_type}", confidence=0.75, source="config",
                    ))
                if re.search(r"openai|anthropic|llm|ai", node_type_lower):
                    caps.append(make_capability(
                        "external_model_api", "External APIs", "n8n",
                        f"node type: {node_type}", confidence=0.75, source="config",
                    ))
                    model = node.get("parameters", {}).get("model", node.get("model", ""))
                    if model:
                        result["models"].append(str(model))
                if re.search(r"email|smtp|mail", node_type_lower):
                    caps.append(make_capability(
                        "email", "Email", "n8n",
                        f"node type: {node_type}", confidence=0.75, source="config",
                    ))

        connections = data.get("connections", {})
        if isinstance(connections, dict):
            for source, targets in connections.items():
                if isinstance(targets, dict):
                    for target_type, target_list in targets.items():
                        if isinstance(target_list, list):
                            for target_group in target_list:
                                targets = (
                                    target_group
                                    if isinstance(target_group, list)
                                    else [target_group]
                                )
                                for target in targets:
                                    if not isinstance(target, dict):
                                        continue
                                    result["relationships"].append({
                                        "source": source,
                                        "target": target.get("node", ""),
                                        "type": target_type,
                                    })

    def _parse_python(self, content, result, caps):
        for m in re.finditer(r"n8n", content, re.IGNORECASE):
            result["detection_evidence"].append(f"n8n reference: {m.group(0)}")
