"""Amazon Bedrock Agent configuration adapter.

Detects Bedrock Agent configs via JSON files containing ``bedrock``
keyword. Extracts workflow names, action tools, and metadata keys.
"""

import json

from safeai.frameworks import register_parser


@register_parser
class BedrockAgentParser:
    name = "bedrock_agent"

    def detect(self, path, content, scan_ctx=None):
        return path.endswith(".json") and "bedrock" in content.lower()

    def parse(self, path, content, scan_ctx=None):
        try:
            data = json.loads(content)
        except Exception:
            return {}
        if not isinstance(data, dict):  # a list or scalar is not an agent configuration
            return {}
        return {
            "framework": "bedrock_agent",
            "keys": list(data.keys()),
            "workflows": [{"name": str(data.get("name", "bedrock_workflow")), "evidence": "json.name"}],
            "tools": [{"name": str(a), "evidence": "json.actions"} for a in data.get("actions", [])] if isinstance(data.get("actions"), list) else [],
            "capabilities": [],
            "discovery_method": "configuration",
            "parser_confidence": 0.8,
            "detection_evidence": ["json:bedrock"],
        }
