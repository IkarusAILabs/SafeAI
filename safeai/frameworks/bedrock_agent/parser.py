"""Amazon Bedrock Agent configuration adapter.

Detects a JSON file as a Bedrock Agent configuration only when it is one:
a JSON object that is

- an agent as the Bedrock API describes it (``foundationModel``,
  ``actionGroups`` or ``agentResourceRoleArn``, any case), or
- a CloudFormation / CDK template declaring ``AWS::Bedrock::Agent``, or
- an ``actions`` list in a configuration whose name, description, model
  or type names Bedrock.

Mentioning "bedrock" is not enough: package manifests that depend on a
Bedrock SDK and plugin manifests that list it as a provider are not
agent configurations. Extracts the agent name, its action tools and its
top-level keys. CloudFormation in YAML is not read.
"""

import json

from safeai.frameworks import register_parser

# ``agentName`` alone is too generic; these keys are Bedrock's own.
_API_KEYS = frozenset({"foundationmodel", "actiongroups", "agentresourcerolearn"})
_HINTS = ("bedrock", *_API_KEYS)
_CFN_TYPE = "AWS::Bedrock::Agent"
_NAMING_FIELDS = ("name", "description", "model", "type")


def _load(content):
    try:
        data = json.loads(content)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _cfn_agents(data):
    resources = data.get("Resources")
    if not isinstance(resources, dict):
        return []
    return [r.get("Properties") or {} for r in resources.values()
            if isinstance(r, dict) and r.get("Type") == _CFN_TYPE
            and isinstance(r.get("Properties") or {}, dict)]


def _is_agent_config(data):
    if data is None:
        return False
    if _cfn_agents(data):
        return True
    if {str(k).lower() for k in data} & _API_KEYS:
        return True
    names = " ".join(str(data.get(k, "")) for k in _NAMING_FIELDS).lower()
    return isinstance(data.get("actions"), list) and "bedrock" in names


def _get(mapping, key):
    """``key`` in camelCase or PascalCase (the API and CloudFormation forms)."""
    if not isinstance(mapping, dict):
        return None
    return mapping.get(key, mapping.get(key[:1].upper() + key[1:]))


def _action_group_tools(agent):
    groups = _get(agent, "actionGroups")
    if not isinstance(groups, list):
        return []
    return [{"name": str(_get(g, "actionGroupName")), "evidence": "json.actionGroups"}
            for g in groups if _get(g, "actionGroupName")]


@register_parser
class BedrockAgentParser:
    name = "bedrock_agent"

    def detect(self, path, content, scan_ctx=None):
        lowered = content.lower()
        if not path.endswith(".json") or not any(h in lowered for h in _HINTS):
            return False
        return _is_agent_config(_load(content))

    def parse(self, path, content, scan_ctx=None):
        data = _load(content)
        if not _is_agent_config(data):  # a list, scalar or unrelated JSON
            return {}
        workflows, tools = [], []
        for agent in _cfn_agents(data) or [data]:
            name = _get(agent, "agentName") or agent.get("name", "bedrock_workflow")
            workflows.append({"name": str(name), "evidence": "json.name"})
            actions = agent.get("actions")
            if isinstance(actions, list):
                tools += [{"name": str(a), "evidence": "json.actions"} for a in actions]
            tools += _action_group_tools(agent)
        return {
            "framework": "bedrock_agent",
            "keys": list(data.keys()),
            "workflows": workflows,
            "tools": tools,
            "capabilities": [],
            "discovery_method": "configuration",
            "parser_confidence": 0.8,
            "detection_evidence": ["json:bedrock"],
        }
