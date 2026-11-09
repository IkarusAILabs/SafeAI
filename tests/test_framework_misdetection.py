"""Files that merely mention a framework are not that framework.

Found by the credibility track's target eligibility check (2026-11-08):
Azure Pipelines and GitHub workflow files, lockfiles and a package.json
depending on an ``@n8n/...`` utility were reported as Azure AI Foundry
and n8n projects in MCP server repositories. The C-5 census found the
same for Bedrock Agent (2026-11-09).
"""

import json

import pytest

from safeai.frameworks.azure_foundry.parser import AzureFoundryParser
from safeai.frameworks.bedrock_agent.parser import BedrockAgentParser
from safeai.frameworks.n8n.parser import N8nParser

AZURE_PIPELINE = """trigger:
  - main
pool:
  vmImage: ubuntu-latest
stages:
  - stage: Publish
    jobs:
      - job: docker
        steps:
          - task: AzureCLI@2
"""
GH_WORKFLOW_LOCK = """name: triage
on: issues
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
"""
PNPM_LOCK = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@azure/identity':
        specifier: ^4.0.0
"""


@pytest.mark.parametrize(("path", "content"), [
    (".azure-pipelines/publish-docker.yml", AZURE_PIPELINE),
    (".github/workflows/issue-triage.lock.yml", GH_WORKFLOW_LOCK),
    (".github/workflows/triage.yml", GH_WORKFLOW_LOCK),
    ("pnpm-lock.yaml", PNPM_LOCK),
    ("broken.yaml", "azure: [unclosed\n"),
    ("list.yaml", "- azure\n- tools\n"),
])
def test_yaml_that_only_mentions_azure_is_not_foundry(path, content):
    assert not AzureFoundryParser().detect(path, content)


@pytest.mark.parametrize("content", [
    "name: triage\nmodel: gpt-4\ndeployment: azure-openai-gpt4\ntools:\n  - lookup\n",
    "azure: true\nname: app\ntools: []\n",
    "name: helper\ninstructions: Help with Azure billing.\nmodel: gpt-4o\n",
])
def test_foundry_agent_definitions_are_still_detected(content):
    assert AzureFoundryParser().detect("agent.yaml", content)


PACKAGE_JSON = """{
  "name": "workers-bindings",
  "dependencies": {"@n8n/json-schema-to-zod": "1.1.0", "zod": "3.0.0"}
}"""


@pytest.mark.parametrize(("path", "content"), [
    ("apps/workers-bindings/package.json", PACKAGE_JSON),
    ("pnpm-lock.yaml", "packages:\n  '@n8n/json-schema-to-zod@1.1.0': {}\n"),
    ("README.md", "Works with n8n and Zapier."),
    ("src/app.ts", "// TODO: n8n integration\n"),
    ("tool.py", "# n8n support is planned\nimport os\n"),
    ("flow.json", '{"nodes": [{"type": "custom.node"}], "connections": {}, "note": "n8n"}'),
])
def test_files_that_only_mention_n8n_are_not_workflows(path, content):
    assert not N8nParser().detect(path, content)


@pytest.mark.parametrize(("path", "content"), [
    ("flow.json", '{"nodes": [{"type": "n8n-nodes-base.webhook"}], "connections": {}}'),
    ("agent.json", '{"nodes": [{"type": "@n8n/n8n-nodes-langchain.agent"}], "connections": {}}'),
    ("client.py", 'N8N_URL = "https://n8n.example.org/webhook/x"\n'),
])
def test_n8n_workflows_and_code_are_still_detected(path, content):
    assert N8nParser().detect(path, content)


# Found by the C-5 census (2026-11-09): a plugin manifest listing Bedrock
# among its providers was reported as a Bedrock Agent configuration.
PLUGIN_MANIFEST = json.dumps({
    "identifier": "lhm", "name": "Local helper", "description": "Chat with Bedrock or OpenAI",
    "tools": [{"name": "search"}], "tags": ["bedrock", "openai"]})
PACKAGE_JSON = json.dumps({
    "name": "mcp-server", "dependencies": {"@aws-sdk/client-bedrock-agent-runtime": "^3.0.0"}})


@pytest.mark.parametrize("content", [
    PLUGIN_MANIFEST,
    PACKAGE_JSON,
    json.dumps({"providers": ["bedrock"], "actions": ["a"]}),  # actions, but nothing names Bedrock
    json.dumps(["bedrock", "agent"]),
    json.dumps("bedrock"),
    "{not json bedrock",
])
def test_json_that_only_mentions_bedrock_is_not_an_agent(content):
    parser = BedrockAgentParser()
    assert not parser.detect("config/x.json", content)
    assert parser.parse("config/x.json", content) == {}


API_AGENT = json.dumps({
    "agentName": "billing-agent", "foundationModel": "anthropic.claude-v2",
    "instruction": "Answer billing questions",
    "actionGroups": [{"actionGroupName": "refunds"}, {"actionGroupName": "invoices"}]})
CFN_TEMPLATE = json.dumps({"Resources": {"Agent": {
    "Type": "AWS::Bedrock::Agent",
    "Properties": {"AgentName": "ops-agent", "FoundationModel": "anthropic.claude-v2",
                   "ActionGroups": [{"ActionGroupName": "restart"}]}}}})
MINIMAL = json.dumps({"name": "bedrock_support_triage", "actions": ["lookup_ticket"]})


@pytest.mark.parametrize(("content", "workflow", "tools"), [
    (API_AGENT, "billing-agent", ["refunds", "invoices"]),
    (CFN_TEMPLATE, "ops-agent", ["restart"]),
    (MINIMAL, "bedrock_support_triage", ["lookup_ticket"]),
])
def test_bedrock_agent_definitions_are_detected_with_their_tools(content, workflow, tools):
    parser = BedrockAgentParser()
    assert parser.detect("agent.json", content)
    parsed = parser.parse("agent.json", content)
    assert [w["name"] for w in parsed["workflows"]] == [workflow]
    assert [t["name"] for t in parsed["tools"]] == tools
