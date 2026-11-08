"""Files that merely mention a framework are not that framework.

Found by the credibility track's target eligibility check (2026-11-08):
Azure Pipelines and GitHub workflow files, lockfiles and a package.json
depending on an ``@n8n/...`` utility were reported as Azure AI Foundry
and n8n projects in MCP server repositories.
"""

import pytest

from safeai.frameworks.azure_foundry.parser import AzureFoundryParser
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
