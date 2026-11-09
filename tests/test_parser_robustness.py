"""Framework parsers must not crash on well-formed files of an unexpected shape.

Found by the C-5 census (docs/research/CREDIBILITY_TRACK.md): a JSON file
whose top level was a list, mentioning "bedrock", crashed the Bedrock
Agent parser and with it the whole scan. Every parser is fed documents
whose top level is a list, a scalar or null, in each file type, with
every framework's keywords in them.
"""

import itertools
import json

import pytest

from safeai.engine.orchestrator import run_scan
from safeai.frameworks import discover_parsers

PARSERS = discover_parsers(include_external=False)
KEYWORDS = ["bedrock", "n8n", "crewai", "langgraph", "langchain", "autogen", "dify",
            "haystack", "llama_index", "semantic_kernel", "mastra", "openai", "agents",
            "mcpServers", "google.adk", "foundry", "copilot", "cursor", "windsurf",
            "claude", "tools", "actions", "instructions", "nodes"]
SHAPES = {
    ".json": [json.dumps(KEYWORDS), json.dumps(" ".join(KEYWORDS)), "null", "42",
              json.dumps([{k: k} for k in KEYWORDS])],
    ".yaml": ["- " + "\n- ".join(KEYWORDS), " ".join(KEYWORDS), "~", "42"],
    ".yml": ["- " + "\n- ".join(KEYWORDS)],
    ".toml": [" ".join(KEYWORDS)],
    ".py": ["# " + " ".join(KEYWORDS) + "\n" + "\n".join(f"import {k}" for k in KEYWORDS
                                                          if k.isidentifier())],
    ".ts": ["// " + " ".join(KEYWORDS)],
    ".md": [" ".join(KEYWORDS)],
}
CASES = [(suffix, content) for suffix, contents in SHAPES.items() for content in contents]


@pytest.mark.parametrize(("parser", "case"), list(itertools.product(PARSERS, CASES)),
                         ids=lambda v: getattr(v, "name", None) or v[0])
def test_parsers_survive_unexpected_shapes(parser, case):
    suffix, content = case
    path = f"project/config/agent{suffix}"
    if parser.detect(path, content, scan_ctx={}):
        parser.parse(path, content, scan_ctx={})


def test_one_failing_parser_does_not_abort_the_scan(tmp_path, monkeypatch):
    (tmp_path / "agent.json").write_text('{"bedrock": true, "actions": ["a"]}',
                                         encoding="utf-8")
    from safeai.frameworks.bedrock_agent.parser import BedrockAgentParser

    def boom(self, path, content, scan_ctx=None):
        raise RuntimeError("parser bug")

    monkeypatch.setattr(BedrockAgentParser, "parse", boom)
    report = run_scan(str(tmp_path))
    diagnostics = [d for d in report["diagnostics"] if d.get("stage") == "framework_parsing"]
    assert diagnostics == [{"file": "agent.json", "stage": "framework_parsing",
                            "kind": "parse_error", "parser": "bedrock_agent",
                            "error": "RuntimeError: parser bug"}]
    # The assurance boundary must not claim that every file was analysed.
    notes = " ".join(report["assurance_boundary"]["coverage_notes"])
    assert "agent.json" in notes
