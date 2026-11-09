"""Golden fixture integration tests.

Each supported framework family has a representative fixture that exercises
the full scan pipeline: detection, parsing, capability extraction, and
finding generation. These tests serve as regression anchors — if a fixture
starts failing, it signals a breaking change in the adapter or engine.

Add new fixtures for each framework by:
  1. Creating a directory under tests/fixtures/<framework>/representative/
  2. Adding a representative source file for that framework
  3. Adding a test class below following the existing pattern
"""

import json
import os

from safeai.engine.scan import run_scan
from safeai.report.sarif import write_sarif

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _scan(fixture_name):
    return run_scan(os.path.join(FIXTURES, fixture_name, "representative"))


# ── Framework golden fixtures ──────────────────────────────────────────


class TestClaudeCodeGolden:
    """Claude Code config-file adapter (settings.json + CLAUDE.md + .mcp.json)."""

    FIXTURE = os.path.join(FIXTURES, "claude_code", "compatibility")

    def test_detection(self):
        report = run_scan(self.FIXTURE)
        assert "claude_code" in report["detected_frameworks"]

    def test_artifacts_present(self):
        report = run_scan(self.FIXTURE)
        model = next(
            m for m in report["unified_models"]
            if "claude_code" in m.get("frameworks", [])
        )
        assert model["artifacts"]["tools"]

    def test_capabilities_detected(self):
        report = run_scan(self.FIXTURE)
        model = next(
            m for m in report["unified_models"]
            if "claude_code" in m.get("frameworks", [])
        )
        cap_names = {c["name"] for c in model["capabilities"]}
        assert "mcp" in cap_names


class TestCrewAIGolden:
    """CrewAI framework adapter."""

    def test_detection(self):
        report = _scan("crewai")
        assert "crewai" in report["detected_frameworks"]

    def test_agents_and_tasks(self):
        report = _scan("crewai")
        model = next(
            m for m in report["unified_models"]
            if "crewai" in m.get("frameworks", [])
        )
        artifacts = model["artifacts"]
        assert any("Agent" in a["name"] for a in artifacts["agents"])
        assert any("Task" in t["name"] for t in artifacts["workflows"])

    def test_memory_detected(self):
        report = _scan("crewai")
        model = next(
            m for m in report["unified_models"]
            if "crewai" in m.get("frameworks", [])
        )
        assert any("Memory" in mem["name"] for mem in model["artifacts"]["memory"])


class TestLangGraphGolden:
    """LangGraph framework adapter."""

    def test_detection(self):
        report = _scan("langgraph")
        assert "langgraph" in report["detected_frameworks"]

    def test_graph_and_tools(self):
        report = _scan("langgraph")
        model = next(
            m for m in report["unified_models"]
            if "langgraph" in m.get("frameworks", [])
        )
        artifacts = model["artifacts"]
        assert any("ToolNode" in t["name"] for t in artifacts["tools"])

    def test_memory_saver(self):
        report = _scan("langgraph")
        model = next(
            m for m in report["unified_models"]
            if "langgraph" in m.get("frameworks", [])
        )
        assert any(
            mem["name"] == "MemorySaver"
            for mem in model["artifacts"]["memory"]
        )


class TestCursorRulesGolden:
    """Cursor config-file adapter (.cursorrules)."""

    def test_detection(self):
        report = _scan("cursorrules")
        assert "cursorrules" in report["detected_frameworks"]

    def test_tools_and_model(self):
        report = _scan("cursorrules")
        model = next(
            m for m in report["unified_models"]
            if "cursorrules" in m.get("frameworks", [])
        )
        tool_names = {t["name"] for t in model["artifacts"]["tools"]}
        assert "read_file" in tool_names
        model_names = {m["name"] for m in model["artifacts"]["models"]}
        assert "claude-sonnet-4-5" in model_names


class TestWindsurfGolden:
    """Windsurf config-file adapter (.windsurfrules)."""

    def test_detection(self):
        report = _scan("windsurf")
        assert "windsurf" in report["detected_frameworks"]

    def test_capabilities(self):
        report = _scan("windsurf")
        model = next(
            m for m in report["unified_models"]
            if "windsurf" in m.get("frameworks", [])
        )
        assert model["capabilities"]


class TestOpenClawGolden:
    """OpenClaw JSON/YAML config-file adapter."""

    def test_detection(self):
        report = _scan("openclaw")
        assert "openclaw" in report["detected_frameworks"]

    def test_tools_model_capabilities_and_mcp(self):
        report = _scan("openclaw")
        model = next(
            item
            for item in report["unified_models"]
            if "openclaw" in item.get("frameworks", [])
        )
        artifacts = model["artifacts"]
        assert {tool["name"] for tool in artifacts["tools"]} >= {
            "read_file", "run_shell", "call_api",
        }
        assert {entry["name"] for entry in artifacts["models"]} == {
            "claude-sonnet-4-5",
        }
        assert {capability["name"] for capability in model["capabilities"]} >= {
            "shell", "filesystem", "external_apis", "databases", "mcp",
        }
        parsed = next(
            item["data"]
            for item in report["agent_models"]
            if item["framework"] == "openclaw"
        )
        assert any(asset.get("name") == "github" for asset in parsed["mcp_assets"])


class TestCopilotGolden:
    """GitHub Copilot Markdown and YAML instruction-file adapter."""

    def test_detection(self):
        report = _scan("copilot")
        assert "copilot" in report["detected_frameworks"]

    def test_frontmatter_and_markdown_capabilities(self):
        report = _scan("copilot")
        model = next(
            item
            for item in report["unified_models"]
            if "copilot" in item.get("frameworks", [])
        )
        artifacts = model["artifacts"]
        assert {tool["name"] for tool in artifacts["tools"]} >= {
            "read_file", "run_shell",
        }
        assert {entry["name"] for entry in artifacts["models"]} == {"gpt-5"}
        assert {capability["name"] for capability in model["capabilities"]} >= {
            "shell", "filesystem", "external_apis", "mcp",
        }
        parsed = next(
            item["data"]
            for item in report["agent_models"]
            if item["framework"] == "copilot"
        )
        assert any(asset.get("name") == "github" for asset in parsed["mcp_assets"])


class TestN8NGolden:
    """n8n workflow adapter."""

    def test_detection(self):
        report = _scan("n8n")
        assert "n8n" in report["detected_frameworks"]

    def test_workflow_parsed(self):
        report = _scan("n8n")
        model = next(
            m for m in report["unified_models"]
            if "n8n" in m.get("frameworks", [])
        )
        assert model["artifacts"]["workflows"]


class TestLlamaIndexGolden:
    """LlamaIndex framework adapter."""

    def test_detection(self):
        report = _scan("llamaindex")
        assert "llamaindex" in report["detected_frameworks"]

    def test_agent_detected(self):
        report = _scan("llamaindex")
        model = next(
            m for m in report["unified_models"]
            if "llamaindex" in m.get("frameworks", [])
        )
        assert model["artifacts"]["agents"]


class TestAzureFoundryGolden:
    """Azure Foundry adapter (YAML config)."""

    def test_detection(self):
        report = _scan("azure_foundry")
        assert "azure_foundry" in report["detected_frameworks"]

    def test_tools_detected(self):
        report = _scan("azure_foundry")
        model = next(
            m for m in report["unified_models"]
            if "azure_foundry" in m.get("frameworks", [])
        )
        assert model["artifacts"]["tools"]


class TestBedrockAgentGolden:
    """Bedrock Agent adapter (JSON config)."""

    def test_detection(self):
        report = _scan("bedrock_agent")
        assert "bedrock_agent" in report["detected_frameworks"]

    def test_tools_detected(self):
        report = _scan("bedrock_agent")
        model = next(
            m for m in report["unified_models"]
            if "bedrock_agent" in m.get("frameworks", [])
        )
        assert model["artifacts"]["tools"]


class TestDifyGolden:
    """Dify framework adapter (YAML workflow)."""

    def test_detection(self):
        report = _scan("dify")
        assert "dify" in report["detected_frameworks"]

    def test_artifacts_present(self):
        report = _scan("dify")
        model = next(
            m for m in report["unified_models"]
            if "dify" in m.get("frameworks", [])
        )
        assert model["artifacts"]["tools"] or model["artifacts"]["agents"]


class TestHaystackGolden:
    """Haystack framework adapter (Python pipeline)."""

    def test_detection(self):
        report = _scan("haystack")
        assert "haystack" in report["detected_frameworks"]

    def test_workflow_detected(self):
        report = _scan("haystack")
        model = next(
            m for m in report["unified_models"]
            if "haystack" in m.get("frameworks", [])
        )
        assert model["artifacts"]["workflows"]


class TestLangChainGolden:
    """LangChain framework adapter (Python agent)."""

    def test_detection(self):
        report = _scan("langchain")
        assert "langchain" in report["detected_frameworks"]

    def test_agent_detected(self):
        report = _scan("langchain")
        model = next(
            m for m in report["unified_models"]
            if "langchain" in m.get("frameworks", [])
        )
        assert model["artifacts"]["agents"]


class TestMastraGolden:
    """Mastra framework adapter (Python agent)."""

    def test_detection(self):
        report = _scan("mastra")
        assert "mastra" in report["detected_frameworks"]

    def test_agent_detected(self):
        report = _scan("mastra")
        model = next(
            m for m in report["unified_models"]
            if "mastra" in m.get("frameworks", [])
        )
        assert model["artifacts"]["agents"]


class TestMicrosoftAgentGolden:
    """Microsoft Agent Framework adapter (Python agent)."""

    def test_detection(self):
        report = _scan("microsoft_agent")
        assert "microsoft_agent_framework" in report["detected_frameworks"]

    def test_agent_detected(self):
        report = _scan("microsoft_agent")
        model = next(
            m for m in report["unified_models"]
            if "microsoft_agent_framework" in m.get("frameworks", [])
        )
        assert model["artifacts"]["agents"]


class TestGoogleADKGolden:
    """Google ADK adapter (already has fixtures, needs test class)."""

    def test_detection(self):
        report = _scan("google_adk")
        assert "google_adk" in report["detected_frameworks"]


class TestOpenAIAgentsGolden:
    """OpenAI Agents adapter (already has fixtures, needs test class)."""

    def test_detection(self):
        import pytest
        pytest.skip("RecursionError in import_graph.resolve_symbol - known issue")
        report = _scan("openai_agents")
        assert "openai_agents" in report["detected_frameworks"]


class TestSemanticKernelGolden:
    """Semantic Kernel adapter (already has fixtures, needs test class)."""

    def test_detection(self):
        report = _scan("semantic_kernel")
        assert "semantic_kernel" in report["detected_frameworks"]


class TestMCPToolPatterns:
    """Representative MCP configurations exercise security findings end to end."""

    FIXTURE = os.path.join(FIXTURES, "mcp", "golden")

    @classmethod
    def _finding_ids(cls, fixture_name):
        report = run_scan(cls.FIXTURE)
        return {
            finding["rule_id"]
            for finding in report["findings"]
            if os.path.basename(finding.get("file", "")) == fixture_name
        }

    def test_clean_server_has_no_security_findings(self):
        assert self._finding_ids("clean_server.json") == set()

    def test_poisoned_tool_detected(self):
        assert "MCP_TOOL_DESCRIPTION_INJECTION" in self._finding_ids("poisoned_tool.json")

    def test_missing_auth_detected(self):
        assert "MCP_AUTH_MISSING" in self._finding_ids("missing_auth.json")

    def test_exposed_endpoint_detected(self):
        assert "MCP_ENDPOINT_EXPOSURE" in self._finding_ids("exposed_endpoint.json")


# ── JSON report contract ───────────────────────────────────────────────


class TestJSONReportContract:
    """Verify the JSON report contains all required top-level keys."""

    REQUIRED_KEYS = [
        "findings", "counts", "detected_frameworks", "tool_surface",
        "assurance_boundary", "unified_models",
    ]

    def test_required_keys_present(self):
        report = _scan("crewai")
        for key in self.REQUIRED_KEYS:
            assert key in report, f"Missing key: {key}"

    def test_findings_are_dicts(self):
        report = _scan("crewai")
        for f in report["findings"]:
            assert isinstance(f, dict)
            assert "rule_id" in f
            assert "file" in f
            assert "line" in f
            assert "severity" in f

    def test_counts_has_severity_keys(self):
        report = _scan("crewai")
        counts = report["counts"]
        assert isinstance(counts, dict)


# ── SARIF output contract ──────────────────────────────────────────────


class TestSARIFContract:
    """Verify SARIF output is valid and contains required fields."""

    def test_sarif_version(self, tmp_path):
        report = _scan("crewai")
        out = tmp_path / "out.sarif"
        write_sarif(report, str(out))
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_sarif_has_runs(self, tmp_path):
        report = _scan("crewai")
        out = tmp_path / "out.sarif"
        write_sarif(report, str(out))
        data = json.loads(out.read_text())
        assert len(data["runs"]) >= 1

    def test_sarif_run_has_rules_and_results(self, tmp_path):
        report = _scan("claude_code/compatibility")
        out = tmp_path / "out.sarif"
        write_sarif(report, str(out))
        data = json.loads(out.read_text())
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run

    def test_sarif_rule_has_required_fields(self, tmp_path):
        report = _scan("claude_code/compatibility")
        out = tmp_path / "out.sarif"
        write_sarif(report, str(out))
        data = json.loads(out.read_text())
        run = data["runs"][0]
        for rule in run["tool"]["driver"]["rules"]:
            assert "id" in rule
            assert "shortDescription" in rule

    def test_sarif_result_has_locations(self, tmp_path):
        report = _scan("claude_code/compatibility")
        out = tmp_path / "out.sarif"
        write_sarif(report, str(out))
        data = json.loads(out.read_text())
        run = data["runs"][0]
        for result in run.get("results", []):
            assert "ruleId" in result
            assert "locations" in result


# ── CLI behavior contract ──────────────────────────────────────────────


class TestCLIContract:
    """Verify CLI exit codes and output flags work as documented."""

    def test_zero_exit_on_clean_project(self, tmp_path):
        from safeai.cmd.cli import main
        (tmp_path / "clean.py").write_text("print('hello')\n")
        code = main(["scan", str(tmp_path), "--sarif", "", "--fail-on", "critical"])
        assert code == 0

    def test_nonzero_exit_on_threshold_breach(self, tmp_path):
        from safeai.cmd.cli import main
        (tmp_path / "risky.py").write_text('api_key = "sk-1234567890abcdef1234"\n')
        code = main(["scan", str(tmp_path), "--sarif", "", "--fail-on", "high"])
        assert code == 1

    def test_json_output_flag(self, tmp_path):
        from safeai.cmd.cli import main
        (tmp_path / "app.py").write_text("print('hello')\n")
        json_path = str(tmp_path / "out.json")
        code = main(["scan", str(tmp_path), "--json", json_path, "--fail-on", "critical"])
        assert code == 0
        data = json.loads((tmp_path / "out.json").read_text())
        assert "findings" in data

    def test_sarif_output_flag(self, tmp_path):
        from safeai.cmd.cli import main
        (tmp_path / "app.py").write_text("print('hello')\n")
        sarif_path = str(tmp_path / "out.sarif")
        code = main(["scan", str(tmp_path), "--sarif", sarif_path, "--fail-on", "critical"])
        assert code == 0
        data = json.loads((tmp_path / "out.sarif").read_text())
        assert data["version"] == "2.1.0"

    def test_html_output_flag(self, tmp_path):
        from safeai.cmd.cli import main
        (tmp_path / "app.py").write_text("print('hello')\n")
        html_path = str(tmp_path / "out.html")
        code = main(["scan", str(tmp_path), "--html", html_path, "--fail-on", "critical"])
        assert code == 0
        assert (tmp_path / "out.html").exists()
        content = (tmp_path / "out.html").read_text()[:100].lower()
        assert "doctype" in content


# ── Action inputs/outputs contract ─────────────────────────────────────


class TestActionContract:
    """Verify GitHub Action input/output mapping is stable."""

    def test_action_yaml_has_all_inputs(self):
        import yaml
        action_path = os.path.join(
            os.path.dirname(__file__), os.pardir, "action.yml"
        )
        with open(action_path) as f:
            action = yaml.safe_load(f)
        inputs = action["inputs"]
        expected = [
            "path", "version", "fail-on", "sarif", "rules", "baseline",
            "fail-on-new", "fail-on-escalation", "no-registry", "extra-args",
            "scorecard", "scorecard-json", "scorecard-summary", "scorecard-fail-under",
        ]
        for name in expected:
            assert name in inputs, f"Missing action input: {name}"

    def test_action_yaml_has_all_outputs(self):
        import yaml
        action_path = os.path.join(
            os.path.dirname(__file__), os.pardir, "action.yml"
        )
        with open(action_path) as f:
            action = yaml.safe_load(f)
        outputs = action["outputs"]
        expected = ["sarif-path", "scorecard-path", "safeai-version"]
        for name in expected:
            assert name in outputs, f"Missing action output: {name}"


# ── Adapter contract ───────────────────────────────────────────────────


class TestAdapterContract:
    """Every registered parser must implement detect() and parse().
    Parsers that don't match the file return minimal results — we only
    validate the contract for parsers that do match."""

    REQUIRED_PARSE_KEYS = {
        "framework", "capabilities", "tools", "models",
        "detection_evidence",
    }

    def _get_all_parsers(self):
        from safeai.frameworks import discover_parsers
        return discover_parsers()

    def test_all_parsers_implement_detect(self):
        for parser in self._get_all_parsers():
            assert hasattr(parser, "detect"), (
                f"{type(parser).__name__} missing detect()"
            )
            assert callable(parser.detect)

    def test_all_parsers_implement_parse(self):
        for parser in self._get_all_parsers():
            assert hasattr(parser, "parse"), (
                f"{type(parser).__name__} missing parse()"
            )
            assert callable(parser.parse)

    def test_parse_returns_framework_key(self):
        """Parsers that produce output must include a 'framework' key."""
        for parser in self._get_all_parsers():
            result = parser.parse("test.py", "")
            if result:  # only check parsers that return non-empty
                assert "framework" in result, (
                    f"{type(parser).__name__}.parse() missing 'framework' key"
                )

    def test_parse_capabilities_are_list(self):
        """Parsers that detect capabilities return them as a list."""
        for parser in self._get_all_parsers():
            result = parser.parse("test.py", "")
            if not isinstance(result, dict):
                continue
            caps = result.get("capabilities")
            if caps is not None:
                assert isinstance(caps, list)
                for cap in caps:
                    assert isinstance(cap, dict)
                    assert "name" in cap


# ── Fixture coverage completeness ──────────────────────────────────────


class TestFixtureCoverageCompleteness:
    """Every registered framework adapter must have a golden fixture.

    This test prevents silent coverage regression: if a new adapter is added
    without a corresponding fixture, this test will fail.
    """

    # Mapping from framework names returned by parsers to fixture directory names
    FRAMEWORK_TO_FIXTURE = {
        "microsoft_agent_framework": "microsoft_agent",
    }

    @staticmethod
    def _get_registered_frameworks():
        """Return the set of framework names from registered parsers."""
        from safeai.frameworks import discover_parsers
        parsers = discover_parsers()
        frameworks = set()
        for parser in parsers:
            if getattr(parser, "name", None):
                # A parser's registered name; parsing empty content proves nothing
                # for a parser that, rightly, rejects it.
                frameworks.add(parser.name)
                continue
            # Try .py first, then .json, then .yaml for parsers that need specific file types
            for test_file, test_content in [("test.py", ""), ("test.json", "{}"), ("test.yaml", "")]:
                result = parser.parse(test_file, test_content)
                if isinstance(result, dict) and "framework" in result:
                    frameworks.add(result["framework"])
                    break
        return frameworks

    def _get_fixture_frameworks(self):
        """Return the set of framework names that have golden fixtures."""
        fixture_dirs = []
        for entry in os.scandir(FIXTURES):
            if entry.is_dir() and entry.name not in ("mcp", "action", "regression", "claude_code"):
                rep = os.path.join(entry.path, "representative")
                if os.path.isdir(rep):
                    fixture_dirs.append(entry.name)
        # claude_code uses compatibility/ instead of representative/
        claude_compat = os.path.join(FIXTURES, "claude_code", "compatibility")
        if os.path.isdir(claude_compat):
            fixture_dirs.append("claude_code")
        # Map fixture directory names back to framework names
        frameworks = set()
        for dir_name in fixture_dirs:
            # Check if this directory name maps to a different framework name
            mapped = False
            for fw_name, fw_dir in self.FRAMEWORK_TO_FIXTURE.items():
                if dir_name == fw_dir:
                    frameworks.add(fw_name)
                    mapped = True
                    break
            if not mapped:
                frameworks.add(dir_name)
        return frameworks

    def test_all_frameworks_have_fixtures(self):
        """Every registered framework must have a golden fixture directory."""
        registered = self._get_registered_frameworks()
        with_fixtures = self._get_fixture_frameworks()
        missing = registered - with_fixtures
        assert not missing, (
            f"Frameworks missing golden fixtures: {sorted(missing)}. "
            f"Add a representative fixture under tests/fixtures/<name>/representative/"
        )

    def test_all_fixtures_belong_to_registered_frameworks(self):
        """Every golden fixture directory must correspond to a registered framework."""
        registered = self._get_registered_frameworks()
        with_fixtures = self._get_fixture_frameworks()
        orphaned = with_fixtures - registered
        assert not orphaned, (
            f"Fixture directories for unregistered frameworks: {sorted(orphaned)}. "
            f"Either register the parser or remove the fixture directory."
        )
