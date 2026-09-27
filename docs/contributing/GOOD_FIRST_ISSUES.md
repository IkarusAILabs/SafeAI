# Good First Issues

Welcome, and thank you for considering contributing to SafeAI!

This document indexes **59 beginner-friendly issues** designed for first-time
contributors (25 currently open). Each issue includes the files you'll need to modify, the tests you should write, and
the acceptance criteria.

> **For maintainers:** These issues are defined in `.github/good-first-issues/` as YAML templates. Run the [create-good-first-issues workflow](../../actions/workflows/create-good-first-issues.yml) to create them in the GitHub issue tracker with the `good first issue` label. Once created, this file serves as a curated index.

> **34 issues have already been completed** by community and internal
contributors. See the [Completed Issues](#-completed-issues) section at the bottom.

---

## Framework Adapters

### 1. Add AutoGen detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/frameworks/autogen/parser.py`
- **Suggested tests:** `tests/test_autogen.py`
- **Description:** Detect Microsoft AutoGen framework by scanning Python imports (`from autogen import`). Follow the pattern used by existing parsers (Google ADK, Mastra, etc.) — AST import detection, agent/tool/model extraction, and registration via `@register_parser`.

### 2. Improve LangGraph parser — detect conditional edges
- **Difficulty:** Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/frameworks/langgraph/parser.py`
- **Status:** Partially done — regular `add_edge` calls are detected; `add_conditional_edges` is not yet handled
- **Description:** Extend the LangGraph parser to detect `add_conditional_edges()` calls. Currently the `endswith("add_edge")` check misses the conditional variant (`add_conditional_edges`). Update both the AST detection and regex fallback to capture conditional routing edges.

---

## Capability Detection

### 3. Detect Microsoft Teams integration
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/analyzers/capability/analyzer.py`, `safeai/analysis/capabilities.py`
- **Description:** Add a regex pattern to detect Microsoft Teams SDK usage (`import teams`, `from teams import`, `TeamsClient`, etc.). Follow the same pattern as the existing Docker, Slack, and Jira detectors.

### 4. Detect SharePoint access
- **Difficulty:** Easy | **Effort:** 2 hours
- **Description:** Add a regex pattern for SharePoint Python SDK (`office365`, `sharepoint`, `ClientContext`). This is deferred from the initial capability detection batch and requires MCP-based detection consideration.

### 5. Detect OneDrive access
- **Difficulty:** Easy | **Effort:** 2 hours
- **Description:** Similar to SharePoint — detect OneDrive SDK references (`onedrive`, `OneDriveClient`). May share detection logic with the SharePoint detector.

### 6. Split browser automation into separate rules
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/analyzers/capability/analyzer.py`, `safeai/rules/base_rules.yaml`
- **Description:** The current `CAP_browser` pattern groups Playwright, Selenium, Puppeteer, and `browser_use` under one rule. Split into separate rules (`CAP_browser_playwright`, `CAP_browser_selenium`, etc.) for finer granularity. Community feedback suggests this would improve rule specificity.

---

## Prompt Rules

### 7. Detect unsafe prompt instruction patterns
- **Status:** ✅ Complete — `PROMPT_INJECTION`, `PROMPT_DELIMITER`, `PROMPT_FILE_INJECTION`, `SKILL_EMBEDDED_PROMPT` and 6+ additional rules in `base_rules.yaml:1-112`; analyzer at `safeai/analyzers/prompt/analyzer.py`

### 8. Detect unrestricted instruction overrides
- **Status:** ✅ Complete — `PROMPT_ROLE_OVERRIDE`, `PROMPT_FILE_ROLE_OVERRIDE` rules in `base_rules.yaml:56,103`

### 9. Detect hidden system prompt injection
- **Status:** ✅ Complete — `PROMPT_SYSTEM_LEAK`, `PROMPT_FILE_SYSTEM_LEAK`, `PROMPT_FILE_INJECTION`, `DATAFLOW_prompt` rules

### 10. Detect prompt extraction attempts
- **Status:** ✅ Complete — `PROMPT_SYSTEM_LEAK`, `PROMPT_FILE_SYSTEM_LEAK`, `DATAFLOW_prompt` (system prompt leakage + dataflow tracking)

---

## Governance Signals

### 11. Detect timeout configuration
- **Status:** ✅ Complete (v1.9.0) — `GOV_TIMEOUT_MISSING` rule

### 12. Detect retry policy configuration
- **Status:** ✅ Complete (v1.9.0) — `GOV_RETRY_MISSING` rule

### 13. Detect approval workflow requirement
- **Status:** ✅ Complete (v1.9.0) — `GOV_APPROVAL_MISSING` rule

### 14. Detect audit logging configuration
- **Status:** ✅ Complete (v1.9.0) — `GOV_AUDIT_MISSING` rule

### 15. Detect rate limiting configuration
- **Status:** ✅ Complete (v1.9.0) — `GOV_RATE_LIMIT_MISSING` rule

---

## Reports & Output

### 16. Improve terminal output readability
- **Status:** ✅ Complete (v1.4) — severity-grouped summary, explicit counts, `Highest escalation` line, coverage/assurance notes
- **Difficulty:** Easy | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/terminal.py`
- **Description:** Original task restructured the terminal scan summary for readability. Now delivered: grouping by severity, clearer section headers, and a better signal-to-noise ratio (informed by the HTML report design).

### 17. Improve HTML report — add filtering and search
- **Status:** ✅ Complete (v1.4-b) — client-side filter + searchable tables via `safeai/report/html_kit.py` (`data_table`, `data-filter`)
- **Difficulty:** Medium | **Effort:** 4–6 hours
- **Suggested files:** `safeai/report/html.py`, `safeai/report/html_kit.py`

### 18. Improve SARIF output — add code flow
- **Difficulty:** Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/sarif.py`

### 19. Add Markdown report generator
- **Status:** 🔄 Partial — a Markdown reviewer summary ships via `--pr-comment` (`safeai/report/pr_comment.py`); a standalone `--format markdown` report generator is still open
- **Difficulty:** Easy | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/markdown.py`

### 20. Improve JSON schema — add versioning
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/report/json_report.py`

### 21. Add dependency graph visualization in HTML
- **Difficulty:** Medium | **Effort:** 4–6 hours
- **Suggested files:** `safeai/report/html.py`

### 22. Add CSV report generator
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/report/csv_report.py`

---

## Scoring & Trust Score

### 23. Tune trust score weighting for critical and high findings
- **Status:** ✅ Complete (v1.4) — severity weighting shipped via `SEVERITY_POINTS` in `safeai/severity.py` (critical 25 / high 15 / medium 8 / low 4 / info 1), consumed by `safeai/scoring/engine.py`; category weights remain configurable (`config_weights`)
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/scoring/engine.py`, `safeai/severity.py`
- **Description:** Weighted severity now drives the trust score; the original equal-weight-per-category note is superseded.

---

## Documentation

### 24. Improve architecture diagram
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `ARCHITECTURE_FOR_CONTRIBUTORS.md`

### 25. Add framework-specific documentation page
- **Status:** ✅ Complete — `docs/reference/FRAMEWORK_SUPPORT.md` (565 lines) covers all 19 frameworks with detection coverage, test coverage, and limitations
- **Difficulty:** Easy | **Effort:** 3–4 hours

### 26. Improve installation guide for Windows users
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `USER_GUIDE.md`

### 27. Add FAQ with common troubleshooting scenarios
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `USER_GUIDE.md`

### 28. Add glossary of terms
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `GLOSSARY.md`

### 29. Create video or animated GIF guide for scan workflow
- **Difficulty:** Medium | **Effort:** 4–6 hours

---

## Config-File Adapters

### 30. Add Windsurf config-file adapter
- **Difficulty:** Easy-Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/frameworks/windsurf/__init__.py` (new), `safeai/frameworks/windsurf/parser.py` (new), `safeai/frameworks/__init__.py` (register), `safeai/engine/orchestrator.py` (add `.windsurfrules` to `_is_scannable_file`), `tests/test_windsurf_framework.py` (new), `tests/fixtures/windsurf/representative/.windsurfrules` (new)
- **Description:** Add a framework adapter for the Windsurf IDE config file (`.windsurfrules`). Follow the exact pattern of the `.cursorrules` adapter (PR [#113](https://github.com/ikaruscareer/SafeAI/pull/113)): filename-based detection, JSON/YAML/free-text structured-first parsing, capability keyword scanning (`shell`, `filesystem`, `external_apis`, `databases`), tool/model extraction, unrestricted grant detection, MCP reference detection. Register via `@register_parser`. Write tests covering JSON parsing, YAML parsing, free-text fallback, detection by filename, and integration with `run_scan()`. Maps to v2.0.0 config-file coverage in `ROADMAP.md`.

---

## Governance Depth

### 31. Detect runaway-loop / recursion-guard governance signals
- **Difficulty:** Medium | **Effort:** 4–5 hours
- **Suggested files:** `safeai/analyzers/governance/analyzer.py`, `safeai/rules/base_rules.yaml`, `tests/test_governance_analyzer.py`
- **Description:** Add two new `GOV_*` rules to the `GovernanceAnalyzer`: `GOV_MAX_ITERATIONS_MISSING` (detects agent loops with no max-iteration bound — e.g. `while True`, recursive agent-to-agent calls without depth limit) and `GOV_RECURSION_GUARD_MISSING` (detects recursive tool calls without a recursion depth guard). Follow the existing pattern in `GovernanceAnalyzer`: regex detection over Python source, per-tool dedup, ±10-line source confirmation. Add rules to `base_rules.yaml` with appropriate severity (`high` for unbounded loops, `medium` for missing recursion guards). Map both to OWASP LLM06 and OWASP Agentic in `RULE_MAPPINGS`. Write tests covering detection, dedup, and rule mapping. Maps to v2.0.0 governance depth in `ROADMAP.md`.

---

## Registry

### 32. Add `safeai registry import` command
- **Difficulty:** Medium | **Effort:** 4–5 hours
- **Suggested files:** `safeai/cmd/cli.py`, `safeai/kya/exporter.py`, `tests/test_registry_cli.py`
- **Description:** Implement `safeai registry import <file>` to complete the portable registry export/import cycle. `registry export` already produces a portable, source-safe JSON inventory (`safeai/kya/exporter.py`); `import` should read that JSON and merge agent records into the local SQLite registry (`SAFEAI_REGISTRY` or `~/.safeai/registry.db`). Import must: skip duplicate agents (match on `agent_id`), merge `agent_metadata` fields (business owner, technical owner, environment), merge `component_snapshots` (dedup by component identity), merge `finding_lifecycle` events (dedup by finding fingerprint), merge `agent_tool_snapshots` (dedup by tool identity), and record the import in the scan history. Add `--dry-run` flag to preview what would be imported without writing. Add `--force` flag to overwrite existing metadata. Write tests covering: import of a valid export, idempotent re-import (no duplicates), metadata merge, dry-run output, and error handling for corrupt/invalid JSON. Maps to CE 2.0 portable registry in `ROADMAP.md`.

---

## Security Reviews & Tests

Newest batch — issue-driven security review and test-hardening tasks for the v2.4.x authority/exception/release surfaces. Each lists exact files, threat cases, and acceptance criteria.

### 54. Security review: exception scope-escape paths (#196)
- **Difficulty:** Easy | **Effort:** 2 hours
- **Labels:** good first issue, security
- **Suggested files:** `safeai/kya/exceptions.py`, `tests/test_exceptions.py`
- **Description:** Verify traversal-style `target_id` values (`../`, absolute paths, Windows `..\\`), legacy-key ambiguity, and cross-project exceptions can never resolve to `active`. Fail-closed: unknown scope = not applied.

### 55. Security review: authority gate fail-closed guarantees (#197)
- **Difficulty:** Easy-Medium | **Effort:** 2–3 hours
- **Labels:** good first issue, security
- **Suggested files:** `safeai/analysis/capability_diff.py`, `safeai/cmd/postprocess.py`, `tests/test_authority_change.py`, `tests/test_unknown_authority.py`
- **Description:** Lock non-zero exit for: confirmed authority change with `--fail-on-authority-change`, UNKNOWN authority under `block`, and mixed inferred/confirmed additions (`inferred_only` must not mask confirmed tools).

### 56. Security test: HTML report injection fixtures (#198)
- **Difficulty:** Easy | **Effort:** 2 hours
- **Labels:** good first issue, security, test-coverage
- **Suggested files:** `safeai/report/html.py`, `safeai/report/html_kit.py`, `tests/test_html_report.py`
- **Description:** Seed `<script>`, attribute-breakout, and table-breakout payloads through findings into rendered HTML; assert every call site escapes (`html_kit` promises call-site escaping — prove it).

### 57. Security test: terminal escape-sequence sanitization (#199)
- **Status:** ✅ Complete — `_sanitize()` at all terminal print sites + residual-ESC backstop, `tests/test_terminal_report.py` (@chenzeyan54-commits, PR #203)
- **Difficulty:** Easy | **Effort:** 2 hours
- **Labels:** good first issue, security, test-coverage
- **Suggested files:** `safeai/report/terminal.py`, `tests/test_terminal_report.py` (new)
- **Description:** ANSI/OSC sequences in file paths and finding messages print raw today. Add `_sanitize()` at print sites; payloads must not clear the screen or set terminal titles; clean input stays byte-identical.

### 58. Security test: PR comment markdown injection (#200)
- **Status:** ✅ Complete — `sanitize_pr_text()` over composed comment output + `tool_key` backtick neutralization (@HarshRajSinghania, PR #204)
- **Difficulty:** Easy | **Effort:** 2 hours
- **Labels:** good first issue, security, test-coverage
- **Suggested files:** `safeai/report/pr_comment.py`, `tests/test_pr_comment.py`
- **Description:** Composed comment bodies must not allow code-fence breakouts, markdown links from finding paths, or `@mention` spam originating from scanned content; 60-line cap must hold under injection attempts.
### 59. Security review: release workflow supply-chain posture tests
(#201)
- **Status:** ✅ Complete — fail-fast posture tests, id-token scoping, promote-signed-artifact publish with PyPI sidecar staging (@thadidaniel-ctrl, PR #206)
- **Difficulty:** Easy | **Effort:** 2 hours
- **Labels:** good first issue, security, test-coverage
- **Suggested files:** `.github/workflows/release.yml`, `tests/test_release_workflow.py`
- **Description:** Extend the existing posture suite across all jobs: every `uses:` SHA-pinned, no `continue-on-error`/`|| true` on the signing path, no post-sign artifact re-fetch, `id-token: write` scoped to sign/publish only.

---

## ✅ Completed Issues

These issues have been implemented by community contributors and are now part of the main codebase.

### Framework Adapters

| # | Issue | Contributor |
|---|-------|-------------|
| 1 | Add Google ADK detector | ikaruscareer |
| 2 | Add Mastra detector | ikaruscareer |
| 3 | Add Haystack detector | ikaruscareer |
| 5 | Add n8n workflow detector | ikaruscareer |
| 6 | Improve CrewAI parser — extract tool definitions | ikaruscareer |
| 8 | Add Dify detector | ikaruscareer |
| — | Add `.cursorrules` config-file adapter | @i-safonoff (PR #113) |
| #155 | Add OpenClaw and GitHub Copilot config-file adapters | @YaoSong808 (PR #159) |

### Capability Detection

| # | Issue | Contributor |
|---|-------|-------------|
| 12 | Detect Docker capability | @yugaaank (PR #2) |
| 13 | Detect Kubernetes capability | @yugaaank (PR #2) |
| 14 | Detect Redis capability | @yugaaank (PR #2) |
| 15 | Detect S3 / cloud storage access | @yugaaank (PR #2) |
| 16 | Detect GCP / Google Cloud services | @yugaaank (PR #2) |
| 17 | Detect Slack integration | @yugaaank (PR #2) |
| 18 | Detect Jira integration | @yugaaank (PR #2) |
| 19 | Detect browser automation capability | @yugaaank (PR #2) |
| — | Detect hidden instructions in MCP tool descriptions | @Solarthis (PR #107) |

### Reports, Output & Scoring

| # | Issue | Contributor |
|---|-------|-------------|
| 16 | Improve terminal output readability | SafeAI (v1.4) |
| 17 | Improve HTML report — add filtering and search | SafeAI (v1.4-b) |
| 23 | Tune trust score weighting for critical/high findings | SafeAI (v1.4) |
| 25 | Add framework-specific documentation page | SafeAI (v2.3.0) |
| — | Add `rule_coverage_summary()` for control-mapping gaps | @i-safonoff (PR #112) |

### Prompt Rules

| # | Issue | Contributor |
|---|-------|-------------|
| 7 | Detect unsafe prompt instruction patterns | SafeAI (v1.8) |
| 8 | Detect unrestricted instruction overrides | SafeAI (v1.8) |
| 9 | Detect hidden system prompt injection | SafeAI (v1.8) |
| 10 | Detect prompt extraction attempts | SafeAI (v1.8) |

### Governance Signals

| # | Issue | Contributor |
|---|-------|-------------|
| 11 | Detect timeout configuration | SafeAI (v1.9.0) |
| 12 | Detect retry policy configuration | SafeAI (v1.9.0) |
| 13 | Detect approval workflow requirement | SafeAI (v1.9.0) |
| 14 | Detect audit logging configuration | SafeAI (v1.9.0) |
| 15 | Detect rate limiting configuration | SafeAI (v1.9.0) |

### Data-Flow & Governance

| # | Issue | Contributor |
|---|-------|-------------|
| — | Interprocedural data-flow tracking (follow taint one call deep) | @ARAVIND281 (PR #110) |
| — | Resolve Claude Code permission evaluation order | @ARAVIND281 (PR #111) |

### Security Reviews & Tests

| # | Issue | Contributor |
|---|-------|-------------|
| #199 | Terminal escape-sequence sanitization | @chenzeyan54-commits (PR #203) |
| #200 | PR comment markdown injection sanitization | @HarshRajSinghania (PR #204) |
| #201 | Release workflow supply-chain posture tests | @thadidaniel-ctrl (PR #206) |

---

## Test Fixtures & Compatibility

### 33. Expand golden fixtures to all framework adapters
- **Difficulty:** Easy | **Effort:** 1–2 hours per framework
- **Suggested files:** `tests/fixtures/<framework>/representative/`, `tests/test_compatibility.py`
- **Description:** The compatibility test suite has golden fixtures for 10 of 17 framework adapters (Claude Code, CrewAI, LangGraph, Cursor Rules, Windsurf, n8n, LlamaIndex, Google ADK, OpenAI Agents, Semantic Kernel). Add representative fixtures and golden tests for the remaining 7: Azure Foundry, Bedrock Agent, Dify, Haystack, LangChain, Mastra, Microsoft Agent.
- **Acceptance criteria:**
  1. Create `tests/fixtures/<framework>/representative/` with a minimal source file
  2. Add a `Test<Framework>Golden` class in `tests/test_compatibility.py` following the existing pattern
  3. All 36+ tests pass (`pytest tests/test_compatibility.py`)

### 34. Add MCP tool-pattern golden fixtures
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `tests/fixtures/mcp/`, `tests/test_compatibility.py`
- **Description:** Add golden fixtures for representative MCP patterns: clean server, poisoned tool description, missing auth, exposed endpoint. Test that the MCP analyzer produces expected findings for each.
- **Acceptance criteria:**
  1. Create `tests/fixtures/mcp/golden/` with 4 representative `.json` files
  2. Add `TestMCPToolPatterns` class in `tests/test_compatibility.py`
  3. All tests pass

### 35. Scan LangChain and share results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/langchain/`
- **Description:** Scan the LangChain repository with SafeAI and share your results. This helps us understand SafeAI's coverage of one of the most popular LLM frameworks.
- **Acceptance criteria:**
  1. Clone `langchain-ai/langchain`
  2. Run `python -m safeai scan /tmp/langchain --html langchain.html --scorecard langchain-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/langchain/` with your results
  4. Add a README.md summarizing your findings (use `community-scans/reports/template/README.md` as a template)
  5. Document any false positives in `false-positives.md` (see [Reporting False Positives](#reporting-false-positives))
  6. Submit a PR

### 36. Scan AutoGen and share results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/autogen/`
- **Description:** Scan the Microsoft AutoGen repository with SafeAI and share your results. AutoGen is a popular multi-agent framework.
- **Acceptance criteria:**
  1. Clone `microsoft/autogen`
  2. Run `python -m safeai scan /tmp/autogen --html autogen.html --scorecard autogen-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/autogen/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 37. Scan Haystack and share results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/haystack/`
- **Description:** Scan the Haystack repository with SafeAI and share your results. Haystack is a popular RAG framework.
- **Acceptance criteria:**
  1. Clone `deepset-ai/haystack`
  2. Run `python -m safeai scan /tmp/haystack --html haystack.html --scorecard haystack-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/haystack/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 38. Scan DSPy and share results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/dspy/`
- **Description:** Scan the DSPy repository with SafeAI and share your results. DSPy is a popular framework for programming with LLMs.
- **Acceptance criteria:**
  1. Clone `stanfordnlp/dspy`
  2. Run `python -m safeai scan /tmp/dspy --html dspy.html --scorecard dspy-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/dspy/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 39. Scan MetaGPT and share results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/metagpt/`
- **Description:** Scan the MetaGPT repository with SafeAI and share your results. MetaGPT is a popular multi-agent framework.
- **Acceptance criteria:**
  1. Clone `geekan/MetaGPT`
  2. Run `python -m safeai scan /tmp/metagpt --html metagpt.html --scorecard metagpt-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/metagpt/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 40. Scan 5 frameworks and compare results
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `community-scans/reports/<your-username>/comparison/`
- **Description:** Scan 5 different frameworks (your choice) and create a comparison report. This helps us understand how SafeAI performs across different framework architectures.
- **Acceptance criteria:**
  1. Choose 5 frameworks from the target list
  2. Scan each framework with SafeAI
  3. Create `community-scans/reports/<your-username>/comparison/` with:
     - Individual scan results for each framework
     - A `COMPARISON.md` file comparing:
       - Trust scores across frameworks
       - Types of findings detected
       - Capabilities detected
       - Any patterns you noticed
  4. Document any false positives in `false-positives.md`
  5. Submit a PR

### 41. Test SafeAI against a framework not in the target list
- **Difficulty:** Easy | **Effort:** 1 hour
- **Suggested files:** `community-scans/reports/<your-username>/<framework>/`
- **Description:** Scan an AI framework that's NOT in our target list. This helps us discover new frameworks and expand coverage.
- **Acceptance criteria:**
  1. Choose an AI framework not in `community-scans/targets.yml`
  2. Scan it with SafeAI
  3. Create `community-scans/reports/<your-username>/<framework>/` with your results
  4. Add a README.md summarizing:
     - What you found
     - Whether SafeAI detected the framework
     - Any issues or suggestions
  5. Document any false positives in `false-positives.md`
  6. Submit a PR with your results AND a suggestion to add the framework to targets.yml

### 42. Create a scan automation script
- **Difficulty:** Medium | **Effort:** 2 hours
- **Suggested files:** `scripts/scan_framework.py`
- **Description:** Create a script that automates scanning multiple frameworks and generates a comparison report. This would make it easier for contributors to scan many frameworks.
- **Acceptance criteria:**
  1. Create `scripts/scan_framework.py` that:
     - Takes a list of framework names or URLs
     - Clones each framework
     - Runs SafeAI scan
     - Collects results
     - Generates a comparison report
  2. Add usage instructions to `community-scans/SCAN_AND_SHARE.md`
  3. Test with at least 3 frameworks
  4. Submit a PR

### 43. Add framework-specific scan tips
- **Difficulty:** Easy | **Effort:** 1 hour
- **Suggested files:** `community-scans/FRAMEWORK_TIPS.md`
- **Description:** Document framework-specific tips for scanning. Some frameworks require special handling (e.g., monorepos, large codebases, unusual directory structures).
- **Acceptance criteria:**
  1. Scan at least 3 frameworks and document any issues or special handling required
  2. Create `community-scans/FRAMEWORK_TIPS.md` with:
     - Framework-specific scan commands
     - Known issues and workarounds
     - Expected scan times
     - Tips for interpreting results
  3. Submit a PR

---

## Framework Validation

### 47. Scan a LangGraph project and report results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/langgraph/`
- **Description:** Run SafeAI against a public LangGraph project and report the results. LangGraph is a stateful agent orchestration framework.
- **Acceptance criteria:**
  1. Clone `langchain-ai/langgraph`
  2. Run `python -m safeai scan /tmp/langgraph --html langgraph.html --scorecard langgraph-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/langgraph/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 48. Scan a CrewAI project and report results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/crewai/`
- **Description:** Run SafeAI against a public CrewAI project and report the results. CrewAI is a popular multi-agent framework.
- **Acceptance criteria:**
  1. Clone `crewAIInc/crewAI`
  2. Run `python -m safeai scan /tmp/crewai --html crewai.html --scorecard crewai-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/crewai/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 49. Scan an MCP server and report results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/mcp-server/`
- **Description:** Run SafeAI against a public MCP server and report the results. This tests SafeAI's MCP analysis capabilities.
- **Acceptance criteria:**
  1. Find and clone a public MCP server repository
  2. Run `python -m safeai scan /tmp/mcp-server --html mcp-server.html --scorecard mcp-server-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/mcp-server/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 50. Scan a Claude Code project and report results
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** `community-scans/reports/<your-username>/claude-code/`
- **Description:** Run SafeAI against a public Claude Code project and report the results. Claude Code has deep analysis support in SafeAI.
- **Acceptance criteria:**
  1. Find and clone a public Claude Code project
  2. Run `python -m safeai scan /tmp/claude-code --html claude-code.html --scorecard claude-code-scorecard.md --no-registry`
  3. Create `community-scans/reports/<your-username>/claude-code/` with your results
  4. Add a README.md summarizing your findings
  5. Document any false positives in `false-positives.md`
  6. Submit a PR

### 51. Find one SafeAI false positive
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** N/A (report via GitHub issue)
- **Description:** Find one SafeAI false positive — a finding that SafeAI reports but is actually correct behavior. This is extremely valuable for improving SafeAI's accuracy.
- **Acceptance criteria:**
  1. Choose a project to scan (your own or a public one)
  2. Run SafeAI scan and review findings
  3. Identify one finding you believe is a false positive
  4. Document the false positive with evidence
  5. Create a GitHub issue with title `False positive: [rule_id] in [file]`

### 52. Find one capability SafeAI misses
- **Difficulty:** Easy | **Effort:** 30 minutes
- **Suggested files:** N/A (report via GitHub issue)
- **Description:** Find one capability that SafeAI fails to detect — a security-relevant feature in a framework that SafeAI doesn't identify. This is extremely valuable for expanding coverage.
- **Acceptance criteria:**
  1. Choose a framework to analyze
  2. Identify a security-relevant capability it has
  3. Run SafeAI scan to confirm it's not detected
  4. Document the missed capability with evidence
  5. Create a GitHub issue with title `Missed capability: [capability] in [framework]`

### 53. Compare SafeAI findings with actual tool permissions
- **Difficulty:** Easy | **Effort:** 1 hour
- **Suggested files:** N/A (report via GitHub issue)
- **Description:** Compare SafeAI's static analysis findings with a project's actual tool permissions and configuration. This validates whether SafeAI's findings align with real-world security posture.
- **Acceptance criteria:**
  1. Choose a project that uses tools/agents
  2. Run SafeAI scan
  3. Analyze the project's actual tool permissions
  4. Compare findings with actual permissions
  5. Document your comparison
  6. Create a GitHub issue with title `Permission comparison: [project name]`

---

## Reporting False Positives

False positives are findings that SafeAI reports but are actually safe behavior. Reporting false positives is extremely valuable for improving SafeAI's accuracy.

### How to Report

1. Create a `false-positives.md` file in your scan results directory
2. For each false positive, include:
   - **Rule ID** (e.g., `CAP_shell_execution`)
   - **File and line number** (e.g., `app.py:42`)
   - **What SafeAI reported** (e.g., "Shell execution detected")
   - **Why you believe it's a false positive** (e.g., "This is a fixed command, not user-controlled")
   - **Evidence** (e.g., the actual code context)
3. Reference this in your PR description

### Example

```markdown
# False Positives

## 1. CAP_shell_execution in app.py:42

**What SafeAI reported:** Shell execution detected
**Why it's a false positive:** This is a fixed command running `git status`, not user-controlled input
**Evidence:**
```python
import subprocess
result = subprocess.run(["git", "status"], capture_output=True)  # Fixed command
```
```

---

## Release Pipeline

### 44. Add support-matrix consistency check to release checklist
- **Difficulty:** Easy | **Effort:** 1–2 hours
- **Suggested files:** `.github/workflows/release.yml` (checklist job), `scripts/check_release.py`
- **Description:** Add a step to the release checklist that verifies `SUPPORT_MATRIX.md` is consistent with the actual codebase: adapter count matches `discover_parsers()` output, Python version classifiers match `pyproject.toml`, Action I/O matches `action.yml`. Fail the pipeline if any mismatch is found.
- **Acceptance criteria:**
  1. New step in `release.yml` checklist job compares adapter count in `SUPPORT_MATRIX.md` against runtime parser count
  2. New step compares Action I/O in `SUPPORT_MATRIX.md` against `action.yml`
  3. Mismatches cause the pipeline to fail with a clear error message
  4. Add the same check to `scripts/check_release.py`

### 45. Add fixture coverage completeness check to release checklist
- **Difficulty:** Easy | **Effort:** 1–2 hours
- **Suggested files:** `.github/workflows/release.yml` (checklist job), `tests/test_compatibility.py`
- **Description:** Add a step to the release checklist that verifies every adapter registered via `discover_parsers()` has a corresponding golden fixture directory under `tests/fixtures/`. Fail the pipeline if any adapter is missing fixtures.
- **Acceptance criteria:**
  1. New step in `release.yml` checklist job iterates `discover_parsers()` and checks for `tests/fixtures/<name>/` directory
  2. Missing fixtures cause the pipeline to fail with a clear error message listing the missing adapters
  3. Add a `test_fixture_coverage_completeness` test in `tests/test_compatibility.py`

### 46. Wire check_release.py into the release pipeline
- **Difficulty:** Easy | **Effort:** 1 hour
- **Suggested files:** `.github/workflows/release.yml`, `scripts/check_release.py`
- **Description:** The standalone `scripts/check_release.py` script duplicates some checks from the inline pipeline steps but is never invoked by the workflow. Add a step to the checklist job that runs `python scripts/check_release.py` to consolidate all pre-release checks in one place.
- **Acceptance criteria:**
  1. New step in `release.yml` checklist job: `run: python scripts/check_release.py`
  2. `check_exit_code` script exits non-zero on any failure
  3. Pipeline fails if the script reports inconsistencies

---

## Detailed Templates

Each issue above has a corresponding YAML template in `.github/good-first-issues/` with the full description, acceptance criteria, and labels. Run the GitHub Actions workflow to create them all in the issue tracker at once.

## How to Claim an Issue

1. Find an issue in the [GitHub issue tracker](https://github.com/ikaruscareer/SafeAI/issues) labeled `good first issue`
2. Comment to let others know you're working on it
3. Ask questions if anything is unclear
4. Submit a draft PR early for feedback
5. Reference the issue in your PR description

**All first-time contributors are welcome.** If you're unsure where to start, pick the smallest issue that interests you and start there.
