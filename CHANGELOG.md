# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v2.5 IaC Authority Evidence (Lane B)

- Explicit authority graph (`safeai/iac/model.py`, ADR-0009):
  Identity (kind/name/namespace), Grant (per-field
  resolved/partially-resolved/unresolved), GrantBinding chains,
  AgentIdentityLink (workload/config evidence only), and verdicts
  carrying agent, identity, declared, grant, and link evidence refs.
- Terraform relationship extraction: identities, policy statements
  (inline, attached, data-document-inherited), Role → policy →
  statement bindings; attachments are relationships, never fake
  permissions; trust policies excluded; managed/external/module
  content recorded unresolved, never guessed.
- Kubernetes RBAC chains: ServiceAccount → Binding → Role → rule
  with namespace isolation, cluster scope, multi-subject/rule
  support, workload references, and dangling-reference honesty.
- Identity-link resolver: workload `serviceAccountName` and explicit
  config references (role ARNs, identity keys) with file:line
  evidence; string coincidence never links (namespace-aware).
- Semantic matcher: provider/service/operation-class comparison with
  conservative wildcard reasoning; un-normalizable semantics →
  UNKNOWN. Strict verdicts: MATCH (evidenced link + compatible
  resolved grant), EXCESS (linked grant strictly beyond need),
  MISMATCH (authoritatively visible absence only), UNVERIFIED_LINK
  (ambiguous default), UNKNOWN (preferred over false conclusions).
- Orchestrator `collect_iac_evidence()` first-class stage;
  assurance-boundary IaC inspection notes; manifest
  `iac_correlations` schema v2 + summary counts (additive, Contract
  v1 + JSON schema validate verdicts, evidence refs, Lane B);
  PR "Infrastructure authority" Lane-B section inside the 60-line
  cap with control-character sanitization.
- Benchmark corpus (`tests/fixtures/iac/benchmark/catalog.yml`:
  Terraform, Kubernetes, linking, verdict cases) with a
  precision/recall harness, adversarial tests, and invariant
  extensions (IaC never gates; unresolved shadows absence claims).
  Findings `IAC_EXCESS_AUTHORITY` / `IAC_AUTHORITY_MISMATCH` /
  `IAC_UNVERIFIED_LINK` remain `repo-iac-observed` / `review-only`;
  no new gates, no exit-code changes, no new dependencies.

### Added — v2.4.x Security Architecture Hardening

- Release pipeline signs *and* verifies: `cosign verify-blob` against
  the artifact with the expected repository identity and OIDC issuer
  runs before asset preparation; verification failure blocks publish.
  `cosign-release` pinned explicitly to v2.6.1; `tests/test_release_workflow.py`
  statically asserts SHA pins, the verify stage, and fail-closed wiring.
- Governable UNKNOWN authority: policy-file `authority: unknown`
  (`allow | warn | require_review | deny`), `--unknown-authority
  pass|review|block` CLI fallback (explicit file setting wins), and an
  optional `unknown-authority` GitHub Action input. Default behavior
  unchanged: UNKNOWN never fails alone and is never shown as safe.
- Authority dimension block on capability-diff tool entries
  (`capabilities`, `destinations`, `data_scope`, `approval`, `autonomy`,
  `delegation` with per-dimension provenance; `credential`/`identity`
  honestly `unknown`), plus semantic `change_types` derived from
  escalation ids and structural status.
- Manifest evidence: top-level `exception_evaluations` (id, target,
  state, owner, expiry) and `authority_changes` entries plus
  `summary.authority_change_counts` / `summary.highest_change_class`
  (additive; Contract v1 + JSON schema validate the new enums).
- PR comments separate CI-gate escalations from a **Human review**
  Lane-B questions section inside the 60-line cap; data-flow paths
  remain heuristic-labelled and gate-inert.
- Exception model: explicit `target_type` (`finding | policy |
  escalation | authority_change`) + `target_id` with legacy
  `finding_or_policy` back-compat; distinct `scope-mismatch` and
  `invalid` states; review triggers documented as metadata-only.

## [2.4.0] - 2026-09-21

**Agent Authority ChangeGuard precision and evidence hardening.**

### Added — Review decision lanes (WS1)

- Lane A (deterministic gates) vs Lane B (mandatory-review questions):
  `evaluate_policy` publishes canonical outcomes (`pass | warn |
  review-required | block`) mapped from the policy-DSL actions, plus the
  winning `action`, `lane`, per-match lanes, and a `lanes` summary.
  Terminal prints Lane-B matches as review questions; gates print
  verdicts — never blended.
- Review floor: new-or-changed prompt/config-definition findings
  (`PROMPT_*`, `PROMPT_FILE_*`, `SKILL_*`, `TOOL_DEF_*`, `MODEL_CONFIG_*`,
  `WORKFLOW_*`, `CC_*`) resolve to at least `require_review`, never
  `pass` — even with zero other matches.
- Fixed: SafeAI's own manifests failed Contract v1 validation on every
  non-`warn` policy outcome (`deny`/`require_review`/`allow` are not
  contract outcomes). Decisions now publish mapped outcomes, so
  `safeai manifest validate` accepts real scan output.

### Added — Material-change classification and authority gate (WS2)

- Per-tool `change_class` (`NO_CHANGE | LOW_CHANGE | MATERIAL_CHANGE |
  HIGH_RISK_CHANGE | UNKNOWN`, never a score) with `inferred_only`
  tracking, `by_change_class` counts, and `highest_change_class` on the
  capability diff. UNKNOWN (unattributed baselines) never fails a gate.
- New `--fail-on-authority-change material|high-risk` gate (requires
  `--baseline`); inferred-only changes never trip it. Wired through the
  GitHub Action (`fail-on-authority-change` input) and `extra-args`.

### Added — Evidence hardening (WS3)

- Per-finding `provenance_class` (`declared | detected | inferred |
  unknown`) and `gateability` (`deterministic | review-only`) attached
  at normalization, carried in manifests, validated by Contract v1 and
  the manifest JSON schema (optional, backward-compatible enums).
- Registry schema v7 (additive): `scan_findings.provenance_class` and
  `scan_findings.gateability` columns; pre-v2.4 rows read NULL.
- Deterministic report generation covered by double-scan digest test.

### Added — File-backed exception schema (WS4)

- `.safeai/exceptions.yml` records: `exception_id`, `finding_or_policy`,
  scope, named `risk_owner`, `rationale`, `compensating_controls`,
  `expires_at`, `review_trigger`. Expired or stale (nothing live matches)
  exceptions warn on stderr by default; `--strict-exceptions` fails the
  scan (exit 1). Invalid files are hard errors — silent exceptions are
  never permitted.

### Added — Source-to-destination paths in PR output (WS5)

- New-or-regressed `DATAFLOW_*` paths render alongside escalations in
  `--pr-comment` inside the existing 60-line cap, labelled heuristic
  and single-file. No heuristic fails a Lane-A gate on its own.

## [2.3.0] - 2026-09-16

**Plugin SDK and Rule Ecosystem (CE 2.3).**

### Added — CE 2.3 Plugin SDK and Rule Ecosystem

- Analyzer plugin registry (`safeai.analyzers`: `@register_analyzer`,
  `discover_analyzers`, `safeai.analyzers` entry-point group) mirroring
  the parser pattern; built-in run order preserved; third-party
  analyzers run isolated and never fail a scan.
- Per-scan plugin/pack versions: manifest `safeai` block stamps
  `analyzer_versions`, `parser_versions`, and `policy_profile`;
  registry `scans` row carries `plugin_versions_json` (schema v6,
  additive migration); portable imports record NULL for pre-v2.3 exports.
- Pack lifecycle: `registry export` carries pack pins per project,
  `registry import --dry-run` warns on pin drift (advisory, never a gate).
- Lockfile-style component integrity: `registry components --lockfile`
  writes pinned `{type, name, path, content_hash}` pins,
  `--check-lockfile` exits 1 on added/removed/changed components.
- Rule-authoring scaffold: `safeai init` writes `pack_example.yaml`,
  `fixtures/` safe/risky examples, and `tests/test_pack.py`; new
  `safeai rules check [dir]` validates rules and runs expected-findings
  fixtures offline (pack rules act as overrides of built-in rule IDs).
- Community pack contract (`docs/guides/COMMUNITY_PACKS.md`): layout,
  fixture requirements, compatibility policy, pinning, sharing.
- ADR 0005: no `integrations` command namespace yet —
  `--pr-comment-post` stays the single explicit network path.

### Added

- `safeai scan --digest-file PATH` (with `--manifest`) writes a detached sidecar
  `<canonical-sha256>  <manifest-basename>` for independent-channel checks in CI.
  The digest equals the one `safeai manifest verify` reports; the sidecar is
  intentionally not `sha256sum -c` compatible.
  Thanks to [@burakeyler](https://github.com/burakeyler) (PR #148).
- OpenClaw (`.openclaw/` JSON/YAML, root `.openclaw.yaml`) and GitHub Copilot
  (`.github/copilot-instructions.md`, `.copilot/instructions.md`, `.copilot/*.yml`)
  config-file adapters with structured-first parsing, free-text fallback,
  capability scanning, and MCP server references.
  Thanks to [@YaoSong808](https://github.com/YaoSong808) (PR #159).
- Benchmark corpus expanded to 21 fixtures: new `benign-static-subprocess-limitation`
  documents the static-argument precision gap (`CAP_shell:high` fires on safe
  `subprocess.run(["git", "--version"])`).
  Thanks to [@Teachmeplaycode](https://github.com/Teachmeplaycode) (PR #174).
- Policy profile name displayed in terminal and HTML reports alongside policy
  outcome; profile omitted when absent; HTML-escaped to prevent injection.
  Thanks to [@nikitajos7](https://github.com/nikitajos7) (PR #175).

## [2.2.1] - 2026-09-12

**Release-evidence integrity + offline-boundary clarity.**

### Fixed — Release asset scoping
- Release automation uploads only artifacts built for the running tag;
  historical SBOM/provenance can no longer leak into a release.
- New `scripts/verify_release_assets.py` gate fails the release on foreign
  versions, unversioned `provenance.json`, missing Cosign sidecars, or
  SHA256SUMS mismatches; SLSA provenance is version-named.
- Removed committed historical release evidence from `release-artifacts/`
  (generated evidence lives on GitHub Releases, not in-repo).

### Changed — Offline boundary
- Promise sharpened: "Offline and source-private by default. Network
  activity occurs only through explicitly enabled integration commands
  (currently only `--pr-comment-post`)."
- `--pr-comment-post` announces itself on stderr before requesting and
  documents token scope (`pull-requests: write`) and transmitted data
  (rendered redacted comment only) in `docs/guides/REPORTING_GUIDE.md`.

## [2.2.0] - 2026-09-12

**Contract & Proof.** Governance, trust, evidence, and developer-confidence
release: a versioned KYA manifest contract, offline integrity, structured
escalation remediation, a reproducible benchmark corpus, and public
Community/Corporate governance clarity. Offline, static, and backward
compatible throughout.

### Added — Manifest Contract v1
- Published JSON Schema `schemas/safeai-manifest/v1.0.0.json` plus
  `docs/manifest/{README,COMPATIBILITY,EXAMPLES}.md`.
- `contract{}` block on every manifest; `safeai manifest validate` (stdlib-only).

### Added — Offline Manifest Integrity
- Canonical SHA-256 digest on manifests and registry exports;
  `safeai manifest verify`; `registry import --require-integrity`
  (default off); GPG-envelope docs (`docs/manifest/INTEGRITY.md`).

### Added — Escalation Remediation
- Structured remediation for all 14 `ESC_*` rules, rendered in JSON,
  manifest, HTML, terminal, PR comment, and scorecard.

### Added — Benchmarks
- 20-fixture corpus (`benchmarks/catalog.yml`), offline runner
  (`scripts/run_benchmarks.py`), published results (`BENCHMARKS.md`).

### Added — Governance
- `DCO.md` with CI sign-off check; `docs/GOVERNANCE_AND_EDITIONS.md`;
  MCP scope/export-privacy policy; ADRs 0001–0004; re-baselined `ROADMAP.md`.

## [2.1.2] - 2026-09-09

**Cosign signing for OpenSSF Scorecard.** Adds keyless Cosign signatures to
release artifacts to satisfy the Signed-Releases check.

### Added
- Cosign keyless signing of wheel and tarball artifacts in release workflow.

## [2.1.1] - 2026-09-09

**PyPI release fix.** Version 2.1.0 was already published; bumped to 2.1.1.

### Fixed
- Release pipeline: PyPI publish step now uses trusted publishing (OIDC).
- Release pipeline: artifact paths corrected for downloaded attestations.
- Release pipeline: GitHub release created before artifact upload.

## [2.1.0] - 2026-09-09

**CI/CD Hardening & Developer Experience.** Makes SafeAI a true CI gate with
rich developer feedback, brings governance into the IDE, and makes installation
trivial with standalone binaries.

### Added — Quality Gates
- **`--fail-on-rule`** — fail when any finding matches a rule ID pattern
  (glob-style: `GOV_*`, `MCP_*`, `ESC_*`, etc.).
- **`--fail-on-category`** — fail when any finding belongs to a category
  (security, governance, capability, dataflow, prompt, mcp, dependency).

### Added — PR Decoration Auto-Posting
- **`--pr-comment-post`** — post or update the PR comment on GitHub via the
  GitHub API. Uses marker to find and update existing comments.
- GitHub Action input `pr-comment-post` added.

### Added — Extended MCP Tool-Poisoning Detection
- **`MCP_TOOL_SCHEMA_INJECTION`** — detects hidden instructions in input_schema
  property descriptions, titles, and default values.
- **`MCP_RESOURCE_DESCRIPTION_INJECTION`** — detects hidden instructions in MCP
  resource descriptions.

### Added — Standalone Binaries
- PyInstaller spec file and build script for creating standalone binaries.
- No Python installation required for end users.

### Added — VS Code Extension MVP
- Workspace scan and file scan commands.
- Inline diagnostics (problem markers) for findings.

### Added — Test Coverage
- Golden fixtures for 7 new adapters: azure_foundry, bedrock_agent, dify,
  haystack, langchain, mastra, microsoft_agent.
- `TestFixtureCoverageCompleteness` test prevents silent coverage regression.

### Fixed
- **Issue #93** — Claude Code permission precedence correctly implements
  `deny > ask > allow`.
- **Issue #120** — SUPPORT_MATRIX.md now consistent with code.
- **Issue #121** — Fixture coverage completeness check added to release CI.
- **Issue #15** — Trust score category weights differentiated.

### Changed
- Version bumped to 2.1.0.
- 780 tests passing (up from 751 in v2.0.1).

## [2.0.1] - 2026-09-03

**Release hardening.** Consolidated release pipeline with mandatory
verification gates, GPG-signed artifacts, cross-platform verification
instructions, and pre-release checklist.

### Added

- **Consolidated release pipeline** (`.github/workflows/release.yml`) —
  6-job pipeline: checklist → build → attest → sign → publish → release.
  Every gate must pass before the next starts. Builds are pinned to the
  exact release commit SHA.
- **Pre-release checklist** — blocks publication if version string, rules,
  analyzers, compatibility tests, SARIF output, JSON report, Action I/O
  contract, failure-class matrix, or CHANGELOG entry is inconsistent.
- **GPG-signed release artifacts** — wheel, sdist, checksums, provenance,
  and SBOM are all GPG-signed with detached `.asc` signatures.
- **Cross-platform verification instructions** (`VERIFICATION.md`) —
  step-by-step GPG, checksum, and provenance verification for Linux,
  macOS, and Windows (PowerShell). Includes pip hash-checking.
- **Compatibility test suite** (`tests/test_compatibility.py`) — 36 tests
  covering golden fixtures (7 frameworks), JSON/SARIF/CLI/Action contracts,
  and adapter contract (detect/parse for all 17 parsers).
- **Golden fixtures** for Google ADK, OpenAI Agents, Semantic Kernel.
- **Release channels documentation** (`RELEASE_CHANNELS.md`).
- **Security policy** (`SECURITY.md`) with vulnerability reporting and
  response targets.
- **Support matrix** (`SUPPORT_MATRIX.md`) — Python versions, platforms,
  adapters, CI, Action I/O, exit codes, rule coverage.

### Changed

- Version bumped to 2.0.1.
- 731 tests passing (up from 695 in v2.0.0).

## [2.0.0] - 2026-09-03

**Governance Depth & Ecosystem Expansion.** Deepens governance detection with
runaway-loop and recursion-guard rules, adds Windsurf config-file adapter,
and presents governance gaps as a failure-class coverage matrix.

### Added — Runaway-loop / recursion-guard detection

- Two new `GOV_*` rules: `GOV_MAX_ITERATIONS_MISSING` (detects agent loops
  with no max-iteration bound — `while True`, recursive calls without depth
  limit) and `GOV_RECURSION_GUARD_MISSING` (detects recursive tool calls
  without a recursion depth guard).
- Both rules slot into the existing `GovernanceAnalyzer` with per-tool dedup
  and ±10-line source confirmation.
- Mapped to OWASP LLM06, OWASP Agentic AGENTIC08, and NIST AI RMF MANAGE_1.
- Severity: `high` for unbounded loops, `medium` for missing recursion guards.

### Added — Failure-class coverage matrix

- New `failure_class_matrix` section in HTML report and JSON output groups
  `GOV_*` findings by the class of failure they leave the agent unprepared
  for: dependency timeout, dependency unavailable, resource exhaustion,
  cascading failure, unbounded recursion, missing accountability.
- Shifts operator question from "which rules fired?" to "which failure modes
  can this agent survive?"
- Source: Reddit community feedback (2026-09).

### Added — Windsurf config-file adapter

- Framework adapter for `.windsurfrules` (Windsurf IDE config file).
- JSON/YAML/free-text structured-first parsing, capability keyword scanning,
  tool/model extraction, unrestricted grant detection, MCP reference detection.
- 13 tests covering detection, parsing, and integration.

### Added — Evidence type schema (v1.3)

- `evidence_type` field on every finding: `static-config` (parsed fields),
  `static-pattern` (regex matches), or `runtime-observed` (reserved, nothing
  emits it today). KYA manifest bumped to v1.3.

### Changed

- Governance analyzer now checks 10 controls (up from 8): added
  `max_iterations` and `recursion_guard`.
- 695 tests passing (up from 675 in v1.9.1).

## [1.9.1] - 2026-08-30

Post-release fixes for v1.9.0.

### Fixed

- **AGENTIC04 mojibake** — removed CJK fragment from English description in
  `safeai/controls/catalogs.py`.
- **Scoped governance source suppression** — suppression now scoped to tool
  line ±10 window, avoiding masking missing controls in poly-tool modules.
- **Removed unused regex patterns** — `_TOOL_TIMEOUT_RE`, `_TOOL_RETRY_RE`,
  `FUNCTION_PARAM_RE` cleaned up from `safeai/analyzers/governance/analyzer.py`.
- **Hardened LangGraph detection** — `detect()` now requires an import or
  `StateGraph(` call, not a bare substring match.
- **Browser rule enrichment** — added `CAP_browser_playwright`,
  `CAP_browser_selenium`, `CAP_browser_use` to `RULE_MAPPINGS` in
  `safeai/controls/mappings.py`.

### Community contributors

Thank you to the following community members for their contributions to
SafeAI v1.9.1:

- **[@i-safonoff](https://github.com/i-safonoff)** — filled missing entries
  in RULES_REFERENCE.md (PR [#108](https://github.com/ikaruscareer/SafeAI/pull/108))
  and fixed dataflow rule ID casing mismatch (PR
  [#109](https://github.com/ikaruscareer/SafeAI/pull/109)).
- **[@Solarthis](https://github.com/Solarthis)** — added MCP tool
  description injection detection (PR
  [#107](https://github.com/ikaruscareer/SafeAI/pull/107)).
- **[@ARAVIND281](https://github.com/ARAVIND281)** — implemented
  interprocedural data-flow tracking within a single file (PR
  [#110](https://github.com/ikaruscareer/SafeAI/pull/110)) and resolved
  Claude Code permission evaluation order (PR
  [#111](https://github.com/ikaruscareer/SafeAI/pull/111)).
- **[@hadbiaghiles](https://github.com/hadbiaghiles)** — added AutoGen
  to supported frameworks documentation (PR
  [#98](https://github.com/ikaruscareer/SafeAI/pull/98)).
- **[@mikemikimike](https://github.com/mikemikimike)** — added adapter
  negative detection tests (PR
  [#90](https://github.com/ikaruscareer/SafeAI/pull/90)).
- **[@asarakhatun17-lgtm](https://github.com/asarakhatun17-lgtm)** —
  fixed supported frameworks consistency (PR
  [#91](https://github.com/ikaruscareer/SafeAI/pull/91)).
- **[@mah](https://github.com/mahirhir)** — documented Claude Code deep
  analysis fixtures and detection approach (PR
  [#92](https://github.com/ikaruscareer/SafeAI/pull/92)).

## [1.9.0] - 2026-08-28

**Curated theme — "Component Depth & Ecosystem Foundations."** Carries the
remaining depth items not in v1.8.0: CE 1.6 component-record depth, CE 1.4/1.5
governance and data-flow leftovers, and CE 2.0 ecosystem foundations.

### Added — Component version/hash (WS1)

- Component `content_hash` (SHA-256, truncated to 16 chars) stored in the KYA
  registry's `component_snapshots` table (schema v5).
- `safeai registry components` CLI lists tracked components with deduplication,
  type filtering, and consuming-agent resolution.
- Hash-based `_has_changed()` in `component_diff` replaces data-equality checks.

### Added — `safeai init` + custom rule scaffold (WS2)

- `safeai init [--profile NAME] [--force]` scaffolds `.safeai/` with `config.yml`,
  `policy.yml`, `suppressions.yml`, and `rules/example_rules.yaml`.
- Identity-preserving init: existing `local_project_uuid` and `project_id` are
  never overwritten.
- `load_rules()` auto-discovers `.safeai/rules/` with validation and metadata.

### Added — Governance signal detection (WS3)

- `GovernanceAnalyzer` detects missing operational governance controls:
  timeout, retry, approval (HITL), audit logging, rate limiting, circuit breaker
  pattern, backpressure/concurrency limits, and health check/readiness probes.
- Eight rules: `GOV_TIMEOUT_MISSING`, `GOV_RETRY_MISSING`,
  `GOV_APPROVAL_MISSING`, `GOV_AUDIT_MISSING`, `GOV_RATE_LIMIT_MISSING`,
  `GOV_CIRCUIT_BREAKER_MISSING`, `GOV_BACKPRESSURE_MISSING`,
  `GOV_HEALTH_CHECK_MISSING`.
- Findings carry `risk_category: "Governance"` for scoring and reporting.
- Per-tool deduplication: same tool missing the same control produces one finding.
- Source-level confirmation scoped to tool definition ±10 lines to reduce
  false positives from poly-tool modules.

### Added — Control mappings taxonomy (WS4)

- Structured mapping layer between SafeAI rules and external control
  frameworks: OWASP Top 10 for LLM Applications (2025), OWASP Top 10 for
  Agentic Applications (2025), and NIST AI RMF 1.0.
- `map_rule_to_controls()` and `map_findings_to_controls()` API for
  framework-based filtering and grouping.
- Taxonomy only — never a compliance or coverage claim.

### Added — Adapter completion (WS5)

- AutoGen framework adapter for Microsoft AutoGen multi-agent systems.
  Detection tightened: requires import, class usage, or `register_for_llm`/
  `register_for_exec` — no bare substring match.
- LangGraph parser now detects `add_conditional_edges()` calls; detection
  tightened to require `StateGraph` — no loose `Graph(` match.
- Browser automation rules split: `CAP_browser_playwright`,
  `CAP_browser_selenium`, `CAP_browser_use`.

### Added — Heuristic data-flow depth (WS6)

- `DataFlowAnalyzer` tracks untrusted input propagation into sensitive sinks
  (prompts, tool calls, shell, file writes, HTTP requests, database queries).
- Six new rules: `DATAFLOW_prompt`, `DATAFLOW_tool_call`, `DATAFLOW_shell`,
  `DATAFLOW_file_write`, `DATAFLOW_http_request`, `DATAFLOW_database`.
- Placeholder-aware confidence: variables starting with `test_`, `example_`,
  `dummy_`, `mock_`, `fake_`, `sample_`, `fixture_`, `stub_`, `temp_`, `tmp_`
  are skipped as likely test fixtures.
- `.py`-only file filter eliminates false positives on JSON/YAML configs.

### Fixes (post-review)

- **Governance deduplication** — changed from per-rule-id to per-tool
  `(path, tool_name, rule_id)` granularity; same tool not duplicated.
- **AutoGen detection tightened** — removed loose `"autogen" in content.lower()`
  substring match; now requires import, class usage, or registration pattern.
- **LangGraph detection tightened** — removed loose `Graph(` match that
  false-positived on `networkx.Graph`.
- **DataFlow `.py`-only filter** — non-Python files (JSON, YAML configs) no
  longer produce data-flow false positives.
- **Governance source confirmation scoped** — `_find_governance_controls` now
  checks only within ±10 lines of the tool definition, not the entire file.
- **Orchestrator null guard** — `parse_frameworks` skips `None` returns from
  framework parsers.
- **Mojibake fixed** — removed CJK fragment from `AGENTIC04` description.

### Community contributors

Thank you to the following community members for their contributions to
SafeAI v1.9.0:

- **[@Aming9303](https://github.com/Aming9303)** — `safeai registry components`
  CLI (PR [#82](https://github.com/ikaruscareer/SafeAI/pull/82)) and
  `safeai init` command (PR [#83](https://github.com/ikaruscareer/SafeAI/pull/83)).
- **[@D05TL3](https://github.com/D05TL3)** — GitHub Actions scanning example
  (PR [#84](https://github.com/ikaruscareer/SafeAI/pull/84)).

## [1.7.0] - 2026-08-16

### Added — Multi-source MCP discovery

- IDE-scoped MCP config discovery for Cursor (`.cursor/mcp.json`), Windsurf
  (`.windsurf/mcp.json`), and VS Code (`.vscode/mcp.json`). Out-of-repo scopes
  are behind an explicit `--mcp-ide-scopes` flag and excluded from exports by
  default, preserving the source-private guarantee.

### Added — Named policy profiles

- Five built-in profiles: `developer`, `strict-ci`, `mcp`, `rag`,
  `production-agent`. Each profile is a composable set of policy rules that
  extends (not replaces) the user's `.safeai/policy.yml`.
- `--policy-profile NAME` loads the preset profile plus user overrides.
- Profiles documented in `POLICY.md`.

### Added — Registry freshness indicators

- Agent records now track `last_scan_timestamp` and `scan_count` in the local
  SQLite registry.
- `safeai registry list` surfaces freshness status (fresh / stale / never
  scanned).
- HTML report includes freshness indicators per agent.

### Added — Suppression CI failure

- `--strict-suppressions` fails the scan (exit 1) when expired or moved
  suppressions are detected, enabling CI enforcement of suppression hygiene.
- Expired suppressions already produce warnings; this flag promotes them to
  failures.

### Added — Component registry persistence

- Component snapshots (type, name, path, source, line, and full data JSON) are
  now stored in the local KYA registry in a new schema-v3 `component_snapshots`
  table, alongside agent and tool records, with `first_seen_scan` /
  `last_seen_scan` provenance. (Component *version/hash* columns are deferred;
  the schema records identity and last-seen, not an integrity hash yet.)
- Internal query `get_component_agents` resolves which agents reference a
  given component (via scan co-occurrence); surfaced in `component_diff` output
  and intended for a future `safeai registry components` view (not yet exposed
  as a standalone subcommand).

### Added — Component-change diffs

- When a scan detects a changed, added, or removed component (MCP configuration,
  skill, prompt, tool definition, or model config), the consuming agents are
  flagged via the `component_diff` section in the JSON report and HTML output.
  The diff is computed against the baseline scan; with no baseline, all current
  components are reported as newly added.

### Added — Framework compatibility test fixtures (community)

- LangGraph detection validation test and representative fixture (`tests/test_langgraph_framework.py`, `tests/fixtures/langgraph/representative/graph.py`). [#63]
- LlamaIndex detection validation test and representative fixture (`tests/test_llamaindex_framework.py`, `tests/fixtures/llamaindex/representative/agent.py`). [#61]
- CrewAI detection validation test and representative fixture (`tests/test_crewai_framework.py`, `tests/fixtures/crewai/representative/crew.py`). [#62]
- Claude Code project compatibility test and fixture (`tests/test_claude_code_deep.py`, `tests/fixtures/claude_code/compatibility/`). [#59]

Thanks to @adnqcr7-code for these contributions.

### Changed

- Version bumped to `1.7.0`.

## [1.8.0] - 2026-08-23

**Curated theme — "True Authority & Complete Lifecycle."** This release bundles
the remaining CE 1.4, CE 1.5, and CE 1.8 gaps into four cohesive workstreams
and is the gate for starting CE 2.0.

### Shipped — Workstream 1: Lifecycle & Ownership (CE 1.4 completion)

- **Finding Lifecycle Event Engine** — `finding_lifecycle` table (registry
  schema v4) tracking state transitions on existing fingerprints: `introduced` →
  `persisting` → `resolved` → `reopened`. `ESC_RECURRING_RISK` escalation rule
  fires when a previously resolved finding is reintroduced.
- **Stale Suppression Guard** — `detect_stale_suppressions()` in
  `safeai/kya/suppressions.py` compares a suppression's fingerprint against the
  current AST/location; `--strict-suppressions` fails when a waiver exists but
  the underlying code has materially shifted.
- **Agent Enrichment Schema** — `safeai registry metadata set <agent_id>
  --owner "platform-sec" --env "production"` stored in a dedicated
  `agent_metadata` table, decoupled from automated scan snapshots and rendered in
  the HTML report.

### Shipped — Workstream 2: Code-Level Authority (CE 1.5 completion)

- **Tool ↔ Implementation Mapping** — a correlator in `safeai/analysis/` that
  bridges `tool_def` findings with skill/capabilities and surfaces orphan states
  in reports with full declaration/implementation provenance (path, line, source).
- **Command-Aware MCP Resolution** — extend `safeai/analyzers/mcp/analyzer.py` to
  statically resolve a local MCP server `command` (e.g. `node build/index.js`,
  depth-capped, never executed), attempt static extraction on the target, and
  label output `assurance: resolved` vs `assurance: unresolved-command` vs
  `assurance: external-package` (for `npx`/`uvx`/`docker run`).
- **Target Taxonomy Engine** — extend `safeai/report/html_kit.py` and
  `json_report.py` to aggregate external-network capabilities into explicit
  buckets (Database, Object Storage, SaaS APIs) as a first-class report view.

### Shipped — Workstream 3: Detection Depth (analysis hardening)

- **Prompt risk depth** — move beyond single-line regex in `PROMPT_*` /
  `PROMPT_FILE_*` rules: multi-line prompt concatenation detection, cross-file
  prompt interpolation (prompt file read and interpolated into code), indirect
  injection via tool calls embedded in prompts, XML/HTML tag injection
  (`<system>`, `</system>`) in prompts, template variable injection in `.md`
  files. Heuristic detectors use hedged language to avoid overclaiming.
- **Data leakage depth** — expand `DATA_LEAKAGE` beyond the 4 basic patterns:
  private keys (`-----BEGIN RSA PRIVATE KEY-----`), JWT tokens (`eyJ...`),
  AWS access keys (`AKIA...`), connection strings (`mongodb://`, `postgres://`),
  base64-encoded secrets, hex-encoded secrets. Per-pattern severity
  differentiation (private keys = critical, connection strings = high).
- **Cross-component analysis** — new `safeai/analysis/component_graph.py` that
  analyzes relationships between components with deterministic output (sorted
  edges, adjacency lists, and summary keys).

### Shipped — Workstream 4: Community & Onboarding

- **Community scans expansion** — expanded from 5 to 25 AI tool targets across
  all categories (workflow platforms, LLM frameworks, multi-agent, RAG, stateful
  orchestration).
- **First-time user experience** — `safeai welcome` guided first-run command
  displaying recommended rules, first scan instructions, result interpretation,
  registry commands, and documentation links.

### Definition of done

- All CE 1.4, CE 1.5, and CE 1.8 items in ROADMAP.md can be confidently marked ✅ shipped.
- Prompt injection detection covers multi-line, cross-file, and indirect
  injection patterns; data leakage covers private keys, JWT, AWS keys, and
  connection strings with per-pattern severity.
- Cross-component relationships (skill→tool→workflow→MCP→model) are analyzed
  and surfaced in reports.
- A reviewer can see, for any tool or MCP server, where it is declared and
  where it is implemented, and SafeAI flags mismatches. Suppressions are
  provably valid against the current code, and every finding carries its
  longitudinal history — unblocking CE 2.0 (Plugin SDK & Static IaC
  Correlation).

### Fixes (post-review)

- **Lifecycle provenance** — resolved lifecycle rows now preserve last-known
  `file_path` and `line` from `scan_findings`; `previous_event` uses actual
  history instead of hardcoded value.
- **Tool provenance** — orphan findings now include declaration/implementation
  source path and line when available; summary includes deterministic mappings.
- **Deterministic output** — component graph and target taxonomy output is
  deterministic independent of input ordering (sorted edges, adjacency, buckets).
- **Heuristic wording** — prompt detectors use hedged language ("pattern detected",
  "may enable") to avoid overstating confidence; severity adjusted for
  `PROMPT_INDIRECT_INJECTION` (high→medium) and `PROMPT_XML_INJECTION` (medium→low).

## [1.6.0] - 2026-08-13

### Added — SafeAI Security Scorecard

- **Security Scorecard** (`safeai/scorecard.py`): a deterministic, auditable
  0–10 report that summarises a scan into an overall score, per-category
  scores, and a `pass`/`warn`/`fail` outcome. It is a Scorecard-style report,
  **not** an OpenSSF Scorecard report, and says so in every rendering.
- **Scoring model** (documented in-module): severity weights
  `critical=4.0, high=2.0, medium=0.75, low=0.25, info=0.0`, diminishing
  returns for repeated findings at the same `(rule_id, file, line)`, and
  fingerprint deduplication. Suppressed findings are excluded from the score
  and from gating.
- **Five new scan flags**: `--scorecard`/`--scorecard-md` (Markdown),
  `--scorecard-json` (JSON), `--scorecard-summary` (append to the GitHub
  Actions step summary via `$GITHUB_STEP_SUMMARY`), and
  `--scorecard-fail-under N` (fail the scan when the score is below `N`,
  validated to `[0, 10]`).
- **Machine-readable contract** (`safeai/scorecard-schema.json`,
  `schema_version: 1`) with `additionalProperties: false` on the `policy`,
  `coverage`, and finding objects so producer/consumer drift fails validation.
- **Injection-safe rendering**: all untrusted finding text is Markdown-escaped
  and secret-redacted before it reaches the report or the job summary.
- Robustness: malformed finding input (non-numeric `line`, unknown severity,
  unrecognised `--fail-on`) never crashes the scorecard; an unknown fail-on
  threshold fails closed. ~55 scorecard tests in `tests/test_scorecard.py`.

### Added — Community Scan programme (private pilot)

- **`community-scans/`**: a governed workflow for scanning public third-party
  agent frameworks and disclosing results responsibly. Includes the target
  manifest (`targets.yml` + `targets-schema.json`), `methodology.md`,
  `disclosure-policy.md`, `private-pilot.md`, and a pinned-dependency
  `requirements.txt`.
- **Pipeline scripts** (`community-scans/scripts/`): `validate_targets.py`
  (read-only GitHub API validation, path-traversal-safe refs), `resolve_meta.py`
  (pin a target to a 40-char commit SHA), `build_scan_manifest.py` (provenance
  manifest), `sanitise_report.py` (redact a private report into a public-safe
  summary), and `render_reddit_draft.py` (human-review disclosure drafts).
- **Workflows**: `.github/workflows/community-scan.yml` (SHA-pinned actions,
  `contents: read` only, concurrency group, 30-minute timeout, private/public
  artifact split) and `.github/workflows/validate-community-scan.yml`.
- Nothing is published automatically; every report is private by default and
  requires human review before any external disclosure.

### Added — CLI version support & developer guide

- **`safeai/version.py`**: single source of truth for the version string
  (`SAFEAI_VERSION`) plus `version_requested()`/`print_version()` helpers.
  `safeai --version` / `-V` prints a stable machine-readable line.
- **`DEVELOPER_GUIDE.md`**: local development and GitHub Actions usage guide,
  including the Security Scorecard flags.

### Changed — GitHub Action hardening

- **Version source of truth**: `pyproject.toml` reads the version dynamically
  from `safeai.__version__` (`setuptools` `attr:`), so the package metadata and
  the source can no longer drift.
- **Hermetic install path**: `scripts/safeai-action.py` honours
  `SAFEAI_ACTION_FIND_LINKS` so CI can install a freshly built wheel instead of
  a published PyPI version; dependencies still resolve from PyPI.
- **Output hardening**: `set_output()` strips `\n`/`\r` to prevent
  `$GITHUB_OUTPUT` key injection; path inputs are rejected when they contain
  control characters; `get_safeai_version()` failures surface as `::warning::`.

### Notes

- Version bumped to `1.6.0` (tag `v1.6`). Full suite: 459 tests collected.

## [1.5.0] - 2026-08-11

### Added — GitHub Actions Marketplace action

- **Composite action** (`action.yml` at the repository root): a ready-to-use
  GitHub Actions action with inputs `path`, `version`, `fail-on`, `sarif`,
  `rules`, `baseline`, `fail-on-new`, `fail-on-escalation`, `no-registry`,
  and `extra-args`; a `sarif-path` output; and `shield`/`purple` branding.
- **Pure-Python driver** (`scripts/safeai-action.py`): installs the
  `SafeAI-Static-Analyzer` PyPI distribution into the runner's Python and
  runs `python -m safeai scan`. All inputs arrive as `INPUT_*` environment
  variables and are forwarded to the tool as an argv list — no shell
  evaluation, no `eval`, no interpolation of user input into `run:`.
- **Native exit-code passthrough** (0 = pass, 1 = policy/finding threshold hit,
  2 = operational error), with the SARIF artifact written even on a failing
  scan so downstream uploads keep working. The action prints `::warning::`
  if a failed scan produced no SARIF.
- **Least-privilege design**: the action only needs `contents: read` and runs
  with the runner's default Python 3.11+ (`setup-python@v5` recommended);
  `no-registry: true` is the default so scans stay ephemeral.
- **Self-validating CI** (`.github/workflows/action-test.yml`): runs the
  action itself (`uses: ./`) against clean and risky fixture repositories,
  builds the wheel, installs it into a throwaway venv, and validates SARIF
  2.1.0 output and failure behavior on every commit.
- Local validation helpers: `scripts/run_local_integration.py` (build →
  venv-install → scan → SARIF/exit-code check, with `PYTHONPATH` cleared so
  only the installed package is used) and `scripts/check_wheel.py` (wheel
  entry points, rules data, METADATA name). 24 new tests in
  `tests/test_github_action.py` plus fixtures in `tests/fixtures/action/`.

### Added — Environment Dependency Inventory & Correlation (CE 1.5)

- **Environment and credential dependency inventory**
  (`safeai/analyzers/env_dependency/`): a new analyzer records *references* to
  external configuration and credentials — `os.getenv`/`os.environ`,
  `process.env`, dotenv keys, shell/template interpolation, AWS Secrets
  Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, and Kubernetes
  `secretKeyRef`. **Names and source locations only; values are never read,
  masked, or stored**, preserving the source-private guarantee. Entries are
  flagged `secret: true` when backed by a secret manager or a secret-ish name.
- **Dependency-to-capability correlation**
  (`safeai/analysis/dependency_correlation.py`): the inventory is matched
  against the per-tool capability surface via a reviewable name-family keyword
  model, producing two new findings:
  - `DEP_UNDECLARED_CAPABILITY` (medium) — a referenced credential/config
    family has no declared capability to consume it: a candidate undeclared
    capability.
  - `DEP_ORPHANED_TOOL` (low) — a credential-demanding capability is declared
    with no matching credential/config reference anywhere: a probable dead or
    misconfigured tool.
- Correlation findings feed the severity counts, trust score, SARIF, terminal
  and HTML outputs, and are written to the KYA manifest (`dependency_inventory`
  and `dependency_correlation`, plus a `summary.dependency_count`).
- New rules in `safeai/rules/base_rules.yaml`: `ENV_DEP_INVENTORY`,
  `DEP_UNDECLARED_CAPABILITY`, `DEP_ORPHANED_TOOL`.

### Fixed — CE 1.5 architecture review hardening

- **Family matching is now word-segment based**
  (`safeai/analysis/dependency_correlation.py`): names are split on
  non-alphanumeric boundaries instead of raw substring matching, so short
  tokens no longer false-positive inside unrelated words (e.g. `jdbc` no longer
  maps to the database family via `db`). Provider-specific families
  (`cloud`/`database`/`messaging`) take precedence over the generic `api`
  fallback, keeping `SLACK_TOKEN` aligned with a declared `slack` capability and
  eliminating simultaneous false `DEP_UNDECLARED_CAPABILITY` +
  `DEP_ORPHANED_TOOL` pairs.
- **Single scoring pass** (`safeai/engine/orchestrator.py`): correlation now
  runs before the single count/score/relativize pass so its findings are
  included exactly once; the second `_relativize_report()` call was removed.
- **Payload-carrying findings are never suppressed**
  (`safeai/kya/suppressions.py`): `ENV_DEP_INVENTORY` (and
  `MCP_ASSETS_DISCOVERED`) are exempt from `apply_suppressions`, so a broad
  `rule_id`/`path` suppression cannot blank the dependency-inventory section.

### Notes

- The informational `ENV_DEP_INVENTORY` finding is counted in the severity
  breakdown and baseline; scans of repositories with a declared dependency
  inventory will report one more finding than v1.4 for the same input.

### Changed — first stable release & packaging fixes

- Version bumped to `1.5.0` and the `Development Status :: 4 - Beta`
  classifier replaced with `5 - Production/Stable` (`pyproject.toml`).
- `safeai.cmd.postprocess._safeai_version()` now resolves the installed
  version through `importlib.metadata` using the `SafeAI-Static-Analyzer`
  distribution name (with the previous `safeai` name as fallback).
- `data_files`-free pure-Python wheel confirmed to package
  `safeai/rules/base_rules.yaml` as package data; a wheel check script now
  guards this in CI.

## [1.4.0-beta] - 2026-08-02

### Added — Tool-Centric Capability Model & Escalation Detection

- **Tool identity** (`safeai/analysis/tool_identity.py`): capabilities are now
  attributed to a named tool rather than only to an agent. A tool identity
  carries a `kind` (`agent`, `mcp_server`, `skill`, `tool`, `workflow_node`,
  or `unknown`), a `name`, and a `framework`, and reduces to a deterministic
  `tool_key` (for example `mcp_server:invoice-lookup`, `tool:send_email`).
  The key is stable across scans when a name is available, and falls back to
  a path-derived hash only when a tool is genuinely unnamed. Capabilities
  that cannot be attributed to any tool are grouped under a fixed
  `unknown:unattributed` identity rather than dropped or guessed at.
- **Access modes**: every capability now carries an `access_mode` on an
  ascending scale of `none < read < write < mutate < execute`. Where a
  framework or configuration does not explicitly declare the mode, SafeAI
  infers it conservatively (defaulting to `read`) and marks the capability
  `access_mode_inferred: true`. Inferred access can trigger a rule, but its
  severity is capped below critical, and never on its own claims the same
  certainty as a declared, evidenced access mode. See `LIMITATIONS.md`.
- **Capability diff, schema version 2** (`safeai/analysis/capability_diff.py`):
  the baseline comparison now keys on `(tool_key, capability_name,
  access_mode)` instead of capability name alone, so the diff can tell you
  which tool gained or lost which authority, not just that "shell" appeared
  somewhere in the project. The output adds a `tools` breakdown, `counts`
  (new/escalated/reduced/removed/unchanged tools, plus escalations by
  severity), and a `highest_escalation` summary. The pre-2.0 flat
  added/removed/changed diff is preserved verbatim under a `legacy` key and
  at the top level for existing consumers.
- **Thirteen capability escalation rules** (`safeai/analysis/escalation.py`):
  `ESC_SHELL_ADDED`, `ESC_FILESYSTEM_WRITE_ADDED`,
  `ESC_EXTERNAL_ACCESS_ADDED`, `ESC_MCP_SERVER_ADDED`,
  `ESC_MCP_READ_TO_MUTATE`, `ESC_APPROVAL_GATE_REMOVED`,
  `ESC_MEMORY_SCOPE_EXPANDED`, `ESC_WRITE_TOOL_ADDED`,
  `ESC_NEW_EXTERNAL_DESTINATION`, `ESC_AUTONOMY_INCREASED`, plus three
  combination rules that only fire when two conditions are true of the same
  tool at once — `ESC_COMBO_UNTRUSTED_INPUT_SHELL`,
  `ESC_COMBO_AUTONOMY_BROAD_DATA`, and
  `ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT`. These exist because a single
  capability rarely tells you whether a change matters: an agent gaining
  shell access is a different story than one that already had it, and an
  agent that gains both autonomy and broad data access at once is riskier
  than the sum of the two changes taken separately.
- **Tool surface** (`safeai/analysis/tool_surface.py`): a per-tool capability
  index, built from data the scan already collected (agent models and MCP
  assets), with no additional file access. It is written into the JSON
  report, the KYA manifest (`tool_surface`, added at manifest schema 1.1),
  and the registry. An MCP configuration that does not name its server is
  recorded under the unattributed tool identity rather than assigned an
  invented name.

### Added — Deep Claude Code Analysis

- The Claude Code adapter moves from presence detection to structural
  analysis of `.claude/settings.json` and `.claude/settings.local.json` (in
  that precedence order), `.mcp.json`, `.claude/commands/*.md` slash
  commands, `.claude/agents/*.md` subagent definitions, and lifecycle hooks.
  See `FRAMEWORK_SUPPORT.md` for the full scope boundary.
- **Ten new rules**, documented with exact severities and OWASP LLM mappings
  in `RULES_REFERENCE.md`: `CC_WILDCARD_PERMISSION`,
  `CC_BYPASS_PERMISSIONS`, `CC_DENY_SHADOWED`, `CC_FS_WRITE_OUTSIDE_ROOT`,
  `CC_SLASH_COMMAND_SHELL`, `CC_SLASH_COMMAND_ARG_INJECTION`,
  `CC_SUBAGENT_PRIVILEGE_ESCALATION`, `CC_HOOK_SHELL_EXEC`,
  `CC_MCP_UNCONSTRAINED`, and `CC_SETTINGS_UNPARSEABLE`. Configuration that
  cannot be parsed is reported as a low-severity finding rather than
  silently skipped or treated as a crash.

### Added — PR Comment, CI Context, and the Assurance Boundary

- **PR comment renderer** (`safeai/report/pr_comment.py`): produces a short,
  reviewer-facing Markdown summary of capability escalations, grouped by
  tool with the worst severity first, capped at 60 lines. With no baseline
  it summarizes the first scan rather than fabricating a diff; with no
  changes it prints a single line. SafeAI only ever writes this file to
  disk or stdout — it never posts it anywhere and makes no network call of
  any kind. Publishing the comment is left entirely to the CI workflow. See
  the "Capability escalation in CI" section in `README.md`.
- **CI context detection** (`safeai/kya/ci_context.py`): reads environment
  variables (and, on GitHub Actions, the pull request event payload) to
  identify the provider, branch, base ref, commit, PR number, and
  repository. It never raises — outside CI it returns an
  all-`unknown`/`None` result — and supports GitHub Actions, GitLab CI, and
  Azure Pipelines.
- **Three new `safeai scan` flags**: `--pr-comment PATH` writes the Markdown
  summary to a file; `--pr-comment-stdout` prints it to stdout; and
  `--fail-on-escalation {critical,high,medium}` fails the scan when a
  capability escalation at or above that severity is found. This is a
  separate gate from `--fail-on`/`--fail-on-new`, which act on findings, not
  capability escalations; the two gates only add to the failing set, never
  subtract from it, and `--fail-on-escalation` requires `--baseline` because
  an escalation is by definition a change relative to something.
- **Assurance boundary** (`safeai/kya/assurance.py`): a short, factual
  statement of what a scan verified statically (declared tools, prompt and
  instruction files, MCP server configuration, workflow structure,
  permission configuration) and what it structurally cannot verify (IAM and
  cloud permissions, runtime identity, deployed network policy, actual
  runtime behaviour, dynamically constructed tool bindings). It is computed
  from real scan data — files actually skipped, configuration that actually
  failed to parse, and the count of access modes that were actually
  inferred rather than declared — never from a fixed template. Written into
  the manifest as `assurance_boundary` (manifest schema 1.2). See
  `KYA_MANIFEST.md` and `LIMITATIONS.md`.

### Added — Registry Schema v2

- **`agent_tool_snapshots` table**: one row per tool per scan, storing the
  tool's identity, kind, framework, its capability list, and a summarized
  access level. `agent_id` is nullable by design — a tool is attributed to
  an agent only when the tool's evidence paths overlap the agent's source
  locations, and a tool with no such overlap is stored unattributed rather
  than assigned a guessed owner or dropped. Uniqueness is enforced by an
  expression index (`IFNULL(agent_id, ''), scan_id, tool_key`) because
  SQLite treats `NULL` as distinct for ordinary `UNIQUE` constraints. See
  `REGISTRY.md`.
- **Automatic migration from schema v1**: existing registries gain the new
  table and indexes in place on the next scan. Migrations are additive and
  forward-only; no existing row in any table is dropped, rewritten, or
  renumbered.

### Changed

- `MANIFEST_SCHEMA_VERSION` is now `1.2`. The `tool_surface` array
  (introduced at 1.1, alongside this release) and the `assurance_boundary`
  object (new at 1.2) are both present in every manifest written by this
  version. `KYA_MANIFEST.md` has been brought up to date to document both.
- Baseline loading accepts a legacy JSON report or a KYA manifest of schema
  1.1 or later as the `--baseline` input, matching the existing baseline
  contract.
- Version bumped to `1.4.0b0` (`pyproject.toml`).

### Compatibility

- **Registries** created under schema v1 migrate automatically on the next
  scan and retain every existing row; nothing is deleted or renumbered by
  the migration.
- **Baselines** captured before v1.4 (no `tool_surface` in the manifest, or
  a legacy JSON report) still work with `--baseline` and
  `--fail-on-escalation`, but because they predate per-tool attribution,
  the diff cannot trust their structural tool status. In that case,
  individual per-tool escalation rules are suppressed and only the three
  combination rules are evaluated, since those depend on conditions within
  a single scan rather than on trusting the baseline's tool structure.
- No new runtime dependency was introduced. PyYAML remains the only
  third-party dependency.

## [1.3.0-beta] - 2026-07-31

### Added — KYA Baseline & Local Registry

- **Canonical KYA manifest** (`safeai-manifest.json`, schema v1.0): the
  portable public contract for scan-derived agent evidence, written via
  `--manifest`. See `KYA_MANIFEST.md`.
- **Local SQLite KYA registry** at `.safeai/registry.db`, created/updated
  automatically on interactive scans (auto-disabled when `CI` is set).
  Historical snapshots are append-only. See `REGISTRY.md`.
- **`safeai registry` command group**: `list`, `show`, `history`, `diff`,
  `export` with `--registry PATH` and `--format table|json`.
- **Deterministic finding fingerprints** (documented SHA-256 algorithm),
  stable `finding_id`s, confidence labels (`high|medium|low`), provenance
  records, and remediation defaults for high-value rules.
- **Baseline comparison** (`--baseline`): classifies findings as
  new/existing/resolved; accepts manifests or legacy JSON reports.
- **`--fail-on-new`**: opt-in gating on new/regressed findings only.
  Existing `--fail-on` semantics are unchanged without it.
- **Suppression workflow** (`.safeai/suppressions.yml`): required
  reason/owner/created, optional expiry and path scope; expired entries
  warn; suppressed findings stay visible and are excluded from gating.
- **Minimal policy-as-code** (`.safeai/policy.yml`): `allow|warn|
  require_review|deny` with rule/severity/capability/framework/agent/path/
  MCP-posture selectors; deterministic evaluation; outcome in terminal,
  manifest, HTML, and JSON. `deny` fails the scan.
- New scan flags: `--manifest`, `--registry`, `--no-registry`,
  `--strict-registry`, `--policy`, `--suppressions`, `--fail-on-new`.
- Terminal/HTML/SARIF output: KYA section, registry status, policy
  outcome, baseline counters, SARIF `partialFingerprints` and rule help
  text.
- Docs: `KYA_MANIFEST.md`, `REGISTRY.md`, `LIMITATIONS.md`; maturity
  categories in `FRAMEWORK_SUPPORT.md`; README/USER_GUIDE KYA sections.
- 66 new tests covering manifest determinism, fingerprints, baseline,
  suppressions, policy, registry persistence/queries/CLI, redaction, and
  CI behavior.

### Changed

- Scan engine skips `.safeai/` and SafeAI-generated artifacts (manifests,
  JSON reports) to prevent findings feedback loops. The JSON report now
  carries a `report_type: safeai.scan` marker (additive).
- JSON report findings gain additive keys (`fingerprint`, `finding_id`,
  `status`, `confidence_label`, `provenance`); no keys removed or retyped.
- `--baseline` still feeds legacy capability diff when given a legacy JSON
  report, and now also drives fingerprint comparison.
- Version bumped to `1.3.0b0` (`safeai/__init__.py` now matches
  `pyproject.toml`).

### Backward compatibility

- Existing CLI usage, exit codes, and JSON/HTML/SARIF shapes are preserved;
  all schema changes are additive. The manifest is a new artifact, versioned
  independently (`schema_version: 1.0`).
- Registry write failures never fail a scan unless `--strict-registry` is
  passed (exit code 2).

## [1.2.0] - 2026-07-26

### Added
- Eight new capability detectors (contributed by @yugaaank):
  - Docker (`CAP_docker`): `import docker`, `DockerClient`, `containers.run`
  - Kubernetes (`CAP_kubernetes`): `import kubernetes`, `kubectl`, `kube_config`, `k8s`
  - Redis (`CAP_redis`): `import redis`, `Redis()`, `StrictRedis`
  - S3 / Cloud Storage (`CAP_s3`): `import boto3`, `boto3.client('s3')`
  - Slack (`CAP_slack`): `import slack`, `slack_sdk`, `SlackClient`
  - Jira (`CAP_jira`): `import jira`, `JIRA()`, `jira.Client`
  - Browser Automation (`CAP_browser`): `playwright`, `selenium`, `webdriver`, `browser_use`
  - Google Cloud (`CAP_gcp`): `google.cloud`, `BigQuery`, `gcsfs`
- New capability categories: `Container` and `Collaboration`
- 20 tests in `tests/test_capability_detection.py` covering detection, false positives, multi-capability, and deduplication

### Changed
- `safeai/analysis/capabilities.py`: added `container` and `collaboration` categories
- `safeai/analyzers/capability/analyzer.py`: 8 new `CAP_PATTERNS`, `RULE_BY_CAP`, and `CATEGORY_BY_CAP` entries
- `safeai/rules/base_rules.yaml`: 8 new capability rules

## [1.1.0-beta] - 2026-07-24

### Added
- AI Component Security: skill, prompt file, tool definition, model config, and workflow template analysis
- Deep MCP analysis: per-tool broad permissions, sensitive resource detection, insecure transport detection
- Seven early-preview framework adapters: Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, n8n (15 total)
- Capability diff (`--baseline` flag) comparing current scan against a previous JSON report
- Parser registry with `@register_parser` decorator and `safeai.parsers` entry-point group for third-party plugins
- Diagnostics reporting in scan output

### Changed
- Component and integration paths are relativized to scan root in all report formats
- Provider-aware model safety checks (`MODEL_MISSING_CONTENT_FILTER` scoped to Google/Bedrock/Azure)
- Dify and n8n detection tightened to reduce false positives
- Guard against `IndexError` in parser arg extraction

### Security
- Masked credential values in findings evidence across all report formats

## [1.0.0-beta] - 2026-07-18

### Added
- Multi-framework scanning: LangGraph, CrewAI, LangChain, Semantic Kernel,
  OpenAI Agents SDK, Microsoft Agent Framework, Azure AI Foundry, Bedrock Agent
- Prompt injection detection (LLM01): input interpolation, missing delimiters,
  system prompt leakage, role override attempts
- Capability analysis (LLM06): shell, filesystem, HTTP, database, code
  execution, autonomous loops, `subprocess` with `shell=True`, file writes
- Data leakage detection (LLM02): hardcoded API keys, tokens, passwords,
  environment secret references
- MCP analysis: config discovery, schema validation (v1.0/v1.1), missing auth,
  weak auth, missing permissions, exposed endpoints, hardcoded secrets
- Deterministic trust scoring across 7 risk categories (0–100)
- Reports: terminal, JSON, SARIF 2.1.0, HTML
- Custom YAML rules via `--rules`
- CI/CD exit codes via `--fail-on`
- GitHub Actions workflow with self-scan SARIF dogfooding
- Installable package with `safeai` console script and `python -m safeai`

### Security
- Credential values in findings evidence are masked in all report formats
- Scans exclude VCS directories, dependency caches, and oversized files
