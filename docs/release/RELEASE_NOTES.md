# SafeAI — Release Notes

> Releases v2.1–v2.6 are documented in `CHANGELOG.md` and on the
> GitHub Releases page.

## v2.16.0 (2026-11-06)

**Change Coverage, Identity & Governance Evidence, IaC Collectors.** One
release for plans v2.14 to v2.16; there is no v2.14.0 or v2.15.0. Every
new signal is review-only (Lane B): it is reported for review and never
fails a gate until its precision is published.

### What's New

- **More in the OCSF export.** Delegation and workload-identity changes
  are IAM Analysis Findings (`severity_id` 0: SafeAI gives them no
  severity). The manifest now keeps those change blocks.
- **LangGraph and AutoGen delegation.** Supervisors (nested ones too),
  swarm handoff tools, AutoGen handoffs and teams, and 0.2 group chats
  join the delegation graph; the delegation change types and Separation
  of Duties apply to them.
- **Separation of Duties for Kubernetes, and your own pairs.**
  ServiceAccounts that can create and approve certificate requests,
  `escalate` / `bind` Roles, `impersonate`, or act and delete Events are
  reported. Declare organisation pairs in `.safeai/config.yml`:

  ```yaml
  separation_of_duties:
    pairs:
      - id: ORG-DEPLOY-APPROVE
        title: deploy a release and approve it
        first: ["deploy_*"]
        second: ["approve_release"]
  ```
- **Agent identity through its workload.** Annotate the pod template with
  `ai.safeai.dev/agent: <name or agent_id>`, or let the container
  entrypoint name the agent's file, and the SPIFFE ID the workload is
  issued is attributed to that agent.
- **Governance metadata in the attestation.** `agent_governance` in
  `.safeai/config.yml` (owner, lifecycle, purpose, CIMD `client_id`) is
  restated in the attestation, with the client metadata document when
  the repository holds it (never fetched).
- **Baseline approval.** `safeai manifest approve baseline.json --by
  security-lead@example.org --owner dev@example.org` records who approved
  the baseline; `--require-approval` now also fails on an unapproved,
  self-approved or changed baseline.
- **Capability-level delegation.** A delegate's tool no longer counts as
  exceeding its delegator when everything detected inside it is
  something the delegator can already do.
- **CloudFormation, Serverless Framework and Helm.** IAM roles and
  policies from CloudFormation templates and `serverless.yml`, and RBAC
  from Helm chart templates, read without evaluating intrinsics,
  variables or template actions.

### Upgrade notes

- No breaking changes. Manifest contract **1.3.0** (schema
  `v1.3.0.json`); readers of 1.0 to 1.1 are unaffected, and no value
  domain changed. Fingerprints, agent IDs and tool keys are unchanged.
- The attestation predicate type is now `agent-authority-v0.2-experimental`;
  `manifest verify --attestation` still accepts v0.1 Statements.
- `--require-approval` with `--baseline` now needs an approved baseline:
  run `safeai manifest approve` once per baseline, or expect the scan to
  fail.
- A CloudFormation YAML file with `!Ref` tags was listed as unparsed IaC;
  it is now read, so IaC counts and correlation verdicts can change for
  repositories that hold such templates.
- The 58-case authority benchmark holds with unchanged digests
  (`ee76875d…`, `de9cb451…`); the 44 pending cases hold.

### Links

- [Changelog](../../CHANGELOG.md#2160---2026-11-06)
- [Implementation plan v2.14–v2.16](../releases/IMPLEMENTATION_PLAN_V2_14_TO_V2_16.md)
- [Attestation predicate v0.2 (experimental)](../attestation/agent-authority-v0.2-experimental.md)
- [OCSF mapping](../exports/OCSF.md)

---

## v2.13.0 (2026-11-03)

**Interoperability Exports.** A scan's findings and authority changes
can now go to a SIEM or a Shared Signals receiver as standard formats,
OCSF events and SSF Security Event Token payloads. SafeAI only writes
the files: nothing is signed or sent, and `--pr-comment-post` is still
the one network path.

### What's New

- **OCSF 1.9.0 export.** `safeai scan . --ocsf events.jsonl` writes one
  Application Security Posture Finding (2007) per finding and one IAM
  Analysis Finding (2008) per tool authority change other than
  `NO_CHANGE`, as JSON Lines. SafeAI-specific fields are under
  `unmapped.safeai`. CI validates every event of a real scan against
  the published OCSF class schemas, vendored in `schemas/ocsf/1.9.0/`.
- **SSF SET payloads.** `safeai scan . --baseline B --ssf-set sets.jsonl`
  writes one unsigned RFC 8417 claims set per `MATERIAL_CHANGE` or
  `HIGH_RISK_CHANGE` tool change, in the OpenID SSF 1.0 envelope, with
  the manifest integrity digest as evidence. Set `iss` and `aud` with
  `--ssf-issuer` and `--ssf-audience`. The event type is SafeAI's own
  and experimental, because no CAEP 1.0 event type describes a static
  authority change.
- **Exports from a stored manifest.**
  `safeai manifest export M --format ocsf|ssf-set -o PATH` checks the
  manifest's integrity digest first; the same manifest always gives the
  same bytes.
- **Reference integration** (Apache-2.0) in
  `examples/integrations/ocsf-ssf-consumer/`: a receiver that validates
  both exports, rejects SETs bound to another manifest and prints a
  review queue. `reproduce.py` rebuilds the committed result, and CI
  checks it.

### Fixed

- Manifests no longer contain the scanning machine's paths:
  tool-surface evidence for MCP and Claude Code configuration files was
  absolute. The JSON report's tool-implementation map and module paths
  are now repository-relative too.
- With a manifest as the baseline, the component diff no longer reports
  every component as both added and removed.

### Upgrade notes

- No breaking changes. The manifest contract stays at **1.1.0**.
  Fingerprints, agent IDs and tool keys are unchanged, so baselines,
  suppressions and registry history keep matching.
- A manifest written by v2.12.0 or earlier still works as a baseline:
  its absolute evidence paths do not show up as authority or component
  changes.
- The 58-case authority benchmark holds with unchanged digests
  (`ee76875d…`, `de9cb451…`); the 33 pending cases hold.

### Links

- [Changelog](../../CHANGELOG.md#2130---2026-11-03)
- [Exports overview](../exports/README.md)
- [OCSF mapping](../exports/OCSF.md)
- [SSF event type v0.1 (experimental)](../exports/ssf-agent-authority-change-v0.1-experimental.md)

---

## v2.12.0 (2026-11-03)

**Attestation & Accountability.** A scan can now hand its authority
evidence to another system as an in-toto Statement, name each agent's
SPIFFE or WIMSE identity with where that name came from, and record who
approved each exception. There is no v2.11.0: its items shipped in
v2.10.0.

### What's New

- **Experimental Agent Authority Attestation.**
  `safeai scan . --manifest M --experimental-attestation A` writes an
  unsigned in-toto Statement v1 about the manifest file. Its predicate
  keeps `machine_derived`, `declared` and `unknown` fields apart, per
  agent and for the repository; every unknown field says why.
  `safeai manifest verify M --attestation A` checks that neither file
  was edited apart from the other. Experimental: no schema-stability
  promise.
- **Agent identity field** `agents[].workload_identity`. Declare
  identities in `.safeai/config.yml`:

  ```yaml
  agent_identities:
    - agent: billing-agent
      id: spiffe://example.org/ns/billing/sa/agent
  ```

  A declared ID that the repository's own `ClusterSPIFFEID` also issues
  is `corroborated`. Nothing is attributed to an agent that declared
  nothing, and `runtime_verified` is always `false`.
- **Approval metadata** on exceptions and suppressions:

  ```yaml
  approval:
    approved_by: security-lead@example.com
    approved_at: 2026-11-02
    escalation_owner: platform-team
  ```

  Reported as `approval_state` (`approved`, `self-approved`,
  `unrecorded`). `--require-approval` fails the scan when an active
  exception or applied suppression has no approval from someone other
  than its owner.

### Fixed

- Paths of dot-files and dot-directories keep their leading dot in
  findings, the manifest and SARIF (`.claude/settings.json`, not
  `claude/settings.json`). Fingerprints and agent IDs are unchanged, and
  suppression and policy globs match either form.

### Upgrade notes

- No breaking changes. Manifest Contract moves to **1.1.0** (new
  optional section and fields; schema `v1.1.0.json`). Readers of 1.0.0
  are unaffected, and `v1.0.0.json` is unchanged.
- Existing baselines, suppressions and registry history keep matching:
  fingerprints and agent IDs did not change.
- `--require-approval` is off by default. Turning it on in CI fails
  every active exception that has no `approval` block yet.
- The 58-case authority benchmark holds with unchanged digests
  (`ee76875d…`, `de9cb451…`); the 33 pending cases hold.

### Links

- [Changelog](../../CHANGELOG.md#2120---2026-11-03)
- [Attestation predicate v0.1 (experimental)](../attestation/agent-authority-v0.1-experimental.md)
- [Manifest compatibility](../manifest/COMPATIBILITY.md)

---

## v2.10.0 (2026-11-01)

**Workload Identity, Delegation & Separation of Duties.** SafeAI now
answers three new questions from repository evidence: *which SPIFFE
identity is each workload issued*, *which agent can hand work to which*,
and *can one holder both perform and approve the same thing*. Every new
signal is Lane B: reported for review, never failing a gate.

### What's New

- **Static SPIFFE workload identity.** `ClusterSPIFFEID`,
  `ClusterFederatedTrustDomain`, the SPIRE controller manager config and
  `Namespace` labels give each workload its SPIFFE ID
  (workload → ServiceAccount → SPIFFE ID). Undecidable selectors leave
  the identity `unknown`, with the reason. Istio `AuthorizationPolicy`
  principals become declared callers. See
  `iac_correlations.workload_identity`.
- **`IAC_STATIC_CREDENTIAL_WITH_WORKLOAD_IDENTITY`** (low): a workload
  with a SPIFFE ID is also handed a static credential. Names only.
- **Delegation graph**: Claude Code session → subagents, OpenAI Agents
  SDK handoffs, CrewAI delegation (`report.delegation_graph`).
- **Change types against a baseline**, in the PR comment:
  - identity: `IDENTITY_ADDED`, `IDENTITY_REMOVED`,
    `IDENTITY_BROADENED`, `CALLER_ADDED`, `FEDERATION_ADDED`,
    `STATIC_CREDENTIAL_ADDED`;
  - delegation: `DELEGATE_ADDED`, `DELEGATION_BREADTH_INCREASED`,
    `DELEGATION_DEPTH_INCREASED`, `DELEGATE_EXCEEDS_DELEGATOR`,
    `SUBAGENT_TOOLS_WIDENED`.
- **`SOD_CONFLICTING_AUTHORITY`** (low): one holder can create and
  approve the same transaction, change and merge code, act and erase the
  audit trail, or rewrite its own permission settings.
- **Evidence metric** `unknown_workload_identity_rate`.

### Lane B: reported, not gating

None of the new change types is read by `--fail-on-authority-change` or
`--fail-on-escalation`, and both new rules are low severity, below the
lowest `--fail-on` threshold. Their precision is **not yet published**:
the twenty-four benchmark cases behind them hold, but await human review
(#300).

### Upgrade notes

- No breaking changes. A baseline taken with v2.9 or earlier carries no
  workload-identity block or delegation graph: the new change types then
  report `baseline_available: false` instead of reporting everything as
  added. Re-baseline with v2.10 to start comparing.
- New report fields: `iac_correlations.workload_identity`,
  `delegation_graph`, `separation_of_duties`, and
  `capability_diff.workload_identity_changes` / `delegation_changes`.
  Manifest Contract stays `1.0.0`; the new manifest fields are optional.
- The 58-case authority benchmark holds with unchanged digests
  (`ee76875d…`, `de9cb451…`).

### Links

- [Changelog](../../CHANGELOG.md#2100---2026-11-01)
- [Rule reference: SOD_CONFLICTING_AUTHORITY](../reference/RULES_REFERENCE.md#sod_conflicting_authority)
- [Rule reference: IAC_STATIC_CREDENTIAL_WITH_WORKLOAD_IDENTITY](../reference/RULES_REFERENCE.md#iac_static_credential_with_workload_identity)
- [Pending benchmark cases](../../tests/benchmarks/authority-pending/README.md)

---

## v2.9.0 (2026-11-01)

**Package-Manager Authority.** SafeAI now reports whether an agent can
change the project's dependencies — install, upgrade, remove or publish —
and which registry credentials it holds for that. It reports *that* the
agent can, never whether a chosen package is safe.

### What's New

- **`CAP_package_manager`** (medium, LLM03) from three sources:
  - Claude Code `Bash(...)` allow grants (settings, slash-command
    `allowed-tools`, subagent tools): `Bash(npm install:*)` is `write`,
    `Bash(npm publish)` is `execute`;
  - literal commands in LangGraph, CrewAI and AutoGen tool code
    (`subprocess.run(["npm", "install", pkg])`), as detected evidence;
  - MCP tools named for a package operation (`npm_install`,
    `publish_package`), as *inferred* evidence, with no finding.
- **`dependency` authority dimension** per tool: `npm:install`,
  `npm:publish`, `manifest:package.json`, … `Edit(package.json)` and
  similar grants show up here as manifest writes.
- **`credential` dimension**, populated for the first time: registry
  credential *names* set in the same Claude Code settings file's `env`
  block (`NPM_TOKEN`, `TWINE_PASSWORD`, …). Values are never read into
  any output.
- Nothing is guessed: a bare `Bash`, `Write(*)`, `npm run build`, or a
  command chosen at run time adds no dependency authority.

### Lane B: reported, not gating

`CAP_package_manager` findings are review-only, and a tool change made
only of package-manager (or inferred) evidence never fails
`--fail-on-authority-change` or `--fail-on-escalation`. Escalations are
still reported; `--fail-on-escalation` acts on the new
`highest_gating_escalation`. Its precision is **not yet published**: the
nine benchmark cases await human review (#296).

### Upgrade notes

- No breaking changes. Upgrading fails neither diff gate against a
  baseline taken with v2.8, even though `package_manager` is new on
  existing tools; a genuine Lane-A change still fails them.
- New report fields: `targets` and `credentials` on tool-surface
  capabilities, `dependency` (and `credential.values`) in each diff
  tool's `authority` block, `review_only` per diff tool, and
  `highest_gating_escalation` on the diff. `evidence_metrics` counts one
  more authority dimension.
- Manifest Contract stays `1.0.0`. The 58-case authority benchmark holds
  with unchanged digests.

### Links

- [Changelog](../../CHANGELOG.md#290---2026-11-01)
- [Rule reference: CAP_package_manager](../reference/RULES_REFERENCE.md#cap_package_manager)
- [Pending benchmark cases](../../tests/benchmarks/authority-pending/README.md)

---

## v2.8.0 (2026-11-01)

**Evidence Hygiene & Mapping.** Findings now name the control-framework
entries they map to, every statement a scan emits is audited for
provenance, and the roadmap's authority dimensions match the code.

### What's New

- **Control mappings in JSON and SARIF.** Each JSON finding carries
  `control_mappings`, each SARIF result `properties.controls`
  (`framework:control_id`), and each SARIF rule tags its control IDs, so
  code-scanning views can filter by them. Taxonomy only, never a
  compliance, coverage or conformance claim.
- **Blueprint reference-architecture mapping.** A `blueprint` framework
  with the six components of the publicly available Blueprint Alliance
  architecture that static authority evidence speaks to, mapped from
  MCP, skill, IaC, approval and authority-change rules. Ikarus AI Labs is
  not an Alliance member; nothing here implies membership or
  endorsement.
- **Provenance audit.** A test scans all 58 authority corpus cases and
  requires an enum-valid provenance class, gateability and evidence
  reference on every finding, capability and authority statement.
- **Per-side provenance on access-mode transitions** (`before_inferred`,
  `after_inferred`) and **evidence metrics in the HTML Security Brief**,
  both merged after v2.7.0.

### Fixed

- Text files are read and written as UTF-8 regardless of the locale; on
  some non-UTF-8 Windows locales scanner metadata reported 0 rules.
- The diff-gate blind warning names `--unknown-authority block` and a
  policy-file `authority.unknown: deny`.

### Upgrade notes

- No breaking changes, no detection changes and no gate or exit-code
  changes. Baselines and suppressions from v2.7 keep matching.
- JSON and SARIF gain fields; consumers that reject unknown keys need to
  allow `control_mappings` (JSON) and `properties.controls` /
  `properties.tags` (SARIF).
- The KYA manifest, its schema, contract version (`1.0.0`) and digest are
  unchanged: mappings go to JSON and SARIF only.
- The authority benchmark holds 58/58 with unchanged digests.

### Links

- [Changelog](../../CHANGELOG.md#280---2026-11-01)
- [Implementation plan v2.8 → v2.13](../releases/IMPLEMENTATION_PLAN_V2_8_TO_V2_13.md)
- [SARIF review guidance: control references](../sarif-review-guidance.md#control-references)

---

## v2.7.0 (2026-10-22)

**Evidence Metrology.** Every scan now says how much of its authority
picture is backed by evidence, and a critical detection gap is closed.

### What's New

- **Authority evidence metrics.** These are new in the JSON report and
  the manifest (`summary.evidence_metrics`), with a short summary in the
  security brief. They give the evidence-backed, inferred and
  unattributed authority rates, evidence completeness, findings per
  provenance class, and, with a baseline, the unknown
  authority-dimension rate. Empty denominators read
  `insufficient_evidence`, never 0 or 1. The metrics are informational
  and never gate.
- **Benchmark gate in CI.** The full 58-case authority corpus now runs
  on every PR (Python 3.11–3.13) and fails when any case stops holding.

### Fixed

- **`CAP_subprocess_shell` on wrapped calls.** `shell=True` on a later
  line than `subprocess.run(`, which is how black/ruff wrap long calls,
  was a silent false negative for this critical rule. An AST pass now
  catches it. Single-line findings keep their line, evidence and
  fingerprint, so existing baselines and suppressions still match.

### Upgrade notes

- No breaking changes. Expect new `CAP_subprocess_shell` findings
  (critical) on code that wraps subprocess calls over several lines.
  Review them before gating with `--fail-on critical` on a baseline
  taken with v2.6.
- Manifest Contract stays `1.0.0`; `summary.evidence_metrics` is an
  optional field that 1.x readers ignore.

### Links

- [Changelog](../../CHANGELOG.md#270---2026-10-22)
- [Implementation plan v2.7 → v2.11](../releases/IMPLEMENTATION_PLAN_V2_7_TO_V2_11.md)
- [Authority benchmark validation report](../benchmarks/authority/VALIDATION_REPORT.md)

---

## v2.0.1 (2026-09-03)

**Release hardening.** Consolidated release pipeline with mandatory
verification gates, GPG-signed artifacts, cross-platform verification
instructions, and pre-release checklist. 744 tests passing.

### What's New

- **Consolidated release pipeline** — 6-job pipeline: checklist → build →
  attest → sign → publish → release. Every gate must pass before the next.
- **Pre-release checklist** — blocks publication if version, rules, tests,
  CHANGELOG, or Action I/O contract is inconsistent.
- **GPG-signed artifacts** — wheel, sdist, checksums, provenance, SBOM
  all signed with detached `.asc` signatures.
- **Cross-platform verification** (`VERIFICATION.md`) — GPG, checksum,
  and provenance verification for Linux, macOS, Windows.
- **Regression fixtures** — 13 tests for 6 high-risk areas: Claude Code
  deny/allow, dataflow rule-ID casing, MCP tool-description injection,
  config-file adapter discovery, governance suppression, runaway-loop
  detection.
- **File discovery extraction** — `safeai/engine/file_discovery.py` with
  `discover_files()` and `dispatch_adapters()` extracted from orchestrator.
- **Scanner metadata** — machine-readable `scanner_metadata` section in
  reports (engine version, schema version, ruleset hash, adapter versions).

### Schema Stability

All v2.0.0 schema stability commitments remain in effect. See
[UPGRADE.md](./UPGRADE.md) for details.

### Links

- [Source Code](https://github.com/ikaruscareer/SafeAI/tree/v2.0.1)
- [Verification](./VERIFICATION.md)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)

---

## v2.0.0 (2026-09-03)

**Governance Depth & Ecosystem Expansion.** Deepens governance detection with
runaway-loop and recursion-guard rules, adds Windsurf config-file adapter,
and presents governance gaps as a failure-class coverage matrix. 695 tests
passing, lint clean, all CI workflows green.

### What's New

- **Runaway-loop / recursion-guard detection** — two new `GOV_*` rules:
  `GOV_MAX_ITERATIONS_MISSING` (severity: high) detects agent loops with no
  max-iteration bound; `GOV_RECURSION_GUARD_MISSING` (severity: medium)
  detects recursive tool calls without a depth guard. Both slot into the
  existing `GovernanceAnalyzer` with per-tool dedup and ±10-line source
  confirmation.
- **Failure-class coverage matrix** — new HTML report and JSON section
  groups `GOV_*` findings by failure class (dependency timeout, dependency
  unavailable, resource exhaustion, cascading failure, unbounded recursion,
  missing accountability). Shifts operator question from "which rules fired?"
  to "which failure modes can this agent survive?"
- **Windsurf config-file adapter** — framework adapter for `.windsurfrules`
  (Windsurf IDE config). JSON/YAML/free-text parsing, capability scanning,
  tool/model extraction, unrestricted grant detection, MCP references.
- **Evidence type schema (KYA manifest v1.3)** — `evidence_type` on every
  finding: `static-config`, `static-pattern`, or `runtime-observed`
  (reserved). See PR #114.

### Upgrade Notes

See [UPGRADE.md](./UPGRADE.md) for the full v1.x → v2.0.0 migration guide.
Key changes:

- `GOV_MAX_ITERATIONS_MISSING` and `GOV_RECURSION_GUARD_MISSING` are new
  rule IDs — custom policies referencing GOV_* rules may need updating.
- `failure_class_matrix` is a new field in JSON output — consumers should
  handle its absence gracefully.
- `.windsurfrules` is now a scannable file — scans of repos containing this
  file will produce new findings.
- KYA manifest schema bumped to v1.3 (additive — `evidence_type` field).

### Schema Stability

The following are stable as of v2.0.0 and will not change without a major
version bump:

- **Rule IDs** — `CAP_*`, `CC_*`, `DATA_*`, `DATAFLOW_*`, `DEP_*`,
  `ENV_*`, `GOV_*`, `MCP_*`, `MODEL_*`, `PROMPT_*`, `PROMPT_FILE_*`,
  `SKILL_*`, `TOOL_*`, `WORKFLOW_*` (79 rules in `base_rules.yaml`).
- **SARIF output** — SARIF 2.1.0 with `properties.*` fields:
  `risk_category`, `affected_framework`, `affected_capability`,
  `score_contribution`, `confidence`, `confidence_label`, `evidence_type`,
  `resolved_definition`, `schema_version`, `validation_rule`,
  `affected_object`.
- **JSON report schema** — `findings[]`, `summary`, `assurance_boundary`,
  `failure_class_matrix`, `tool_surface`, `capability_diff`, `components`,
  `kya_agents`, `policy_decision`, `suppressions`, `baseline`.
- **Exit codes** — 0 = clean, 1 = findings at or above threshold,
  2 = scan error.
- **GitHub Action inputs/outputs** — inputs: `path`, `version`, `fail-on`,
  `sarif`, `rules`, `baseline`, `fail-on-new`, `fail-on-escalation`,
  `no-registry`, `extra-args`, `scorecard`, `scorecard-json`,
  `scorecard-summary`, `scorecard-fail-under`. Outputs: `sarif-path`,
  `scorecard-path`, `safeai-version`.
- **KYA manifest** — schema v1.3: `agents`, `components`, `findings`,
  `summary`, `limitations`, `tool_surface`, `assurance_boundary`,
  `evidence_type` on every finding.

### Supported Environments

- **Python**: 3.11, 3.12, 3.13 (CI-tested). `requires-python = ">=3.11"`.
- **Platforms**: Linux (Ubuntu 24.04), macOS, Windows. No platform-specific
  code; all paths are cross-platform.
- **CI**: GitHub Actions (primary), GitLab CI, Azure Pipelines (via
  `safeai/kya/ci_context.py`).
- **Framework adapters**: 16 adapters (azure_foundry, bedrock_agent,
  claude_code, crewai, cursorrules, dify, google_adk, haystack, langchain,
  langgraph, llamaindex, mastra, microsoft_agent, n8n, openai_agents,
  semantic_kernel, windsurf). All load via `@register_parser`.

### Known Limitations and Non-Goals

- **Static analysis only** — SafeAI scans source code and configuration at
  rest. It does not execute agents, call LLMs, or verify runtime behavior.
  See `assurance_boundary` in every report for what was verified vs what
  cannot be verified statically.
- **No compliance certification** — control mappings (OWASP LLM/Agentic,
  NIST AI RMF) are taxonomy references, not compliance claims. A "covered"
  failure class means a governance control was declared in source, not that
  it is enforced at runtime.
- **Heuristic detection** — capability detection, data-flow tracking, and
  governance signal detection use regex and AST heuristics. False positives
  are possible. Confidence labels (`heuristic` vs `high`) reflect this.
- **Single-file analysis** — data-flow tracking follows taint one call deep
  within a file. Cross-file taint propagation is not yet supported.
- **MCP content-level inspection not yet shipped** — MCP tool-description
  poisoning detection is planned for v2.1. The current MCP analyzer is
  structural (resolved vs unresolved-command).
- **No runtime sandbox** — SafeAI is not a runtime security platform,
  observability product, or red-teaming tool. It complements runtime tools
  by finding risk in code first.

### Links

- [Source Code](https://github.com/ikaruscareer/SafeAI/tree/v2.0.0)
- [Upgrade Guide](./UPGRADE.md)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)

---

## v1.9.1 (2026-08-30)

**SafeAI 1.9.1 is a post-release hardening release for v1.9.0.** Fixes
AGENTIC04 mojibake, scoped governance source suppression, hardened LangGraph
detection, browser rule enrichment, and removes unused regex patterns.

### Community contributors

Thank you to the following community members for their contributions:

- **[@i-safonoff](https://github.com/i-safonoff)** — filled missing entries
  in RULES_REFERENCE.md (PR [#108](https://github.com/ikaruscareer/SafeAI/pull/108))
  and fixed dataflow rule ID casing mismatch (PR
  [#109](https://github.com/ikaruscareer/SafeAI/pull/109)).
- **[@Solarthis](https://github.com/Solarthis)** — added MCP tool
  description injection detection (PR
  [#107](https://github.com/ikaruscareer/SafeAI/pull/107)).
- **[@ARAVIND281](https://github.com/ARAVIND281)** — implemented
  interprocedural data-flow tracking (PR
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
- **[@mahirhir](https://github.com/mahirhir)** — documented Claude Code deep
  analysis fixtures and detection approach (PR
  [#92](https://github.com/ikaruscareer/SafeAI/pull/92)).

### Verification Snapshot

- 641 tests passing, 1 skipped.
- Lint passing (`ruff check safeai/ tests/`).
- 76 built-in rules in `safeai/rules/base_rules.yaml`.

---

## v1.7.0 (Superseded by v1.8.0)

**SafeAI 1.7.0 completes the CE 1.4 and CE 1.6 roadmap milestones.** Adds
IDE-scoped MCP discovery, named policy profiles, registry freshness
indicators, suppression CI failure, component registry persistence, and
component-change diffs. The scanner stays fully offline, static, and
local-first.

### Headline: Multi-source MCP discovery

MCP server configs are now discovered across Cursor, Windsurf, and VS Code
scopes in addition to the scanned repo. Out-of-repo scopes are behind an
explicit `--mcp-ide-scopes` flag and excluded from exports by default.

### Headline: Named policy profiles

Five built-in profiles (`developer`, `strict-ci`, `mcp`, `rag`,
`production-agent`) provide composable policy rule sets. Load with
`--policy-profile NAME`; user overrides in `.safeai/policy.yml` extend the
preset.

### Headline: Registry freshness + suppression enforcement

- Agent records track `last_scan_timestamp` and `scan_count`; `safeai registry
  list` surfaces freshness status.
- `--strict-suppressions` fails the scan on expired or moved suppressions,
  enabling CI enforcement.

### Headline: Component registry + change diffs

- Component snapshots (type, name, path, source, full data JSON) are persisted in
  the KYA registry's `component_snapshots` table (schema v3) with first/last-seen
  provenance; consuming agents are resolved via `get_component_agents`.
- Changed, added, or removed components flag all consuming agents in a new
  `component_diff` section (computed against the baseline scan).

### Upgrade notes

- No breaking changes. All new flags are opt-in.
- Registry schema auto-migrates from v1.6.0 to v3 (adds `component_snapshots`).

---

## v1.8.0 (Shipped — curated scope: "True Authority & Complete Lifecycle")

**SafeAI 1.8.0 bundles the remaining CE 1.4 and CE 1.5 gaps into two cohesive
workstreams and is the gate for starting CE 2.0.** Every item below was confirmed
as not-yet-implemented (or only partially implemented) in the v1.7.0
architectural review.

### Workstream 1 — Lifecycle & Ownership (CE 1.4 completion)

- **Finding Lifecycle Event Engine** — `finding_lifecycle` table (schema v4)
  tracking `introduced → persisting → resolved → reopened` on existing
  fingerprints; new `ESC_RECURRING_RISK` rule for reintroduced findings.
- **Stale Suppression Guard** — compare a suppression's fingerprint against the
  current AST/location; `--strict-suppressions` fails when a waiver exists but
  the underlying code has materially shifted.
- **Agent Enrichment Schema** — `safeai registry metadata set <agent_id>
  --owner … --env …` stored in a decoupled `agent_metadata` table and shown in
  the HTML report.

### Workstream 2 — Code-Level Authority (CE 1.5 completion)

- **Tool ↔ Implementation Mapping** — correlator bridging `tool_def` findings
  with skill/capabilities; surfaces orphan states ("declared but no
  implementation found").
- **Command-Aware MCP Resolution** — statically resolve a local MCP server
  `command`, attempt static extraction, label `assurance: resolved` vs
  `assurance: unresolved-command`.
- **Target Taxonomy Engine** — aggregate external-network capabilities into
  explicit buckets (Database, Object Storage, SaaS APIs) in HTML/JSON reports.

### Workstream 3 — Detection Depth (analysis hardening)

- **Prompt risk depth** — multi-line concatenation, cross-file interpolation,
  indirect injection via tool calls, XML/HTML tag injection, template variable
  injection in `.md` files.
- **Data leakage depth** — private keys, JWT tokens, AWS access keys,
  connection strings, base64/hex-encoded secrets; per-pattern severity.
- **Cross-component analysis** — `component_graph.py` analyzes skill→tool→
  workflow→MCP→model relationships and flags dangerous combinations.

**Community scans:** expanded from 5 to 25 AI tool targets across all categories.
**First-time UX:** `safeai welcome` guided first-run command.

**Definition of done:** all CE 1.4, CE 1.5, and CE 1.8 roadmap items marked ✅ shipped;
a reviewer can see, for any tool or MCP server, where it is declared and where
it is implemented, and SafeAI flags mismatches. Suppressions are provably valid
against the current code, and every finding carries its longitudinal history —
unblocking CE 2.0.

---

## v1.9.0 (Shipped — curated scope: "Component Depth & Ecosystem Foundations")

**SafeAI 1.9.0 carries the remaining depth items not in v1.8.0: CE 1.6
component-record depth, CE 1.4/1.5 governance and data-flow leftovers, and
CE 2.0 ecosystem foundations.** Every item below was confirmed as shipped in
the v1.9.0 architectural review.

### Workstream 1 — Component version/hash (WS1)

- Component `content_hash` (SHA-256, truncated to 16 chars) stored in the KYA
  registry's `component_snapshots` table (schema v5).
- `safeai registry components` CLI lists tracked components with deduplication,
  type filtering, and consuming-agent resolution.
- Hash-based `_has_changed()` in `component_diff` replaces data-equality checks.

### Workstream 2 — `safeai init` + custom rule scaffold (WS2)

- `safeai init [--profile NAME] [--force]` scaffolds `.safeai/` with `config.yml`,
  `policy.yml`, `suppressions.yml`, and `rules/example_rules.yaml`.
- Identity-preserving init: existing `local_project_uuid` and `project_id` are
  never overwritten.
- `load_rules()` auto-discovers `.safeai/rules/` with validation and metadata.

### Workstream 3 — Governance signal detection (WS3)

- `GovernanceAnalyzer` detects missing operational governance controls:
  timeout, retry, approval (HITL), audit logging, rate limiting, circuit breaker
  pattern, backpressure/concurrency limits, and health check/readiness probes.
- Eight rules: `GOV_TIMEOUT_MISSING`, `GOV_RETRY_MISSING`,
  `GOV_APPROVAL_MISSING`, `GOV_AUDIT_MISSING`, `GOV_RATE_LIMIT_MISSING`,
  `GOV_CIRCUIT_BREAKER_MISSING`, `GOV_BACKPRESSURE_MISSING`,
  `GOV_HEALTH_CHECK_MISSING`.
- Per-tool deduplication; source-level confirmation scoped to ±10 lines.

### Workstream 4 — Control mappings taxonomy (WS4)

- Structured mapping layer between SafeAI rules and external control
  frameworks: OWASP Top 10 for LLM Applications (2025), OWASP Top 10 for
  Agentic Applications (2025), and NIST AI RMF 1.0.
- `map_rule_to_controls()` and `map_findings_to_controls()` API.
- Taxonomy only — never a compliance or coverage claim.

### Workstream 5 — Adapter completion (WS5)

- AutoGen framework adapter; detection tightened (requires import, class usage,
  or registration pattern — no bare substring).
- LangGraph parser detects `add_conditional_edges()`; detection tightened
  (requires `StateGraph` — no loose `Graph(` match).
- Browser automation rules split: `CAP_browser_playwright`,
  `CAP_browser_selenium`, `CAP_browser_use`.

### Workstream 6 — Heuristic data-flow depth (WS6)

- `DataFlowAnalyzer` tracks untrusted input propagation into sensitive sinks
  (prompts, tool calls, shell, file writes, HTTP requests, database queries).
- Six rules: `DATAFLOW_prompt`, `DATAFLOW_tool_call`, `DATAFLOW_shell`,
  `DATAFLOW_file_write`, `DATAFLOW_http_request`, `DATAFLOW_database`.
- Placeholder-aware confidence: `test_`, `example_`, `dummy_`, `mock_`,
  `fake_`, `sample_`, `fixture_`, `stub_`, `temp_`, `tmp_` prefixes skipped.
- `.py`-only file filter; governance source confirmation scoped to ±10 lines.

### Community contributors

Thank you to the following community members for their contributions:

- **[@Aming9303](https://github.com/Aming9303)** — contributed
  `safeai registry components` CLI (PR
  [#82](https://github.com/ikaruscareer/SafeAI/pull/82)),
  `safeai init` command (PR
  [#83](https://github.com/ikaruscareer/SafeAI/pull/83)), and a
  GitHub Actions workflow example (PR
  [#84](https://github.com/ikaruscareer/SafeAI/pull/84)).

### Verification Snapshot

- 564 tests passing, 1 skipped.
- Lint passing (`ruff check safeai/ tests/`).
- 76 built-in rules in `safeai/rules/base_rules.yaml`.

---

## v1.6.0 (2026-08-13)

**SafeAI 1.6.0 adds a Security Scorecard, a Community Scan programme, and a
hardened GitHub Action.** The scanner stays fully offline, static, and
local-first — nothing in this release executes agent code or calls an LLM.

### Headline: the SafeAI Security Scorecard

Every scan can now produce a **Security Scorecard** — a single deterministic
0–10 score with per-category breakdowns and a `pass`/`warn`/`fail` outcome,
designed to be the first thing a reviewer reads on a PR.

- **Transparent scoring**: severity weights (`critical=4.0 … info=0.0`),
  diminishing returns for repeated findings, and fingerprint deduplication are
  all documented in `safeai/scorecard.py`. Identical findings always produce an
  identical score.
- **Suppressed findings never move the score** — waivers are respected without
  silently hiding findings.
- **Five new flags**: `--scorecard` / `--scorecard-md`, `--scorecard-json`,
  `--scorecard-summary` (GitHub Actions step summary), and
  `--scorecard-fail-under N` to gate CI on a minimum score.
- **Machine-readable**: `safeai-scorecard.json` conforms to
  `safeai/scorecard-schema.json` (`schema_version: 1`), and every rendering
  Markdown-escapes and secret-redacts untrusted finding text.

```bash
safeai scan . --scorecard scorecard.md --scorecard-json scorecard.json \
  --scorecard-fail-under 7.0
```

### Community Scan programme (private pilot)

SafeAI can now be pointed at **public third-party agent frameworks** under a
governed, responsible-disclosure process (`community-scans/`): a target
manifest, a documented methodology and disclosure policy, provenance manifests,
and a sanitiser that turns a private report into a public-safe summary.
Everything is **private by default**; nothing is published without human
review. CI runs with `contents: read`, SHA-pinned actions, a concurrency group,
and a 30-minute timeout.

### GitHub Action & packaging hardening

- The package version is now read dynamically from `safeai.__version__`, so
  source and metadata cannot drift.
- `scripts/safeai-action.py` supports a hermetic install via
  `SAFEAI_ACTION_FIND_LINKS`, rejects control characters in path inputs, and
  strips newlines from `$GITHUB_OUTPUT` values to block output injection.
- `safeai --version` / `-V` prints a stable machine-readable version line
  (`safeai/version.py`), and a new `DEVELOPER_GUIDE.md` covers local and
  Actions usage.

### Verification Snapshot

- 459 tests collected; scorecard, community-scan, and action suites green.
- Lint passing (`ruff check safeai/ tests/ scripts/ community-scans/`).
- Scorecard output validated against `safeai/scorecard-schema.json`.

### Upgrade Notes

- No breaking changes to existing CLI flags, exit codes, or report shapes; all
  scorecard flags are opt-in.
- The informational scorecard is additive — existing SARIF/JSON/HTML outputs
  are unchanged unless a `--scorecard*` flag is supplied.

## v1.5.0 (2026-08-11)

First **stable** release (`5 - Production/Stable`). In addition to the CE 1.5
environment dependency inventory work, this release makes SafeAI consumable
as a GitHub Actions **Marketplace action**.

### Major Additions

- **GitHub Actions Marketplace action** (`action.yml` composite action):
  - Inputs: `path`, `version`, `fail-on`, `sarif`, `rules`, `baseline`,
    `fail-on-new`, `fail-on-escalation`, `no-registry`, `extra-args`.
  - Output: `sarif-path`.
  - Installs `SafeAI-Static-Analyzer` from PyPI and runs `python -m safeai
    scan` on the repository; native exit codes are preserved.
  - Inputs are passed as environment variables to a pure-Python driver
    (`scripts/safeai-action.py`) and forwarded as an argv list — nothing is
    ever evaluated by a shell. Least-privilege (`contents: read` only).
  - SARIF is written even when a scan fails, so `if: always()` upload steps
    still produce code-scanning alerts. `no-registry: true` is the default to
    keep scans ephemeral.
- **Self-validating CI** (`.github/workflows/action-test.yml`): exercises the
  action itself against fixture repositories, builds/installs the wheel, and
  validates SARIF on every commit. 24 new tests in `tests/test_github_action.py`.
- **Environment and credential dependency inventory** with
  dependency-to-capability correlation (`DEP_UNDECLARED_CAPABILITY`,
  `DEP_ORPHANED_TOOL`).

### Fixed

- Packaging: version → `1.5.0`, classifier → `5 - Production/Stable`;
  `_safeai_version()` resolves through `SafeAI-Static-Analyzer` metadata;
  wheel package-data verified (`safeai/rules/base_rules.yaml`).

### Usage

```yaml
- uses: ikaruscareer/SafeAI@v1.0.0
  with:
    path: .
    fail-on: critical
```

### Verification Snapshot

- Full test suite passing (373 tests, 1 skip).
- Lint passing (`ruff check safeai/ tests/ scripts/`).
- Wheel and source distribution build successfully.
- End-to-end published-style install validated (build → venv install → scan →
  SARIF + exit-code checks) for both a clean fixture (exit 0) and a risky
  fixture (exit 1, SARIF preserved).

## v1.3.0-beta (2026-07-31)

Release 1.3 introduces **KYA (Know Your Agent)** baseline and local registry
capabilities while preserving SafeAI's offline-first static-analysis model.

### Major Additions

- **Canonical manifest**: `safeai-manifest.json` (`schema_version: "1.0"`,
  `manifest_type: "safeai.kya"`) as the portable contract.
- **Deterministic finding identity**: stable `finding_id`/`fingerprint`
  generation, confidence labels (`high|medium|low`), provenance, and
  remediation normalization.
- **Baseline diffing**: `--baseline` and `--fail-on-new` for PR-focused
  gating (new/regressed findings only).
- **Suppressions**: `.safeai/suppressions.yml` with required reason/owner/
  created date, optional expiry and path scope.
- **Policy-as-code**: `.safeai/policy.yml` with actions `allow`, `warn`,
  `require_review`, `deny` and deterministic evaluation.
- **Local SQLite registry**: `.safeai/registry.db` with append-only scan
  history and agent snapshots.
- **Registry CLI**:
  - `safeai registry list`
  - `safeai registry show <agent-id>`
  - `safeai registry history <agent-id>`
  - `safeai registry diff <agent-id> --from previous --to latest`
  - `safeai registry export --format json --output <path>`

### New Scan Flags

- `--manifest`
- `--baseline`
- `--fail-on-new`
- `--registry`
- `--no-registry`
- `--strict-registry`
- `--policy`
- `--suppressions`

### Behavior and Compatibility Notes

- Existing `--fail-on` behavior is preserved unless `--fail-on-new` is
  explicitly used.
- Registry persistence is local-only and enabled by default for interactive
  scans; it is auto-disabled when `CI` is detected unless `--registry` is
  explicitly provided.
- Report schema changes are additive.

### Verification Snapshot

- Full test suite passing (141 tests)
- Lint checks passing (`ruff check safeai/ tests/`)
- End-to-end CLI flows validated for scan, manifest, baseline, suppressions,
  policy, registry, and export.

## v1.1.0-beta (2026-07-24)

Phase 1.5 AI Component Security and stabilization release for SafeAI, the Static AI Capability & Risk Analyzer. This release remains entirely offline and static: SafeAI does not execute agents, invoke tools, call LLMs, or contact reputation services.

### New Features

- **AI Component Security**
  - Discovers skills, prompt files, tool definitions, model configurations, and workflow templates.
  - Reports component inventories in JSON, project graphs, terminal summaries, and HTML reports.

- **Skill Analysis**
  - Detects embedded prompts, hardcoded secrets, excessive permissions, insecure defaults, and risky capabilities.

- **Prompt File Analysis**
  - Scans prompt and system-instruction files for injection-prone placeholders, system prompt exposure, role overrides, and untrusted input interpolation.
  - Supports `CLAUDE.md`, `prompt.md`, `system_prompt.md`, `.prompt`, `.prompt.md`, and `.prompt.txt` artifacts.

- **Tool Definition Analysis**
  - Detects missing input validation, dangerous parameters, shell execution, and excessive tool permissions.

- **Model Configuration Analysis**
  - Detects unsafe temperature settings and explicitly disabled safety controls.
  - Applies provider-aware checks for Google, Bedrock, and Azure model safety settings.

- **Workflow Template Analysis**
  - Detects missing approval gates, insecure defaults, capability sprawl, and missing validation.

- **Deep MCP Analysis**
  - Adds per-tool broad-permission analysis.
  - Detects resources that may expose sensitive data.
  - Detects insecure MCP transports.

- **Framework Coverage**
  - Adds early-preview adapters for Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, and n8n.
  - SafeAI now includes 15 built-in framework parsers.

- **Capability Diff**
  - Compares the current normalized capability inventory with a previous JSON report.
  - Use `safeai scan <directory> --baseline previous-report.json`.

### Stabilization Improvements

- Parser registry now supports installed third-party parsers through the `safeai.parsers` entry-point group.
- Duplicate parser names and invalid parser interfaces are rejected safely.
- Component paths are normalized to scan-relative paths for portable reports.
- Component extraction diagnostics are exposed in scan reports.
- Dify and n8n detection was tightened to reduce generic configuration false positives.
- Framework dependency extraction includes the new early-preview frameworks.
- README, framework support documentation, roadmap, and release metadata now distinguish established and early-preview adapters.

### Verification

- 51 automated tests passing.
- Ruff checks passing.
- Wheel and source distribution build successfully.

### Known Limitations

- The seven new framework adapters are early-preview integrations with limited framework-specific depth.
- Capability diff compares serialized static inventories; it does not infer runtime behavior.
- JavaScript/TypeScript source analysis remains limited.
- Runtime prompt injection, jailbreak, hallucination, and tool execution testing remain outside the scope of SafeAI.

## v1.0.0-beta (2026-07-14)

Initial beta release of SafeAI — the Static AI Capability & Risk Analyzer for AI agent codebases.

### Features

- **Multi-Framework Scanning**
  - LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents
  - Microsoft Agent, Azure AI Foundry, Bedrock Agent
  - Automatic framework detection (AST + config + dependency analysis)

- **Prompt Injection Detection**
  - Direct user input interpolation into prompts (LLM01)
  - Missing delimiters between system and user content
  - System prompt leakage detection
  - Role override / instruction override attempts

- **Capability Analysis**
  - Shell execution, filesystem, HTTP, database, code execution
  - Autonomous agent loop detection
  - OWASP LLM06 (Excessive Agency) coverage

- **Data Leakage Detection**
  - Hardcoded API keys, tokens, passwords
  - Environment variable references to secrets

- **MCP (Model Context Protocol) Analysis**
  - Configuration discovery across project files
  - Schema validation (v1.0, v1.1)
  - Authentication and permissions gap detection
  - Endpoint exposure and secret detection

- **Trust Score**
  - Deterministic, reproducible risk scoring (0–100)
  - 7 risk categories with configurable weights
  - Confidence-weighted findings

- **Report Output**
  - Terminal (human-readable summary)
  - JSON (machine-readable)
  - SARIF 2.1.0 (GitHub Advanced Security compatible)
  - HTML (self-contained interactive report)

- **Custom Rules**
  - User-defined YAML rule overrides via `--rules`
  - Merge with built-in rules

- **Exit Code Integration**
  - Configurable `--fail-on` threshold for CI/CD pipelines

### Known Limitations (Beta)

- Dynamic prompt injection at runtime is not detectable via static analysis
- Framework detection is heuristic-based; some complex configurations may not be detected
- Python-only source analysis (JavaScript/TypeScript agent code not yet supported)
- MCP analysis supports v1.0 and v1.1 schemas only
- Dependency scanning is framework-agnostic (name/version extraction only; no CVE matching)

### Installation

```bash
pip install git+https://github.com/ikaruscareer/SafeAI.git
```

### Quick Start

```bash
safeai scan /path/to/project
safeai scan /path/to/project --json report.json
safeai scan /path/to/project --html report.html --fail-on medium
```
