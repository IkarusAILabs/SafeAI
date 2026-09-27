# SafeAI — Technical Architecture

This document describes the technical architecture of the SafeAI Static AI
Capability & Risk Analyzer. It reflects the v2.5 structure: the scan engine is
split into an orchestrator and a post-scan KYA pipeline, the registry is a
focused package, authority decisions run on Lane A (deterministic gates) vs
Lane B (human review), and IaC authority evidence feeds the authority model.

---

## Overview

SafeAI is a modular, plugin-based static analysis tool. It runs as a pipeline
of independent stages, split into two halves:

1. **Scan engine** (`engine/orchestrator.py`) — collect, parse, analyze, score.
2. **KYA post-processing** (`cmd/postprocess.py`) — normalize, suppress, diff
   against a baseline, evaluate policy, and persist evidence.

```
Source Code
    │
    ▼
prepare ──► load_sources ──► parse_frameworks ──► extract_components
    │                                                      │
    ▼                                                      ▼
analyze (13 analyzers) ──────────────────────► assemble (score, tool surface,
    │                                                      assurance boundary)
    ▼
ScanPostProcessor: normalize → suppress → baseline → policy → identity
                   → manifest → registry → outputs → exit code
    │
    ▼
Report Generation (Terminal / JSON / SARIF / HTML / PR comment / Scorecard)
```

SafeAI never executes the scanned code, never imports it, and never makes a
network call. Every stage is deterministic: identical input produces identical
output.

---

## Package Structure

```
safeai/
├── __init__.py               # package init; handles `safeai --version`
├── version.py                # SAFEAI_VERSION + version helpers (single source)
├── severity.py               # canonical severity vocabulary + point values
├── scorecard.py              # Security Scorecard (0-10) build/render/write
├── scorecard-schema.json     # machine-readable scorecard contract (schema v1)
├── cmd/                      # CLI entry points
│   ├── cli.py                # argparse shell: scan + registry subcommands
│   ├── postprocess.py        # ScanPostProcessor (KYA pipeline)
│   └── registry_cli.py       # registry list/show/history/diff/export
├── engine/                   # scan orchestration
│   ├── orchestrator.py       # ScanOrchestrator (6 stages) + run_scan wrapper
│   └── scan.py               # backward-compat re-export of run_scan
├── kya/                      # Know Your Agent evidence pipeline
│   ├── util.py               # hashing, timestamps, secret redaction
│   ├── identity.py           # project/agent ID derivation
│   ├── fingerprints.py       # deterministic finding fingerprints
│   ├── enrich.py             # finding normalization, agent records
│   ├── manifest.py           # canonical safeai-manifest.json
│   ├── baseline.py           # new/existing/resolved comparison
│   ├── suppressions.py       # .safeai/suppressions.yml workflow
│   ├── policy.py             # .safeai/policy.yml evaluator
│   ├── assurance.py          # assurance boundary (verified vs not)
│   ├── ci_context.py         # CI provider/branch/PR detection
│   ├── exporter.py           # registry inventory export
│   └── registry/             # local SQLite registry (package)
│       ├── schema.py         # DDL + forward-only migrations
│       ├── connection.py     # paths, open, migrate, init
│       ├── persist.py        # append-only scan persistence
│       └── queries.py        # read-only query helpers
├── analysis/                 # core analysis primitives
│   ├── semantic.py           # AST document, symbol resolution
│   ├── import_graph.py       # project-wide import tracking
│   ├── capabilities.py       # capability model & helpers
│   ├── aggregation.py        # multi-parser merge & arbitration
│   ├── project_graph.py      # cross-file entity graph
│   ├── components.py         # component-level extraction
│   ├── tool_identity.py      # path-independent tool keys
│   ├── tool_surface.py       # per-tool capability index
│   ├── capability_diff.py    # schema-v2 per-tool baseline diff
│   ├── escalation.py         # 14 ESC_* capability-escalation rules
│   └── dependency_correlation.py  # DEP_* credential/capability correlation
├── analyzers/                # analysis modules (11)
│   ├── capability/           # CapabilityAnalyzer
│   ├── prompt/               # PromptAnalyzer
│   ├── prompt_file/          # PromptFileAnalyzer
│   ├── data_leakage/         # DataLeakageAnalyzer
│   ├── env_dependency/       # EnvDependencyAnalyzer (CE 1.5)
│   ├── mcp/                  # MCPAnalyzer (+ schema/compatibility/validators)
│   ├── claude_code/          # ClaudeCodeAnalyzer
│   ├── skill/                # SkillAnalyzer
│   ├── tool_def/             # ToolDefAnalyzer
│   ├── model_config/         # ModelConfigAnalyzer
│   └── workflow/             # WorkflowAnalyzer
├── frameworks/               # framework adapters (15)
│   ├── langgraph/  crewai/  langchain/  semantic_kernel/
│   ├── openai_agents/  microsoft_agent/  azure_foundry/  bedrock_agent/
│   └── claude_code/  google_adk/  mastra/  haystack/  llamaindex/  dify/  n8n/
├── report/                   # output generators
│   ├── terminal.py           # console summary
│   ├── json_report.py        # JSON output
│   ├── sarif.py              # SARIF 2.1.0 output
│   ├── html.py               # self-contained HTML report
│   ├── html_kit.py           # shared HTML rendering helpers
│   ├── registry_html.py      # registry HTML views
│   └── pr_comment.py         # reviewer-facing escalation summary
├── rules/                    # rule definitions
│   ├── loader.py             # rule loading/merge
│   └── base_rules.yaml       # built-in rules
└── scoring/
    └── engine.py             # deterministic 0-100 trust score
```

---

## Component Descriptions

### 1. CLI (`cmd/cli.py`)

A thin `argparse` shell over the pipeline. It parses `scan` and `registry`
subcommands, delegates the scan to `run_scan()` + `ScanPostProcessor`, and maps
results to exit codes. It contains no analysis logic.

**Exit codes:** `0` = pass, `1` = policy/finding/escalation/score gate hit,
`2` = operational error. The Security Scorecard adds `--scorecard-fail-under`
as an additional gate.

### 2. Scan Orchestrator (`engine/orchestrator.py`)

`ScanOrchestrator` drives the scan as six individually callable stages:

1. `prepare()` — file collection (Python/YAML/JSON/dependency manifests), rule
   loading, dependency extraction, parser discovery.
2. `load_sources()` — read files, build AST semantic documents, construct the
   import graph.
3. `parse_frameworks()` — run all framework parsers on all files (no mutual
   exclusion), capture provenance.
4. `extract_components()` — component-level extraction, parser aggregation,
   capability normalization.
5. `analyze()` — the multi-analyzer pipeline.
6. `assemble()` — relativize paths, score the report, build the tool surface
   and the assurance boundary.

The module-level `run_scan()` is the historical entry point and a thin wrapper
over the orchestrator; `safeai.engine.scan` re-exports both for backward
compatibility.

### 3. KYA Post-Processor (`cmd/postprocess.py`)

`ScanPostProcessor` runs after `run_scan()` and owns the evidence pipeline:

```
normalize → suppress → baseline → policy → identity → manifest → registry
          → outputs → exit code
```

It writes the canonical manifest, persists to the registry, renders reports,
and computes the final exit code. The engine itself is untouched by KYA.

### 4. Severity (`severity.py`)

The single source of truth for the severity vocabulary. Finding severities are
`info < low < medium < high < critical`; escalation severities never use
`info`. `SEVERITY_POINTS` (`critical=25, high=15, medium=8, low=4, info=1`) is
defined here and imported by the CLI, escalation engine, policy evaluator,
scorers, and renderers so the scales cannot drift.

### 5. Analyzers (`analyzers/*/analyzer.py`)

Each analyzer implements `run(file_cache, rules, agent_models=None)`. The 11
analyzers:

| Analyzer | Purpose |
|----------|---------|
| `CapabilityAnalyzer` | Framework capability arbitration + regex fallback |
| `PromptAnalyzer` | Prompt injection, delimiter, system leak, role override |
| `PromptFileAnalyzer` | Prompt / system-instruction file analysis |
| `DataLeakageAnalyzer` | API keys, tokens, passwords, env secrets |
| `EnvDependencyAnalyzer` | Credential/config dependency inventory (CE 1.5) |
| `MCPAnalyzer` | MCP discovery, schema validation, security analysis |
| `ClaudeCodeAnalyzer` | Deep `.claude/` structural analysis |
| `SkillAnalyzer` | Skill component analysis |
| `ToolDefAnalyzer` | Tool definition analysis |
| `ModelConfigAnalyzer` | Model configuration safety checks |
| `WorkflowAnalyzer` | Workflow template analysis |
| `DataFlowAnalyzer` | Untrusted-input → sensitive-sink heuristics (gate-inert) |
| `GovernanceAnalyzer` | Timeout/retry/approval/audit/rate-limit controls + failure classes |

### 6. Framework Adapters (`frameworks/*/parser.py`)

20 adapter packages: LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents,
Microsoft Agent, Azure AI Foundry, Bedrock Agent, Claude Code, Google ADK,
Mastra, Haystack, LlamaIndex, Dify, n8n, AutoGen, Cursor Rules, Windsurf,
OpenClaw, Copilot. Each implements `detect()` and
`parse()` and returns a consistent artifact schema (agents, workflows, tools,
prompts, memory, models, capabilities, relationships) with confidence and
provenance. See "Plugin Architecture" below.

### 7. Capability Model & Escalation (`analysis/`)

- `tool_identity.py` — capabilities are attributed to a named tool with a
  deterministic `tool_key` (e.g. `mcp_server:invoice-lookup`).
- `tool_surface.py` — per-tool capability index written to the report, manifest,
  and registry.
- `capability_diff.py` — schema-v2 baseline diff keyed on
  `(tool_key, capability, access_mode)`.
- `escalation.py` — 14 `ESC_*` rules (including 3 combination rules) that rank
  authority changes between scans; drives `--fail-on-escalation`.
- `dependency_correlation.py` — matches the CE 1.5 credential/config inventory
  against declared capabilities, producing `DEP_UNDECLARED_CAPABILITY` and
  `DEP_ORPHANED_TOOL`.
- `iac_correlation.py` (v2.5) — matches IaC Grant triples (Terraform, K8s
  RBAC) against the declared tool surface, producing `IAC_EXCESS_AUTHORITY`,
  `IAC_AUTHORITY_MISMATCH`, `IAC_UNVERIFIED_LINK` (all review-only, Lane B).
- `capability_diff.py` change classification (`NO/LOW/MATERIAL/HIGH_RISK/
  UNKNOWN` × semantic `change_types`) feeds `--fail-on-authority-change`
  and the policy lanes (`safeai/kya/policy.py`: Lane A deterministic
  gates vs Lane B human-review questions).

### 8. KYA Registry (`kya/registry/`)

A local, append-only SQLite registry (`.safeai/registry.db`, or the org-wide
shared registry via `SAFEAI_REGISTRY` / `~/.safeai/registry.db`). Standard
library `sqlite3` only, WAL mode, versioned via `schema_migrations`. Split into
`schema` (DDL + forward-only migrations), `connection` (open/migrate/init),
`persist` (append-only writes), and `queries` (read-only helpers); the package
`__init__` re-exports the public API. Raw source and unredacted secrets are
never stored.

### 9. Assurance Boundary (`kya/assurance.py`)

A factual, per-scan statement of what was verified statically versus what
cannot be verified (IAM/cloud permissions, runtime identity, deployed network
policy, actual behaviour). Computed from real scan data, never a fixed
template. Written to the manifest as `assurance_boundary`.

### 10. Trust Scoring (`scoring/engine.py`)

Deterministic 0–100 scoring across **7 risk categories** — Capability,
Governance, Safety, Identity, Integration, Autonomy, Enterprise Readiness
(default weight 1.0 each). Formula:
`category_score = clamp(100 - sum(weighted_contributions), 0, 100)`;
`overall = average(category_scores)`. The result key is
`overall_ai_risk_score`. See `RISK_MODEL.md`.

### 11. Security Scorecard (`scorecard.py`)

A separate, deterministic **0–10** report (distinct from the 0–100 trust
score): an overall score, per-category scores, and a `pass`/`warn`/`fail`
outcome. Severity weights `critical=4.0, high=2.0, medium=0.75, low=0.25,
info=0.0`, with diminishing returns for repeated findings and fingerprint
deduplication. Suppressed findings do not affect the score. Rendered to
Markdown, JSON (`scorecard-schema.json`), and the GitHub Actions step summary.
See `USER_GUIDE.md` and `DEVELOPER_GUIDE.md`.

### 12. Report Generators (`report/*.py`)

| Generator | Output | Format |
|-----------|--------|--------|
| `terminal.py` | Console summary | Plain text |
| `json_report.py` | Raw scanner output | JSON |
| `sarif.py` | SARIF 2.1.0 | JSON (SARIF) |
| `html.py` (+ `html_kit.py`) | Self-contained report | HTML |
| `registry_html.py` | Registry views | HTML |
| `pr_comment.py` | Reviewer escalation summary | Markdown |
| `scorecard.py` | Security Scorecard | Markdown / JSON |

---

## Data Flow

```
Project Directory
    │
    ▼
prepare: collect_files (.py/.json/.yaml/.yml + dependency manifests)
    │      + rules loading + dependency extraction + parser discovery
    ▼
load_sources: semantic documents (AST) + import graph
    │
    ▼
parse_frameworks: all 20 parsers on all files (no mutual exclusion)
    │
    ▼
extract_components: component extraction + parser aggregation + capabilities
    │
    ▼
analyze: 13 analyzers (capability, prompt, prompt_file, data_leakage,
         dataflow, env_dependency, governance, mcp, claude_code, skill,
         tool_def, model_config, workflow)
    │
    ▼
assemble: relativize paths + trust score + tool surface + IaC authority
         correlation + assurance boundary
    │
    ▼
ScanPostProcessor: normalize → suppress → baseline → policy → identity
                   → manifest → registry → outputs → exit code
    │
    ▼
Reports: Terminal │ JSON │ SARIF │ HTML │ PR comment │ Scorecard
```

---

## Agent Authority Model

The pipeline above converges on one analytical concept: **agent
authority** — what an agent is empowered to do, derived statically:

```
Agent → Tool / MCP Server / Skill / Workflow Node → Capability
  → Access Mode (none < read < write < mutate < execute)
    → Data / Destination / Resource → Authority
```

Tool identity (`safeai/analysis/tool_identity.py`), tool surface, and
capability diff (schema v2) key this model on `(tool_identity,
capability, access_mode)`; escalation rules (`ESC_*`) and policy
outcomes (`pass | warn | review-required | block |
accepted-exception`) decide on *changes* to it. Since v2.5 the model
canonically extends to **Identity** (a name string — service account,
role, principal) and **Grant** (`(principal, action-pattern,
resource-pattern, source_ref)` triples from in-repo Terraform /
Kubernetes YAML, `safeai/iac/`), joined by correlation verdicts
(`MATCH | EXCESS_AUTHORITY | AUTHORITY_MISMATCH | UNVERIFIED_LINK |
UNKNOWN`, default `UNVERIFIED_LINK`; ADR-0007). Authority classes:
declared · detected · inferred (confidence-labelled) ·
repository/IaC-observed · unknown · runtime-granted (out of scope for
static analysis). Unknown is an evidence state, not evidence of safety.
Strategy: `ROADMAP.md` (Discover / Compare / Govern),
`docs/STRATEGIC_POSITIONING.md`.

---

## Plugin Architecture

Framework adapters, analyzers, and rules are pluggable. Adapters follow a
plugin-like pattern:

1. **Self-contained** — no cross-framework dependencies.
2. **Auto-detection** — `detect()` determines applicability (AST imports →
   dependency manifest → config files → regex fallback).
3. **Structured output** — a consistent artifact dictionary schema.
4. **Confidence-aware** — reports parser-level confidence and discovery method.

Third-party parsers can also register via the `safeai.parsers` entry-point
group and the `@register_parser` decorator; analyzers work the same way
via `@register_analyzer` (core/component phases) and the
`safeai.analyzers` entry-point group, running isolated so a raising
plugin never fails a scan.

**To add a new framework adapter:**
1. Create `frameworks/new_framework/parser.py`.
2. Implement `detect()` and `parse()`.
3. Decorate with `@register_parser` (no orchestrator edits needed).

---

## Configuration Sources

SafeAI reads configuration from:

1. **Rule YAML files** — `rules/base_rules.yaml` (built-in) + custom via `--rules`.
2. **Dependency manifests** — `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json`.
3. **Source code** — Python files (`.py`).
4. **Configuration files** — `.json`, `.yaml`, `.yml`.
5. **KYA config** — `.safeai/policy.yml`, `.safeai/suppressions.yml`.
6. **CLI arguments** — output paths, thresholds, scorecard and gating flags.

---

## Related Documents

- `RISK_MODEL.md` — trust score model, categories, and score interpretation.
- `SECURITY_MODEL.md` — threat model and security properties of SafeAI itself.
- `KYA_MANIFEST.md` — the canonical manifest contract.
- `REGISTRY.md` — the local/shared KYA registry.
- `LIMITATIONS.md` — what static analysis cannot verify.
- `DEVELOPER_GUIDE.md` — local development and GitHub Actions usage.
