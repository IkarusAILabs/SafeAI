# SafeAI User Guide — Early Preview

> 🌐 [safeai-analyzer.ikaruscareer.com](https://safeai-analyzer.ikaruscareer.com) — project landing page

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Running Scans](#running-scans)
4. [CLI Commands](#cli-commands)
5. [Input Formats](#input-formats)
6. [Supported Project Types](#supported-project-types)
7. [Understanding Results](#understanding-results)
8. [Reports](#reports)
9. [KYA Registry](#kya-registry)
10. [Baseline Workflow](#baseline-workflow)
11. [PR Comments & Capability Escalation](#pr-comments--capability-escalation)
12. [Suppressions & Exceptions](#suppressions--exceptions)
13. [Policy-as-Code](#policy-as-code)
14. [Troubleshooting](#troubleshooting)
15. [FAQ](#faq)

---

## Installation

### System Requirements

- Python 3.11, 3.12, or 3.13
- Operating system: Linux, macOS, Windows
- No external service dependencies
- No GPU required

### Install from Source

```bash
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
pip install -e .
```

Dependencies installed:

- `PyYAML` — YAML configuration file parsing

The SafeAI package itself is installed in editable mode, providing both the
`safeai` command and `python -m safeai`.

### Verify Installation

```bash
safeai scan --help
# or equivalently:
python -m safeai scan --help
```

Expected output:

```
usage: safeai scan [-h] [--sarif SARIF] [--json JSON_PATH] [--html HTML_PATH]
                   [--manifest MANIFEST_PATH] [--rules RULES]
                   [--fail-on {critical,high,medium}] [--verbose]
                   [--baseline BASELINE] [--fail-on-new]
                   [--registry REGISTRY] [--no-registry] [--strict-registry]
                   [--pr-comment PR_COMMENT_PATH] [--pr-comment-stdout]
                   [--fail-on-escalation {critical,high,medium}]
                   [--policy POLICY] [--suppressions SUPPRESSIONS]
                   directory
```

---

## Configuration

SafeAI requires no configuration file. By default it uses built-in rules from `rules/base_rules.yaml`.

### Custom Rules Directory

You can supply custom rule YAML files:

```bash
python -m safeai scan . --rules ./my-rules/
```

Custom rules merge with built-in rules. Duplicate rule IDs overwrite severity and description.

Validate a pack (rules + expected-findings fixtures) offline:

```bash
safeai rules check ./my-rules/
```

See `docs/guides/COMMUNITY_PACKS.md` for the pack contract.

### Rule File Format

```yaml
- id: CUSTOM_RULE
  description: Description of the rule
  severity: high
  owasp_llm: LLM06
```

### Exit Threshold

```bash
python -m safeai scan . --fail-on high   # exit 1 if any high+ finding
```

Valid values: `critical` (default), `high`, `medium`.

---

## Running Scans

### Basic Scan

```bash
python -m safeai scan /path/to/project
```

### Generate All Reports

```bash
python -m safeai scan /path/to/project \
    --sarif results.sarif \
    --json results.json \
    --html report.html
```

### Skip SARIF Output

```bash
python -m safeai scan /path/to/project --sarif ""
```

---

## CLI Commands

### `scan` — Run a static AI risk scan

```
usage: safeai scan [-h] [--sarif SARIF] [--json JSON_PATH]
                   [--html HTML_PATH] [--manifest MANIFEST_PATH]
                   [--rules RULES] [--fail-on {critical,high,medium}]
                   [--verbose] [--baseline BASELINE] [--fail-on-new]
                   [--registry REGISTRY] [--no-registry] [--strict-registry]
                   [--pr-comment PR_COMMENT_PATH] [--pr-comment-stdout]
                   [--fail-on-escalation {critical,high,medium}]
                   [--policy POLICY] [--suppressions SUPPRESSIONS]
                   directory
```

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `directory` | positional | required | Target project directory |
| `--sarif` | string | `report.sarif` | SARIF output file path |
| `--json` | string | — | JSON output file path |
| `--html` | string | — | HTML report output path |
| `--manifest` | string | — | Canonical KYA manifest output path |
| `--rules` | string | built-in | Path to custom rules directory |
| `--fail-on` | choice | `critical` | Minimum severity for non-zero exit |
| `--baseline` | string | — | Baseline manifest/report for status comparison |
| `--fail-on-new` | flag | off | Fail only on new/regressed findings when baseline is supplied |
| `--registry` | string | shared | Override registry database path (default: `SAFEAI_REGISTRY` env var or `~/.safeai/registry.db`) |
| `--no-registry` | flag | off | Do not persist scan state to local registry |
| `--strict-registry` | flag | off | Fail scan on registry persistence errors |
| `--strict-analysis` | flag | off | Exit 2 when the analysis is incomplete (unreadable file, failed parser, extractor or analyser plugin, or no file read). See `analysis_completeness` in the JSON report |
| `--pr-comment` | string | — | Write a reviewer-facing Markdown summary of capability escalations to this path. SafeAI never posts it anywhere. |
| `--pr-comment-stdout` | flag | off | Print the PR comment Markdown to stdout, in addition to or instead of writing it to a file |
| `--fail-on-escalation` | choice | — | Fail the scan when a capability escalation at or above `critical`, `high`, or `medium` is detected. Requires `--baseline`; this is a separate axis from `--fail-on`/`--fail-on-new`, which gate on findings rather than capability escalations. |
| `--policy` | string | `.safeai/policy.yml` | Policy-as-code file path. A path given here that does not exist is an error (exit 2) |
| `--suppressions` | string | `.safeai/suppressions.yml` | Suppression file path |
| `--verbose` | flag | off | Enable verbose scanner output |

### `registry` — Query local KYA history

```bash
safeai registry list [--project-dir DIR] [--registry PATH] [--format table|json|html]
safeai registry show <agent-id> [--scan <scan-id>] [--project-dir DIR] [--registry PATH] [--format table|json|html]
safeai registry history <agent-id> [--project-dir DIR] [--registry PATH] [--format table|json|html]
safeai registry diff <agent-id> --from previous --to latest [--project-dir DIR] [--registry PATH] [--format table|json|html]
safeai registry export --format json --output <path> [--include-history] [--include-suppressed] [--project-dir DIR] [--registry PATH]
safeai registry export --format html --output <path> [--include-history] [--include-suppressed] [--project-dir DIR] [--registry PATH]
```

`--format html` prints a self-contained, shareable report page (dark-mode
aware, searchable tables) — redirect it to a file:

```bash
safeai registry list --format html > registry.html
safeai registry show <agent-id> --format html > agent.html
safeai registry diff <agent-id> --format html > diff.html
```

`--project-dir DIR` inspects the per-project registry `DIR/.safeai/registry.db`
(useful for databases created before the shared default). Without any of
`--project-dir`/`--registry`, the shared registry is used (`SAFEAI_REGISTRY`
env var or `~/.safeai/registry.db`) — the same place `safeai scan` writes by
default, so agents from every scanned project are listed together.
`--registry PATH` always wins.

---

## Input Formats

SafeAI scans files with the following extensions:

- `.py` — Python source files (primary target for framework detection)
- `.json` — JSON configuration files (MCP configs, Bedrock agents)
- `.yaml`, `.yml` — YAML configuration files (Azure Foundry, MCP configs)

### Dependency Files

SafeAI also scans these files for framework detection:

- `requirements.txt` — Python pip dependencies
- `Pipfile` — Pipenv dependencies
- `pyproject.toml` — Python project metadata
- `package.json` — Node.js project metadata

---

## Supported Project Types

SafeAI is designed for projects that build or use AI agents, including:

- **LangGraph applications** — graph-based agent workflows
- **CrewAI projects** — multi-agent task orchestrators
- **LangChain applications** — chain-based LLM applications
- **Semantic Kernel projects** — plugin-based AI orchestrators
- **OpenAI Agents SDK projects** — agent-based assistants
- **Microsoft Agent Framework projects** — Azure AI Agent Service
- **Azure AI Foundry projects** — Azure AI configuration
- **Bedrock Agent projects** — AWS Bedrock agent definitions

---

## Understanding Results

### Findings

Each finding contains:

| Field | Description |
|-------|-------------|
| `rule_id` | Unique rule identifier |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `message` | Human-readable description |
| `file` | Source file path |
| `line` | Line number |
| `owasp_llm` | OWASP LLM category reference |
| `evidence` | Matching source code excerpt |
| `reason` | Explanation of the risk |
| `risk_category` | `Capability`, `Governance`, `Safety`, `Identity`, `Integration`, `Autonomy`, `Enterprise Readiness` |
| `affected_framework` | Detected framework name |
| `affected_capability` | Capability category affected |
| `score_contribution` | Points contributed to overall risk score |
| `remediation` | Recommended fix |
| `confidence` | Detection confidence (numeric, analyzer-level) |
| `confidence_label` | Normalized confidence (`high`, `medium`, `low`) |
| `fingerprint` / `finding_id` | Stable deterministic finding identity |
| `status` | `new`, `existing`, `regressed`, `resolved`, `suppressed`, `unknown` |
| `source` | Detection method (`ast`, `configuration`, `regex`, etc.) |
| `resolved_definition` | Resolved symbol origin (if import graph resolved) |
| `provenance_frameworks` | All frameworks that identified this finding |
| `schema_version` | (MCP only) Schema version used for validation |
| `validation_rule` | (MCP only) Validation rule that triggered |
| `affected_object` | (MCP only) MCP configuration section affected |

### Severity Levels

| Level | Meaning |
|-------|---------|
| Critical | Immediate risk of compromise (e.g., prompt injection, hardcoded secrets) |
| High | Significant capability exposure (e.g., shell execution, missing auth) |
| Medium | Moderate risk (e.g., filesystem access, database access) |
| Low | Informational (e.g., MCP reference without config) |
| Info | Scanner metadata |

---

## Risk Scores

### Trust Score (0–100)

SafeAI computes a deterministic risk score across 7 categories:

| Category | Description |
|----------|-------------|
| Capability | Risk from detected agent capabilities |
| Governance | Risk from missing governance controls |
| Safety | Risk from prompt safety issues |
| Identity | Risk from credential exposure |
| Integration | Risk from MCP and external integrations |
| Autonomy | Risk from autonomous agent behavior |
| Enterprise Readiness | Risk from missing enterprise controls |

### Score Interpretation

| Score Range | Meaning |
|-------------|---------|
| 0–20 | Excellent governance, low risk |
| 21–40 | Good, minor risks |
| 41–60 | Moderate risk, review findings |
| 61–80 | Significant risk, remediate before deployment |
| 81–100 | Critical risk, stop deployment |

---

## Reports

> For a complete guide to interpreting each output format, triaging findings,
> and understanding confidence vs. severity, see
> [REPORTING_GUIDE.md](./REPORTING_GUIDE.md).

### Terminal Summary

Printed to stdout. Includes:

- Files scanned
- Detected frameworks
- MCP asset count
- Overall AI Risk Score
- Finding count by severity
- Finding list with severity, location, message

### JSON Report

Full scanner output as JSON. Compatible with custom tooling.

### SARIF 2.1.0

SARIF format for integration with GitHub Advanced Security, Azure DevOps, and other SARIF-compliant tools. Each finding includes:

- `ruleId` — rule identifier
- `message.text` — finding description
- `locations[].physicalLocation` — file and line number
- `properties` — extended data (OWASP category, risk category, evidence, remediation)

### HTML Report

Self-contained HTML report with:

- Executive Summary
- Detected Frameworks
- Capability Matrix
- Risk Summary
- Trust Scores
- Governance Summary
- Findings table with evidence and recommendations

Responsive design, print-friendly.

### Security Scorecard

A deterministic 0–10 summary of a scan, intended to be the first thing a
reviewer reads. It reports an overall score, per-category scores, and a
`pass`/`warn`/`fail` outcome. It is a SafeAI report, not an OpenSSF Scorecard
report.

```bash
# Markdown + JSON scorecard
safeai scan . --scorecard scorecard.md --scorecard-json scorecard.json

# Gate CI on a minimum score (0-10)
safeai scan . --scorecard-fail-under 7.0

# In GitHub Actions, also append to the step summary
safeai scan . --scorecard-summary
```

Scoring is transparent and reproducible: severity weights
(`critical=4.0, high=2.0, medium=0.75, low=0.25, info=0.0`), diminishing
returns for repeated findings at the same location, and fingerprint
deduplication. Suppressed findings do not affect the score. The JSON output
conforms to `safeai/scorecard-schema.json`.

---

## KYA Registry

Every scan automatically creates or updates a **private, org-wide "Know Your
Agent" registry** (SQLite). By default it is a **single shared database** —
`SAFEAI_REGISTRY` env var if set, else `~/.safeai/registry.db` — so scans of
every project (CrewAI, AGT, LangGraph, ...) accumulate in one place and
`safeai registry list` shows the whole organization's agents from any folder.
No server, account, network call, or source upload.

> KYA records are **static analysis evidence** ("detected in
> source/configuration"). They never represent deployed runtime state,
> effective permissions, live identities, or runtime behavior.

### Registry lifecycle

- **First scan**: creates the shared database, prints a one-line
  initialization message and a `SAFEAI_REGISTRY` tip (SafeAI never edits
  your files for you).
- **Subsequent scans**: append a new snapshot; prior history is never
  overwritten.
- **Per-project registries**: `--registry PATH` or `--project-dir DIR`
  still read/write `<DIR>/.safeai/registry.db`, keeping existing
  per-project databases working.
- **CI**: when the `CI` environment variable is set, persistence is
  auto-disabled for bare jobs. Use `--registry PATH` or set
  `SAFEAI_REGISTRY` to opt in, or `--no-registry` for ephemeral scans.
- **Failure tolerance**: a scan still succeeds and produces reports if
  persistence fails (a warning is printed). `--strict-registry` turns the
  failure into exit code 2.

```bash
safeai scan .                                # default: persist to the shared registry
safeai scan . --no-registry                  # ephemeral
safeai scan . --registry /secure/shared/safeai/registry.db   # explicit location
SAFEAI_REGISTRY=/secure/shared/safeai/registry.db safeai scan .   # org-wide env config
```

### Registry commands

```bash
safeai registry list [--format table|json|html]
safeai registry show <agent-id> [--scan <scan-id>] [--format table|json|html]
safeai registry history <agent-id> [--format table|json|html]
safeai registry diff <agent-id> --from previous --to latest [--format table|json|html]
safeai registry export --format json --output inventory.json \
    [--include-history] [--include-suppressed]
safeai registry export --format html --output inventory.html \
    [--include-history] [--include-suppressed]
```

- All commands accept `--registry PATH`; without it, the shared registry
  is used (`SAFEAI_REGISTRY` env var or `~/.safeai/registry.db`).
- `--project-dir DIR` inspects a per-project `DIR/.safeai/registry.db`.
- `diff` exit codes: `0` no risk-relevant change, `1` changes exist,
  `2` usage/registry error.

### Project identity

Resolved in priority order: (1) `project_id` in `.safeai/config.yml`,
(2) a fingerprint of the normalized Git remote plus repo root, (3) a
persisted local UUID in `.safeai/config.yml`. Raw remote URLs are never
stored or exported.

See [REGISTRY.md](REGISTRY.md) for schema, stored/not-stored data, and
backup guidance.

---

## Baseline Workflow

Baselines let CI emphasize **new or regressed** issues instead of failing on
all historical findings.

```bash
# 1. Establish a baseline (usually on the main branch)
safeai scan . --manifest safeai-manifest.json --no-registry

# 2. Compare a PR scan against it
safeai scan . --baseline safeai-manifest.json --fail-on-new
```

Terminal output shows counters: new / existing / resolved findings and new
high+critical findings. Findings keep their `status` in JSON, HTML, SARIF,
manifest, and registry history.

- `--fail-on-new` requires `--baseline`. The failing set is restricted to
  findings classified `new` or `regressed` at or above `--fail-on` severity.
- Without `--fail-on-new`, `--fail-on` semantics are unchanged (any active
  finding at/above threshold fails).
- Baselines accept the canonical manifest or a legacy SafeAI JSON report.
- Regressed classification (previously resolved, now reintroduced) uses
  registry history when available.

Do not commit baseline files blindly: review them like lockfiles.

---

## PR Comments & Capability Escalation

A capability *escalation* is a tool gaining more authority than it had in
the baseline scan — a new shell capability, a filesystem access widening
from read to write, a new MCP server, a removed approval gate, and so on.
Escalations are computed per tool (see `KYA_MANIFEST.md` for the
`tool_surface` and diff schema), which is why they require `--baseline`:
an escalation is defined relative to a prior scan, not to anything in the
current scan alone.

```bash
safeai scan . \
  --baseline safeai-manifest.json \
  --pr-comment comment.md \
  --fail-on-escalation high
```

This fails the scan (exit 1) if any tool escalated at `high` or `critical`
severity, and writes `comment.md`. A typical comment looks like:

```markdown
<!-- safeai:pr-comment:v1 -->
### SafeAI capability escalation summary

**mcp_server:invoice-lookup** — high
- mcp: read → mutate (`ESC_MCP_READ_TO_MUTATE`)

**tool:send_email** — high
- external_apis: none → write (`ESC_EXTERNAL_ACCESS_ADDED`)

_1 more tool changed — see full report_

---
0 access modes were inferred rather than declared in this scan.
```

Read it the same way you would read a diff: each heading is a tool
identity (`kind:name`), sorted worst severity first; each bullet is one
capability's access-mode change and the rule that fired. The `<!--
safeai:pr-comment:v1 -->` marker on the first line lets a CI script find
and replace SafeAI's own previous comment on a PR rather than posting a
new one on every push. SafeAI writes this file (or prints it to stdout with
`--pr-comment-stdout`); it never posts it to GitHub, GitLab, or anywhere
else, and makes no network call while doing so — posting is the CI
workflow's job. See the "Capability escalation in CI" section in
`README.md` for a complete GitHub Actions example.

If a tool's access summary shows no change (for example, an MCP server
already at its highest observed access mode), but an individual capability
on that tool still changed, the comment falls back to reporting the
capability-level change instead of a misleadingly flat summary.

### Assurance boundary

Every manifest includes an `assurance_boundary` object that states, in
plain language, what this specific scan verified and what it structurally
cannot verify — declared tools and permission configuration are checked;
deployed IAM permissions, runtime identity, and network policy are not.
The terminal summary and HTML report surface the same statement. When a
scan skipped files, failed to parse a configuration file, or had to infer
an access mode rather than read a declared one, the boundary's
`coverage_notes` say so specifically, with a count; when none of that
happened, it says so as well, rather than omitting the field. Treat this
as an instrument-accuracy statement, not a pass/fail judgment — it tells you
how much to trust the rest of the report, not whether the scanned project
is safe. See `KYA_MANIFEST.md` and `LIMITATIONS.md`.

---

## Suppressions & Exceptions

Suppressions record **technical false positives or accepted local
exceptions** in `.safeai/suppressions.yml`. They are auditable and never
silent: suppressed findings stay visible everywhere with status
`suppressed` but are excluded from gating.

```yaml
version: "1"
suppressions:
  - fingerprint: "022ea2ed..."     # or rule_id: CAP_shell
    reason: "Shell is gated by manual approval in this internal tool."
    owner: "security-team"          # required
    created: "2026-07-31"           # required (YYYY-MM-DD)
    expires: "2026-12-31"           # optional
    path: "src/**"                  # optional glob scope
```

- `reason`, `owner`, and `created` are **required** — invalid files are
  rejected, never silently ignored.
- Expired suppressions stop applying and are reported as warnings.
- Distinguish from a **policy exception**: an authorised risk acceptance
  for a defined period belongs in `.safeai/policy.yml` as an `allow`
  policy with a reason.

---

## Policy-as-Code

`.safeai/policy.yml` maps static evidence to actions. Deliberately minimal —
not OPA/Rego. Actions by precedence: `allow < warn < require_review < deny`.

```yaml
version: "1"
default_action: warn
policies:
  - id: deny-shell-with-untrusted-input
    when:
      capabilities_all: [shell]
      finding_ids: [PROMPT_INJECTION]
    action: deny
    message: "Untrusted input reaches an agent with shell capability."
  - id: review-remote-mcp-without-auth-evidence
    when:
      mcp:
        remote: true
        authentication_evidence: absent
    action: require_review
  - id: permit-dev-example
    when:
      path_glob: "examples/**"
    action: allow
    reason: "Intentionally vulnerable fixture."
```

Selectors: `finding_ids`/`rule_ids`, `severity`, `min_severity`,
`capabilities_all`/`capabilities_any`, `frameworks`, `agent`, `path_glob`,
and `mcp` posture (`remote`, `authentication_evidence: present|absent`).

- Evaluation is deterministic (file order; highest-precedence action wins).
- The outcome appears in terminal output, the manifest
  (`summary.policy_decision`), HTML, and JSON, with per-policy match reasons.
- `deny` fails the scan (exit 1) regardless of `--fail-on`.
- A `pass`/`allow` outcome is **not** a safety or compliance claim.

---

## Troubleshooting

### No frameworks detected

- Ensure the project contains Python files with recognized framework imports
- Check that dependency files are present (`requirements.txt`, etc.)
- Run with `--verbose` to see scan details

### No findings reported

- The project may not use AI agent frameworks
- The project may use frameworks not yet supported
- Run `--json` to inspect raw output

### Scan fails with ModuleNotFoundError

- Install the package: `pip install -e .`
- Ensure you are running from the correct directory

### False positive capabilities

- Capability detection uses AST + regex fallback. Some regex patterns may trigger on unrelated code
- Check `confidence` and `source` fields: `ast` detections are more reliable than `regex`
- Submit false positive reports to the project issue tracker

---

## FAQ

**Q: Does SafeAI execute my code?**  
A: No. SafeAI is a static analyzer. It never imports, executes, or evaluates any code in the scanned project.

**Q: Does SafeAI call LLMs or external APIs?**  
A: The scanner is offline and source-private by default and never calls LLMs. Network activity occurs only through explicitly enabled integration commands — currently only `--pr-comment-post`, which makes one GitHub API request to post or update a PR comment and announces itself on stderr when it runs. See "PR auto-posting" below.

**Q: Can SafeAI detect prompt injection at runtime?**  
A: No. SafeAI detects static patterns that may lead to prompt injection. Runtime testing requires separate dynamic analysis tools.

**Q: Is SafeAI specific to any programming language?**  
A: The current Early Preview focuses on Python projects. Framework detection uses Python imports and dependency manifests.

**Q: Does SafeAI support JavaScript/TypeScript projects?**  
A: Limited support via `package.json` dependency detection and JSON/YAML configuration scanning.

**Q: How are trust scores calculated?**  
A: Each finding contributes weighted penalty points to one of 7 categories. Scores start at 100 and decrease as penalties accumulate. The formula is: `category_score = clamp(100 - sum(weighted_contributions), 0, 100)`. The overall score is the average of all category scores.

**Q: Can I trust the confidence values?**  
A: Confidence values indicate detection reliability. AST-based detections typically score 0.8–0.9. Regex fallback detections score 0.45–0.5. Cross-framework arbitration uses max confidence.

**Q: How do I add support for a new framework?**  
A: See CONTRIBUTING.md for the framework adapter pattern and registration process.
