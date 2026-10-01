# SafeAI Reporting Guide

SafeAI produces several output formats. Each serves a different audience and
workflow. This guide explains what each format is for, what to inspect, and how
to interpret the results.

> **Key principle:** SafeAI reports are static analysis evidence. "No findings"
> means SafeAI did not detect a configured rule — it does not prove the absence
> of risk. High-impact capabilities (shell, filesystem, browser, cloud,
> database, external integrations, MCP) should always be reviewed in context.

---

## Output Formats at a Glance

| Format | Best For | Audience | Flag |
|--------|----------|----------|------|
| Terminal | Fast local feedback | Developer | *(stdout, always)* |
| HTML | Human investigation and review | Developer, reviewer, auditor | `--html` |
| JSON | Automation and custom tooling | CI pipelines, integrations | `--json` |
| SARIF | GitHub Code Scanning and compatible platforms | Security teams | `--sarif` |
| PR comment | Reviewer workflow on pull requests | Code reviewers | `--pr-comment` |
| KYA manifest | Agent inventory and governance | Platform teams, auditors | `--manifest` |
| Security Scorecard | Quick pass/warn/fail gate | Reviewers, CI gating | `--scorecard` |
| Registry | Historical agent tracking | Platform teams | `safeai registry` |

---

## Terminal Output

**Best for:** quick local feedback during development.

```bash
safeai scan .
```

### What to look at

1. **Overall AI Risk Score** — a 0–100 number. Lower is better. Use it as a
   triage signal, not a verdict.
2. **Severity breakdown** — `critical` findings need immediate attention;
   `high` findings should be reviewed before merge.
3. **Finding list** — each line shows severity, file location, and a short
   message. Start from the top (worst severity) and work down.
4. **Frameworks detected** — confirms SafeAI found your agent framework. If
   none appear, check that your project has Python files with framework
   imports.
5. **MCP assets** — count of discovered MCP servers/tools. Non-zero means MCP
   configuration was found and analyzed.

### What it does NOT include

- Detailed evidence or code snippets (use HTML or JSON for that).
- Baseline comparison (use `--baseline` with JSON/HTML for diffs).
- SARIF output for GitHub (use `--sarif`).

---

## HTML Report

**Best for:** deep human investigation, team review, and audit.

```bash
safeai scan . --html report.html
```

### What to inspect

1. **Security Brief** — the 30-second view: risk signal with band,
   evidence-confidence share, agent/tool/capability counts,
   escalation and authority-observation counts, unresolved unknowns,
   and the baseline change line. Risk and evidence confidence are
   different dimensions: verify high-risk claims on weak evidence.
2. **Assurance Boundary** — what SafeAI verified and what it could
   not (now placed before detailed evidence, not after).
3. **What SafeAI Found** — traced human statements (each cites
   evidence; nothing inferred beyond the reference).
4. **Recommended Review Actions** — prioritized cards with reason,
   evidence, remediation, confidence, limitations, and reviewer
   questions. Nothing here decides for you.
5. **Capability Changes** — human-readable new/removed/changed
   authority since the baseline (per-tool detail follows below).
6. **Authority Review** — IaC verdicts (`MATCH | EXCESS_AUTHORITY |
   AUTHORITY_MISMATCH | UNVERIFIED_LINK | UNKNOWN`) with identity,
   evidence, and resolution. Repository IaC is evidence of declared
   grants, never proof of deployed permission.
7. **Evidence Confidence** — legend of the five evidence classes
   with live counts plus worked Risk/Evidence/Gateability examples.
8. **Executive Summary** — overall score, finding counts, and risk posture at
   a glance.
9. **Capability Matrix** — which tools have which capabilities and at what
   access level. Look for unexpected `write`, `mutate`, or `execute` access.
10. **Findings by severity** — expand each severity tier. For each finding:
   - **File and line** — where the evidence was found.
   - **Evidence** — the matching source code excerpt.
   - **Remediation** — suggested fix.
   - **Confidence** — `high` (AST-based) vs `medium`/`low` (regex fallback).
     Low-confidence findings may need manual verification.
11. **Trust Score breakdown** — which of the 7 categories contributed the most
   penalty. High Capability risk means dangerous tools; high Governance risk
   means missing controls.
12. **Assurance Boundary (detail)** — the full verified-vs-not tables and
    coverage notes (summary already shown near the top).
13. **Policy Decision** — whether the scan passed, warned, or was blocked by
   policy rules.

### How to use it

- Open in a browser and search for specific rules (e.g. `CAP_shell`,
  `MCP_AUTH_MISSING`).
- Print or PDF for audit evidence — the HTML is self-contained and
  print-friendly.
- Share with reviewers who do not have SafeAI installed.

---

## JSON Report

**Best for:** automation, custom tooling, and integration with other systems.

```bash
safeai scan . --json results.json
```

### Structure

The JSON report contains:

- `findings[]` — array of finding objects with all fields (rule_id, severity,
  file, line, evidence, confidence, fingerprint, status, remediation, etc.).
- `tool_surface[]` — per-tool capability index with access modes.
- `counts` — finding counts by severity.
- `trust_score` — overall score and per-category breakdown.
- `component_diff` — changed/added/removed components (with `--baseline`).
- `assurance_boundary` — what was verified vs. not verifiable.
- `policy_decision` — outcome and per-rule match reasons.

### What to inspect

1. **`findings[].fingerprint`** — stable finding identity. Use for
   deduplication, suppression matching, and baseline comparison.
2. **`findings[].status`** — `new`, `existing`, `regressed`, `resolved`,
   `suppressed`. With `--baseline`, only `new` and `regressed` findings
   should concern you.
3. **`findings[].confidence`** — numeric confidence. Below 0.5 suggests manual
   review.
4. **`tool_surface[].capabilities[]`** — each tool's declared capabilities
   with `access_mode` and `access_mode_inferred` flag.
5. **`trust_score.overall_ai_risk_score`** — the 0–100 trust score.

### Caution

- JSON and SARIF are machine-readable contracts. Avoid depending on
  undocumented fields — they may change between versions.
- The `schema_version` field at the top level indicates the report format
  version.

---

## SARIF 2.1.0

**Best for:** GitHub Code Scanning, Azure DevOps, and SARIF-compatible security
platforms.

```bash
safeai scan . --sarif results.sarif
```

### What to inspect

1. **Results count** — total findings uploaded as code-scanning alerts.
2. **Rule severities** — maps directly to GitHub's severity labels.
3. **`ruleId`** — cross-reference with `RULES_REFERENCE.md` for full
   description.
4. **`locations[].physicalLocation`** — file and line for code-scanning
   annotations.
5. **`properties`** — extended data (OWASP category, risk category, evidence,
   remediation) not shown in the default GitHub UI but available via the API.

### How to use it

- Upload with `github/codeql-action/upload-sarif@v3` using `if: always()`
  so alerts are created even when the scan fails.
- SARIF severity and GitHub presentation are triage inputs — define your own
  merge/release policy based on your team's risk tolerance.
- SafeAI always writes the SARIF file, even on exit 1, so downstream steps
  keep working.

---

## PR Comment

**Best for:** reviewer workflow on pull requests — shows what changed, not
everything that exists.

```bash
safeai scan . --baseline base.json --pr-comment comment.md
```

### What to look at

1. **Tool headings** — each `kind:name` (e.g. `mcp_server:invoice-lookup`)
   is a tool that changed, sorted worst severity first.
2. **Capability changes** — each bullet shows what access mode changed
   (e.g. `read → mutate`) and which escalation rule fired.
3. **Inferred access modes** — the count at the bottom tells you how many
   capabilities were inferred rather than declared. High counts mean lower
   confidence in the access-mode attribution.
4. **No changes** — if the comment says "no changes," the baseline comparison
   found no capability differences.

### How to use it

- Post as a PR comment via your CI workflow (`gh pr comment`).
- SafeAI never posts anything anywhere — generating the comment and publishing
  it are two separate steps.
- Use `--fail-on-escalation high` to fail CI when a tool gains dangerous
  authority.
- The `<!-- safeai:pr-comment:v1 -->` marker lets CI scripts find and replace
  SafeAI's previous comment on repeat pushes.

### Auto-posting (`--pr-comment-post`): integration boundary

Rendering the comment above is offline. `--pr-comment-post` is the one
explicitly enabled integration that makes a network request: it calls the
GitHub API to create or update a single PR comment, and announces itself
on stderr when it runs ("Integration mode enabled: …"). The scanner
runtime otherwise has no network behavior.

- **Token scope:** `GITHUB_TOKEN` with `pull-requests: write`.
  CI context (PR number, repository) is auto-detected; without both, SafeAI
  renders locally and posts nothing.
- **Data transmitted:** only the rendered Markdown comment — escalation
  summaries, rule IDs, `path:line` references, and static remediation
  prose. No raw source, no secret values (redacted upstream), no full
  reports, no registry contents.

---

## KYA Manifest

**Best for:** agent inventory, governance, and historical tracking.

```bash
safeai scan . --manifest safeai-manifest.json
```

### What it contains

- **Project identity** — deterministic project/agent IDs (git-remote
  fingerprint, no raw URLs stored).
- **Agent records** — per-agent snapshots with capabilities, tools, findings.
- **Tool surface** — per-tool capability index.
- **Findings** — all findings with fingerprints and status.
- **Assurance boundary** — what was verified vs. not verifiable.
- **Policy decision** — outcome and rationale.
- **Dependency inventory** — environment/config credential references.

### How to use it

- Commit as `safeai-manifest.json` to establish a baseline for future scans.
- Feed back with `--baseline` for new/regressed finding detection and
  capability escalation gating.
- Feed to `safeai registry export` for portable KYA inventory.
- Review it like a lockfile: it records what the scanner saw at a point in
  time, not what is deployed.

---

## Security Scorecard

**Best for:** quick pass/warn/fail gate and first-glance risk assessment.

```bash
safeai scan . --scorecard scorecard.md --scorecard-json scorecard.json
safeai scan . --scorecard-fail-under 7.0
```

### What to look at

1. **Overall score (0–10)** — higher is better. Below 7.0 is a common CI
   gate threshold.
2. **Per-category scores** — identifies which risk area (prompt injection,
   secrets, MCP, etc.) is dragging the score down.
3. **`pass`/`warn`/`fail` outcome** — deterministic based on
   `--scorecard-fail-under` threshold and blocking findings.
4. **Top findings** — up to 10 highest-severity findings with rule IDs and
   locations.

### How to use it

- Add `--scorecard-fail-under 7.0` to CI to enforce a minimum score.
- Use `--scorecard-summary` in GitHub Actions to append to the step summary.
- The JSON output conforms to `safeai/scorecard-schema.json` for integration.

---

## Registry

**Best for:** historical agent tracking across scans and projects.

```bash
safeai registry list                          # all agents
safeai registry show <agent-id>               # latest record
safeai registry history <agent-id>            # per-scan history
safeai registry diff <agent-id> --from previous --to latest
safeai registry export --format json --output inventory.json
```

### What to look at

1. **`list`** — agent names, frameworks, risk scores, policy outcomes,
   freshness status (fresh/aging/stale/never).
2. **`show`** — latest snapshot with capabilities, tools, findings, and
   the scan it came from.
3. **`history`** — how an agent's risk profile changed across scans. Look for
   increasing severity or new capabilities.
4. **`diff`** — before/after tool-centric authority view. Identifies which
   tools gained or lost capabilities.
5. **`export`** — portable JSON inventory for sharing KYA evidence across
   teams without a central service.

---

## Interpreting Findings

### What a finding means

A finding is static evidence that a specific rule matched specific code or
configuration. It is not a proof of vulnerability — it is a signal that
warrants review.

| Field | What it tells you |
|-------|-------------------|
| `severity` | How impactful the pattern would be if exploited |
| `confidence` | How reliably SafeAI detected it (AST > regex) |
| `status` | Whether this is new, existing, regressed, or resolved |
| `evidence` | The exact code that triggered the match |
| `remediation` | Suggested fix (when available) |
| `fingerprint` | Stable identity for tracking across scans |

### Severity vs. confidence

- **High severity + high confidence** — investigate immediately.
- **High severity + low confidence** — verify manually before acting.
- **Low severity + high confidence** — track for cleanup, not urgent.
- **Low severity + low confidence** — likely noise; suppress if persistent.

### What "no findings" means

"No findings" means SafeAI did not detect any of its 57 configured rules in
your code. It does **not** mean:

- Your agent is safe.
- No risks exist.
- No further analysis is needed.

SafeAI is a static pattern detector. It cannot verify runtime behavior,
deployed permissions, or dynamic tool construction.

### Capabilities vs. findings

A **capability** (e.g. `shell`, `filesystem`, `database`) is a property of a
tool — what it *can* do. A **finding** is a specific risky pattern — what
SafeAI *detected*. A tool can have dangerous capabilities with zero findings
(if the capability is used safely) or findings without dangerous capabilities
(e.g. a prompt injection in a read-only tool).

Review both: capabilities tell you the attack surface; findings tell you
where the surface is exposed.

### Escalation remediation coverage

Every `ESC_*` escalation carries structured remediation (`summary`,
`why_it_matters`, `review_questions`, `recommended_actions`,
`safe_configuration_patterns`, `limitations`). Per-output behavior is
intentional:

| Output | Escalation remediation |
|--------|------------------------|
| JSON report | Full structured object on each escalation in `capability_diff` |
| `safeai-manifest.json` | Full structured object in top-level `escalations` |
| HTML | Collapsible "Remediation" per escalation |
| Terminal | Concise `Next:` action for high/critical findings (escalation detail lives in JSON/HTML) |
| PR comment | One recommended action per critical/high escalation (60-line cap preserved) |
| Scorecard | `Remediation focus` theme summary (counts, not raw text) |
| SARIF | Intentionally not duplicated: escalations are baseline diffs without file locations, and SARIF results require locations. Finding-level remediation is in SARIF rule help and result properties. |

---

## Triage Workflow

1. **Start with the Scorecard** — if the score is below your threshold, there
   is work to do.
2. **Check the terminal** — severity breakdown gives you the priority order.
3. **Open the HTML** — investigate each critical/high finding with evidence
   and context.
4. **Review the PR comment** — on pull requests, focus on escalations (what
   changed), not pre-existing findings.
5. **Compare against the baseline** — with `--baseline`, only `new` and
   `regressed` findings need attention.
6. **Check the assurance boundary** — know what SafeAI could and could not
   verify before trusting the results.

---

## Common Patterns

| Pattern | Likely cause | Action |
|---------|-------------|--------|
| Many `CAP_*` findings | Regex fallback matching unrelated code | Check `confidence` field; suppress false positives |
| `MCP_AUTH_MISSING` | MCP config lacks `auth` field | Add authentication configuration |
| `PROMPT_INJECTION` | User input in f-string/format prompt | Use parameterized prompts |
| `DATA_LEAKAGE` | Hardcoded secret in source | Move to environment variable or secret manager |
| `ESC_*` findings | Capability escalated between scans | Review if escalation is intentional; update baseline |
| Score dropped after merge | New findings or capability escalations | Check `--baseline` diff for specific changes |
