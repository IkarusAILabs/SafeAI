# SafeAI — Roadmap

> SafeAI is one research instrument within the Ikarus AI Labs programme on
> **Evidence-Based Assurance for AI-Mediated Software Change**.
>
> SafeAI focuses on the **Agent Authority Evidence Plane**: constructing
> source-derived, evidence-bounded representations of what an AI agent can
> potentially access, control or change.
>
> OpenPulse independently investigates the **Software Ecosystem Evidence
> Plane**. A future research direction is to investigate whether these
> evidence planes can be combined into more effective, explainable and
> accountable decisions about AI-mediated software changes.
>
> See `docs/research/RESEARCH_ALIGNMENT.md` for the programme thesis,
> the plane definitions, and the SafeAI ↔ OpenPulse boundary.

# SafeAI — Agent Authority Evidence for AI-Mediated Software Change

**Technical description:** SafeAI is a source-first static analyser that
constructs an evidence-bounded model of an AI agent's potentially reachable
authority, detects material authority changes, and produces
machine-readable evidence for policy and human review.

> SafeAI does not certify an agent as safe and does not prove deployed
> runtime permissions or behaviour.

---

## How to read this roadmap

Status labels reflect the actual repository at v2.5.0 (verified during
the re-baseline; see *Repository status* below), not earlier milestone
claims:

- **SHIPPED AND VERIFIED** — implemented, tested, and exercised.
- **PARTIALLY SHIPPED** — core exists; stated scope is incomplete.
- **IMPLEMENTED BUT INSUFFICIENTLY VALIDATED** — code exists but no
  published precision/recall or attribution measurement backs it.
- **PLANNED** — accepted direction, not yet implemented.
- **RESEARCH ITEM** — open research question with an experiment, not a
  feature commitment.
- **OBSOLETE / REMOVE** — explicitly dropped; kept here so it stays dropped.

The work is organised in **research layers** (§Layers 1–8), not a
chronological feature list. Layers 1–3 are the validated core; Layers
4–6 extend it; Layer 7 is future integration research; Layer 8 validates
all of it. Milestones (P0–P8) sequence the layers; work may proceed in
parallel where dependencies allow.

This roadmap plans work within the edition commitments in
[docs/GOVERNANCE_AND_EDITIONS.md](./docs/GOVERNANCE_AND_EDITIONS.md);
it does not renegotiate them. Community Edition stays Apache 2.0,
offline, and local-first.

---

## Product model: Discover / Compare / Govern (retained)

- **DISCOVER** — what authority can the agent potentially exercise?
  Tools, MCP servers, filesystem, shell, databases, APIs, cloud
  services, external destinations, memory, delegation, autonomy, human
  approval controls.
- **COMPARE** — what materially changed? New tools, new MCP servers,
  `read → write` / `write → execute` widening, new destinations,
  expanded data reachability, removed approval gates, increased
  autonomy, new delegation paths, new credential dependencies,
  infrastructure authority changes.
- **GOVERN** — should the change be allowed? Deterministic outcomes
  (`pass | warn | review-required | block | accepted-exception`,
  `safeai/kya/contract.py: POLICY_OUTCOMES`), each explaining what
  changed, why it matters, the evidence, affected tool / capability /
  destination, confidence, responsible policy, and baseline used.
  Scores inform; they never decide.

## ChangeGuard is the flagship operational capability

> SafeAI's primary security event is a **material change in agent
> authority**, not simply the existence of a finding.

```
Agent source/configuration changes
  → SafeAI static analysis
    → Agent authority model
      → Approved baseline
        → Authority diff
          → Material change detection
            → Policy evaluation
              → PASS / REVIEW / BLOCK
                → Evidence artifact
```

Formal change taxonomy (machine-readable, `contract.py: CHANGE_CLASSES`):
`NO_CHANGE | LOW_CHANGE | MATERIAL_CHANGE | HIGH_RISK_CHANGE | UNKNOWN`.

Change dimensions: `authority | destination | data_reach |
governance_control | delegation | autonomy | credential_dependency |
dependency | unknown`.

## Agent Authority Model (core research contribution)

```
Agent
  ↓
Principal / Delegation
  ↓
Tool / MCP / Skill / Workflow
  ↓
Capability
  ↓
Access Mode (none < read < write < mutate < execute)
  ↓
Resource / Data / Destination
  ↓
Authority
  ↓
Evidence
```

This is an analytical model of *potentially reachable* authority, not
observed runtime permission. Every meaningful authority statement
carries provenance and uncertainty. Canonical vocabulary (exact
implementation terms in `contract.py` and the manifest JSON Schema):

`declared | detected | inferred | repo-iac-observed | unknown`

(`RUNTIME_UNVERIFIED` is reserved vocabulary for externally supplied
runtime evidence, Layer 6 / §Runtime evidence; no such evidence is
consumed today and the classes must never be silently mixed.)

**Unknown is a first-class security concept and a research object.**
Tool access: inferred. Runtime IAM: unknown. Dynamic tool binding:
unknown. Network egress: unknown. Runtime identity: unknown. *Unknown
is an evidence state, not evidence of safety* — SafeAI never converts
it into a pass, a false-positive assumption, or a false-negative
assumption. The objective is to *reduce unjustified uncertainty
without converting uncertainty into false certainty.*

## Evidence chain (more important than any aggregate score)

```
SOURCE → OBSERVATION → INTERPRETATION → AUTHORITY STATEMENT
  → CHANGE → POLICY EVALUATION → DECISION
```

Each stage is traceable: source path + line + parser + rule +
baseline + policy. Example: `.claude/settings.json` → tool X allows
command execution → capability `shell`, access_mode `execute` →
agent A can potentially execute shell commands → added relative to
approved baseline → production agents require review for execute
authority → REVIEW, with all of the above attached.

---

## Repository status (verified at v2.5.0)

| Area | Status | Evidence |
|---|---|---|
| Authority diff, ChangeGuard, ESC_* rules, access-mode transitions | SHIPPED AND VERIFIED | `capability_diff.py` schema v2, change classes, `--fail-on-authority-change` |
| Review lanes, policy-as-code, exceptions + strict mode | SHIPPED AND VERIFIED | `policy.py` lanes, `exceptions.py` scope states, #220 scope-escape review |
| Provenance/gateability per finding, assurance boundary | SHIPPED AND VERIFIED | Contract v1 enums, manifest + reports |
| KYA manifest Contract v1, digests, verify | SHIPPED AND VERIFIED | `schemas/safeai-manifest/v1.0.0.json`, `manifest validate/verify` |
| IaC authority evidence (TF + K8s RBAC, identities/grants/bindings, 5 verdicts) | SHIPPED AND VERIFIED | `safeai/iac/`, Lane-B only, benchmark corpus + harness |
| security_brief reporting layer, decision-support HTML | SHIPPED AND VERIFIED | `safeai/report/security_brief.py`, PR Lane-B sections |
| Plugin SDK, custom rules, control mappings (taxonomy) | SHIPPED AND VERIFIED | entry points, `rules check`, OWASP/NIST mappings |
| Registry, suppressions, lifecycle, components, dependency inventory + DEP correlation | SHIPPED AND VERIFIED | SQLite registry, export/import, lockfile |
| Governance signals, dataflow (heuristic), scorecard, SARIF/JSON/terminal | SHIPPED AND VERIFIED | GOV_*, DATAFLOW_* (gate-inert), scorecard opt-in gating |
| IaC precision/recall, attribution accuracy, escalation precision | PARTIALLY SHIPPED | first measurements published: `docs/benchmarks/authority/VALIDATION_REPORT.md` (37/37 hold; discovery P/R/F1 1.0; attributable-only 1.0; end-to-end 0.4222; Lane-A correctly not eligible) |
| Delegation depth (sub-agent scope, indirect authority) | PARTIALLY SHIPPED | ESC_COMBO + component graph cover proxies; no dedicated model |
| CFN/Helm/serverless IaC, curated signed packs, component manifests | PLANNED | deferred to v2.6 / process work |
| Authority attestation object, cross-plane contract, flagship experiment | RESEARCH ITEM | §§ below |
| Public authority benchmark (first slice: 37 cases + harness + published measurements) | PARTIALLY SHIPPED | `tests/benchmarks/authority/`, `safeai benchmark`, `docs/benchmarks/authority/VALIDATION_REPORT.md` |
| Trend charts (`safeai trend`), generic compliance dashboard, AI-BOM-as-CE-core, exploitability AI triage, interactive MCP consent, per-finding risk scores, runtime enforcement in core | OBSOLETE / REMOVE | kept listed so they stay dropped |

**Drift corrected in this re-baseline:** Outcome 1's lanes and Outcome
2's hardening items were marked ⏳ but shipped in v2.4.0; Outcome 4's
IaC work shipped in v2.5.0; the "Current state" block still pointed at
v2.4.0. The layer statuses above supersede those markers.

---

## Layer 1 — Authority Discovery

*Framework analysis, tools, MCP, skills, prompts, workflows, capabilities.*

- **SHIPPED AND VERIFIED:** 19+ framework adapters via community plugin
  SDK (core-team depth on Claude Code, MCP, OpenAI Agents, LangGraph,
  CrewAI, Cursor, Windsurf; long tail via packs, not core team);
  config-file adapters; secret/config inventory (names + provenance
  only); destination taxonomy; conservative heuristic dataflow
  (gate-inert); MCP poisoning detection.
- Framework breadth is useful but secondary: it serves evidence
  quality, never adapter-count metrics. No framework-adapter race.

## Layer 2 — Authority Representation

*Access modes, destinations, resources, provenance, confidence,
unknowns, authority model.*

- **SHIPPED AND VERIFIED:** ranked access modes with inference caps;
  per-finding provenance + gateability; confidence labels; unknown as
  explicit state; the canonical model above.
- **Research metric (PLANNED):** unknown authority rate, inferred
  authority rate, evidence-backed authority rate, false attribution
  rate, evidence completeness. Unknowns are measured, not minimized
  away — the target is justified uncertainty only.

## Layer 3 — Authority Change

*Baseline, ChangeGuard, materiality, escalation, delegation and
autonomy changes.*

- **SHIPPED AND VERIFIED:** tool-centric diffs, formal change
  taxonomy + dimensions (machine-readable), review lanes, portable
  file-backed exceptions with owner/expiry/scope, deterministic
  policy decisions with reasons.
- **PLANNED:** deeper delegation-change semantics (new sub-agent,
  broader delegated scope, indirect authority) as explicit change
  types rather than combo-rule proxies.

## Layer 4 — Evidence Contract

*KYA manifest, deterministic artifacts, evidence chain, attestations,
verification, signatures.*

- **SHIPPED AND VERIFIED:** manifest Contract v1 + JSON Schema +
  canonical digests + offline verify; assurance boundary in every
  report and manifest; portable registry export/import; release
  pipeline signs and verifies (Cosign keyless, SLSA/SBOM assets).
- **Outcome — Agent Authority Evidence Contract (PLANNED hardening):**
  evolve the manifest toward the interoperable evidence artefact —
  agent identity, principal/delegation where available, intended
  purpose where declared, authority statements, access modes,
  resources/destinations, evidence source, provenance, confidence,
  unknowns, authority change, baseline reference, policy decision +
  profile, exceptions, source commit, scan/tool/ruleset versions,
  assurance boundary, timestamp, deterministic digest. Minimal and
  extensible; unknown stays unknown; never fabricate. See
  `docs/research/RESEARCH_ALIGNMENT.md`.

## Layer 5 — Authority Context

*Dependency inventory, IaC, repository grants, component relationships.*

- **SHIPPED AND VERIFIED:** env/credential inventory + DEP
  correlation (both mismatch directions); Terraform + Kubernetes
  RBAC evidence with identities, grants, bindings, five strict
  verdicts (Lane B only); component graph + lockfile integrity.
- **Research framing (not regulatory-first):** how accurately can
  static repository/IaC evidence constrain or enrich an agent
  authority model without claiming deployed runtime authority?
  Evaluate declared vs source-detected vs IaC-observed authority,
  mismatches, unresolved scope, confidence, false positives and
  false negatives. Regulatory readiness is secondary context.
- **PLANNED:** CFN/Helm/serverless collectors (v2.6); Lane-A
  graduation only with published precision (ADR-0008).
- **Division with OpenPulse:** SafeAI answers *which agent authority
  or components depend on this software component*; OpenPulse answers
  *what is happening to that component in the ecosystem*. SafeAI must
  not duplicate OpenPulse's intelligence engine.

## Layer 6 — Policy & Accountability

*Deterministic policy, review lanes, exceptions, approval metadata,
accountable human decisions.*

- **SHIPPED AND VERIFIED:** policy-as-code + profiles, Lane A/B
  separation (gates print verdicts, review prints questions),
  expiring scoped exceptions, `--strict-exceptions` fail-closed.
- **PLANNED:** approval metadata on exceptions/decisions (who
  approved, when, expiry, escalation owner) short of a workflow
  system; review-decision records linkable from evidence.
- **Runtime boundary (kept):** SafeAI proves no deployed IAM,
  runtime identity, egress, behaviour, or dynamically granted
  permissions. Future research adapters *may* consume externally
  supplied runtime evidence as a separate, labelled class
  (`RUNTIME_UNVERIFIED` until independently verified) — never
  silently mixed with static classes.

## Layer 7 — Cross-Plane Assurance *(RESEARCH / FUTURE INTEGRATION)*

- **Agent Authority Attestation (RESEARCH ITEM):** canonical
  representation of an agent's identity, delegated authority,
  capabilities, constraints, and evidence so another system can
  independently reason about it. Separate machine-derived,
  human-declared, and unknown fields. Prototype object only; no
  commitment to schema stability yet.
- **Cross-Plane Assurance Integration (RESEARCH ITEM):** define the
  interface first — SafeAI exports agent authority evidence +
  component/dependency identity + authority context + affected
  change context; OpenPulse independently supplies dependency
  intelligence + applicability + evidence + confidence + temporal
  context. Do not implement the combined decision until both
  contracts are stable. Explicitly not an implementation commitment.
- **Flagship experiment (RESEARCH ITEM):** Evidence-Based Software
  Change Assurance — conditions A (dependency-only), B (agent-only),
  C (combined + deterministic policy); measure unsafe changes
  detected, false positives/negatives, unnecessary human review,
  decision explainability, evidence completeness, unknown exposure,
  human effort, reproducibility. The eventual programme flagship;
  do not claim the combined model is proven.

## Layer 8 — Research Validation

- **Agent Authority Benchmark (first slice SHIPPED AND VERIFIED,
  rest RESEARCH ITEM):** 37-case corpus
  (`tests/benchmarks/authority/`: capability-escalation,
  governance-change, delegation-change, MCP, IaC-mismatch,
  unknown-scenario fixtures, each with expected evidence and expected
  authority classification) + `safeai benchmark` harness + published
  measurements (`docs/benchmarks/authority/VALIDATION_REPORT.md`).
  Target remainder: publishable dataset + reproducibility package.
- **Evaluation methodology (first slice SHIPPED AND VERIFIED):**
  detection precision/recall/F1; attribution accuracy (tool,
  capability, access mode; attributable-only vs end-to-end split);
  evidence completeness, reproducibility, determinism;
  material-change precision/recall, false-escalation rate;
  unknown rate, unsupported-inference rate, incorrect-certainty rate.
- **Research deliverables per milestone:** schema, benchmark, dataset,
  experiment, reproducibility package, technical report, paper, or
  reference implementation — engineering must generate academic value.
- **Metrics already tracked:** unknown/inferred/evidence-backed rates
  are computable from provenance fields today; wire them into routine
  reporting before inventing new ones.

---

## Priority sequence

- **P0 — Research Evidence Foundation:** schema hardening, provenance
  completeness, deterministic manifests, assurance boundary honesty,
  unknown handling, evidence verification (mostly shipped; close the
  gaps: manifest unknown-rate surfacing, provenance audits).
- **P1 — ChangeGuard:** material-change precision measurement,
  delegation-change types, review-lane UX, portable exceptions,
  explainable decisions (core shipped; measure + deepen).
- **P2 — Authority Depth:** MCP depth, delegated authority model,
  tool→implementation mapping precision, destination/resource
  modelling, dataflow precision (scaffolding shipped).
- **P3 — Declared vs Repository/IaC Authority:** CFN/Helm/serverless,
  mismatch precision/recall publication, Lane-A graduation case
  (v2.6).
- **P4 — Agent Authority Attestation:** canonical representation,
  evidence chain object, external consumer contract (research).
- **P5 — Research Benchmark:** fixture corpus, expected-truth
  annotations, evaluation harness, reproducibility (research).
- **P6 — Accountability:** review decisions, approvals, exceptions,
  expiry, escalation records.
- **P7 — Cross-Plane Assurance Research:** integration contract,
  dependency-context export, combined policy experiment (research).
- **P8 — Enterprise Evidence Plane:** only after the evidence model
  is validated — aggregation, retention, SSO/RBAC, routing,
  integrations (EE0–EE4 sequencing unchanged).

---

## What was removed, deferred, merged, or downgraded

- **REMOVE (kept listed so they stay removed):** `safeai trend`
  sparklines; generic compliance dashboard; AI-BOM generator as CE
  core (aggregation lives in EE1); exploitability AI triage;
  interactive MCP consent; per-finding risk scores and
  `--fail-on-risk-over`; runtime enforcement/monitoring in core.
- **DEFER:** CE-V validation packs (after measurement exists);
  curated signed packs (process); component manifests;
  CloudFormation/Helm/serverless.
- **MERGE:** regulatory profile packs into Layer 4 evidence-mapping
  work (secondary context, not a track); System Card / Evidence Pack
  into the Evidence Contract outcome.
- **DOWNGRADE (not a track):** framework count; dashboard/UI;
  enterprise integrations before validation; regulatory breadth;
  runtime integration; generic compliance functionality.

---

## Roadmap language rules

Prefer: evidence · authority · provenance · applicability ·
uncertainty · benchmark · reproducibility · hypothesis ·
measurement · attestation · accountability.

Avoid excessive use of: compliance · score · dashboard ·
certification · AI safety score · autonomous governance. Scores and
the scorecard remain secondary informational features, never the
research foundation.

---

## Standing commitments (unchanged)

- Offline, source-private, deterministic; no LLM calls in the scan
  path; single explicit network path (`--pr-comment-post`).
- Static truth only; unknown is an evidence state; no certification
  claims; no detection gating by edition.
- Semver + additive-only manifest evolution; branch protection,
  linear history, required checks, DCO sign-off.
- Release pipeline: checklist → build → attest → sign (Cosign,
  verify stage) → publish → GitHub Release; floater-tag discipline.

---

## Shipped release log (condensed; see CHANGELOG.md for detail)

- **v2.5.0** — IaC Authority Evidence Lane B (graph, verdicts,
  benchmark corpus), security_brief reporting, scope-escape review,
  Teams detector.
- **v2.4.x** — Authority lanes, change classification,
  provenance/gateability, exceptions, manifest evidence, release
  sign+verify, UNKNOWN governance, output sanitization.
- **v2.3.0** — Plugin SDK, community packs, lockfile integrity.
- **v2.2.x** — Manifest Contract v1, integrity, remediation catalog,
  benchmark corpus, edition boundary.
- **v2.1.x** — Quality gates, PR auto-post, MCP poisoning depth,
  binaries, VS Code MVP.
- **v2.0.0** — Governance depth, failure-class matrix, MCP
  hardening, config-file coverage.
- **v1.5–v1.9** — Capability surface, components, lifecycle,
  suppressions, policy profiles, governance signals, dataflow,
  dependency correlation, telemetry Phase 1 (docs; client
  endpoint unprovisioned — Phase 2 blocked).
