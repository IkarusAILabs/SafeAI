# SafeAI — Roadmap

> Research hub: [ikaruslabs.net](https://ikaruslabs.net) | SafeAI: [ikaruslabs.net/safeai](https://ikaruslabs.net/safeai) | OpenPulse: [ikaruslabs.net/openpulse](https://ikaruslabs.net/openpulse)

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

## Repository status (verified at v2.5.0; v2.6 benchmark hardened; v2.7 evidence metrics + CI benchmark gate)

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
| IaC precision/recall, attribution accuracy, escalation precision | **SHIPPED AND VERIFIED (v2.6 hardened)** | hardened measurements published: `docs/benchmarks/authority/VALIDATION_REPORT.md` (58/58 hold; digest `de9cb45150bd39da1ba793cc0b44420f32451e2ffbb474408f792fddb515c64b`; entity discovery calibrated 1.0; attributable-only 1.0; end-to-end 0.4851 with 69/134 unattributed; change P/R/F1 1.0 on 5; escalation P/R/F1 1.0 on 4 with measured corpus false-escalation 0.0; per-class verdict: capability/identity LANE-A CANDIDATE, authority attribution/change/escalation LANE-B, overall NOT LANE-A READY + unknown veto; provenance: 21 independent / 37 migrated) |
| Delegation depth (sub-agent scope, indirect authority) | PARTIALLY SHIPPED | ESC_COMBO + component graph cover proxies; no dedicated model |
| CFN/Helm/serverless IaC, curated signed packs, component manifests | PLANNED | deferred to v2.6 / process work |
| Authority attestation object, cross-plane contract, flagship experiment | RESEARCH ITEM | §§ below |
| Public authority benchmark (hardened slice: 58 cases + canonical v2 truth + harness + published measurements) | **SHIPPED AND VERIFIED (v2.6; CI-gated v2.7)** | `tests/benchmarks/authority/` (truth_schema_version 2.0, human-reviewed), `safeai benchmark`, `docs/benchmarks/authority/VALIDATION_REPORT.md`; `authority-benchmark` CI job fails on any case that stops holding |
| Evidence metrics (evidence-backed / inferred / unattributed authority rates, evidence completeness, finding provenance, unknown authority-dimension rate) | **SHIPPED AND VERIFIED (v2.7)** | `safeai/analysis/evidence_metrics.py`, manifest `summary.evidence_metrics`, JSON report; informational, never gates |
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
- **Research metric (SHIPPED v2.7, except false attribution rate):**
  unknown authority-dimension rate, inferred authority rate,
  evidence-backed authority rate, unattributed authority rate, and
  evidence completeness are emitted on every scan
  (`summary.evidence_metrics`). False attribution rate needs ground
  truth and stays a benchmark measurement. Unknowns are measured, not
  minimized away — the target is justified uncertainty only.

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

- **Agent Authority Benchmark (SHIPPED AND VERIFIED on corpus; publishable
  dataset still RESEARCH ITEM):** 58-case corpus
  (`tests/benchmarks/authority/` with canonical v2.0 gold truth:
  capability-escalation, governance-change, delegation-change, MCP,
  IaC-mismatch, unknown-scenario, and targeted attribution/adversarial
  fixtures, each with expected evidence and expected authority
  classification) + `safeai benchmark` harness (entity/attribution/change/unknown
  PRF with three-state outcomes, determinism digests, 8-area mutation tests)
  + published measurements (`docs/benchmarks/authority/VALIDATION_REPORT.md`,
  digest `de9cb45150bd39da1ba793cc0b44420f32451e2ffbb474408f792fddb515c64b`).
  Target remainder: publishable dataset + reproducibility package.
- **Evaluation methodology (IMPLEMENTED, VALIDATED on corpus):**
  entity discovery P/R/F1 (with insufficient_evidence, never 0/1);
  8-level attribution (tool, capability, agent, identity, grant,
  agent→identity, capability→grant, end-to-end; attributable-only vs
  end-to-end split); evidence completeness, reproducibility,
  determinism; material-change and escalation P/R/F1 plus measured
  false-escalation and missed-material rates (0/0 reports
  insufficient, never 0); unknown preservation across
  UNKNOWN/UNVERIFIED_LINK/PARTIAL/INFERRED/UNRESOLVED; per-class
  Lane-A verdicts (LANE-A CANDIDATE vs LANE-B, overall NOT READY).
- **Research deliverables per milestone:** schema, benchmark, dataset,
  experiment, reproducibility package, technical report, paper, or
  reference implementation — engineering must generate academic value.
- **Metrics already tracked:** unknown/inferred/evidence-backed rates
  are wired into routine reporting since v2.7
  (`summary.evidence_metrics`); report movement in these before
  inventing new ones.

---

## External framework alignment — Blueprint Alliance reference architecture

The [Blueprint Alliance](https://blueprintalliance.ai/) (announced
2026-09-22; operated by Okta, with AWS, CrowdStrike, Databricks,
Docker, Google Cloud, Lovable, Proofpoint, Salesforce, ServiceNow,
Wiz and Zscaler as founding members) publishes an open, multi-vendor
reference architecture, *Governing Agentic Execution*, built around
four questions: *Where are my agents? What can they do? What are they
doing? How do I respond?*

**Positioning (binding):** the Blueprint is runtime-centric; SafeAI is
source-first and pre-deployment. SafeAI aligns as an **evidence
source** for the parts of the architecture that static authority
evidence can constrain — posture before registration, permission
ceilings, delegation structure, and re-attestation against a
known-good baseline. It does not implement gateways, runtime
monitoring, containment or recovery, and nothing here reopens the
REMOVE list. Ikarus AI Labs is **not** an Alliance member; SafeAI
artefacts reference the *publicly available* architecture and must
never imply membership, endorsement or certification.

### Component crosswalk

| Blueprint component | SafeAI evidence | Status |
|---|---|---|
| P1 · AI Agent Security Posture Mgmt — tool & skill supply-chain scanning, misconfigurations, "configuration drift introduced after an agent's initial review passed" | Layer 1 discovery, MCP poisoning detection, ChangeGuard baseline diff | SHIPPED AND VERIFIED |
| P1 · Agent Directory — agent governance metadata (owner, lifecycle, risk tier, scope), identity profile (CIMD) | KYA manifest Contract v1 (declared / detected / inferred / unknown) | PARTIALLY SHIPPED — no owner/lifecycle fields, no CIMD mapping |
| P1 · Agent Import — MCP & skill registries as untrusted input | MCP/skill adapters, destination taxonomy | SHIPPED AND VERIFIED (static config only) |
| P2 · Access policies — delegation & inheritance (intersection of entitlements, capped depth/breadth) | Layer 3 delegation semantics | PLANNED (ESC_COMBO proxies today) |
| P2 · Governance — agent requests checked against static permission ceilings; Separation of Duties; joiner-mover-leaver | Approved baseline = static ceiling; policy-as-code; exceptions with owner/expiry | PARTIALLY SHIPPED — no SoD rule class, no approval metadata (P6) |
| P3 · Runtime authorization, gateways, monitoring | — | OUT OF SCOPE (runtime boundary kept) |
| P4 · Access Recovery — re-attestation "against a known-good baseline", audit trail closure | `manifest verify` + baseline diff + evidence chain | SHIPPED AND VERIFIED (static evidence only) |
| P4 · Response / kill switch | — | OUT OF SCOPE |
| §3.5 Execution context & risk signals (SSF/CAEP) · telemetry (OCSF) | SARIF / JSON / manifest exports | PLANNED — file-only OCSF and SSF/CAEP exports (B4) |
| §4.2 Risk tiering inputs — read-only vs transactional, autonomy, blast radius | Access modes, `autonomy` / `destination` / `data_reach` change dimensions | SHIPPED AND VERIFIED as *inputs*; SafeAI emits no tier or score |
| §4.4 Audit-ready evidence packages, tamper-evident provenance | Evidence chain, signed release, deterministic manifest digests | SHIPPED AND VERIFIED |

Dependency CVEs and execution-environment drift in the Blueprint's
posture layer belong to the **Software Ecosystem Evidence Plane**
(OpenPulse); they are the natural first consumer of Layer 7
cross-plane work and are not duplicated here.

### Alignment work items

- **B1 — Crosswalk + Blueprint control mapping (P0, PLANNED).** Publish
  this crosswalk; add a Blueprint component mapping alongside the
  existing OWASP/NIST mappings (`safeai/controls/mappings.py`) so
  findings and authority changes cite Blueprint components. Mapping is
  taxonomy, not a conformance claim.
- **B2 — Delegation & SoD change types (P1/P2, PLANNED).** Promote
  delegation from combo-rule proxies to explicit change types aligned
  with Blueprint "delegation & inheritance": new sub-agent, delegation
  depth/breadth increase, sub-agent capability not held by its
  delegator (confused-deputy shape). Add a Separation-of-Duties rule
  class for conflicting capability pairs (e.g. create + approve the
  same transaction). Each needs benchmark cases before any gating.
- **B3 — Attestation as re-attestation baseline (P4, RESEARCH ITEM).**
  Shape the Agent Authority Attestation as a signed in-toto-style
  predicate; map fields to Blueprint agent governance metadata and
  CIMD where declared; position it as the known-good baseline for
  Access Recovery re-attestation. Machine-derived, human-declared and
  unknown fields stay separate; nothing is fabricated to fill a field.
- **B4 — Standards exports, file-only (P7 / EE, PLANNED).** Export
  findings and authority changes as OCSF events, and MATERIAL /
  HIGH_RISK changes as SSF/CAEP Security Event Token payloads.
  Community Edition writes files only — transmission belongs to the
  user's pipeline or the Corporate Edition, so the offline /
  single-network-path commitment is unchanged.
- **B5 — Blueprint scenario fixtures (P5, RESEARCH ITEM).** Add
  benchmark cases derived from the whitepaper's "Blueprint in Action"
  composites where static evidence applies (read → transactional
  access-mode widening; multi-agent delegation scope), with runtime-only
  scenarios recorded as expected `unknown`. Publish a technical report:
  *which Blueprint questions can pre-deployment authority evidence
  answer, and with what measured precision and unknown rate?*
- **B6 — Open reference integration (P7, PLANNED).** An Apache-2.0
  reference integration (SafeAI manifest → OCSF / SSF consumer),
  published with reproducible results — the Alliance's stated
  publication form. Engage the open standards communities (OpenID
  Shared Signals, OCSF, IETF WIMSE, MCP) directly; Alliance membership
  is not a prerequisite and is not assumed.

**Not adopted from the Blueprint:** runtime gateways, monitoring,
containment, kill switches, risk-scoring matrices, and the
"risk scoring" language — these conflict with the runtime boundary,
the REMOVE list, and the roadmap language rules.

---

## External framework alignment — SPIFFE / SPIRE workload identity

[SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for
Everyone) and its reference implementation SPIRE are CNCF graduated
projects: a SPIFFE ID (`spiffe://<trust-domain>/<path>`), X.509- and
JWT-SVIDs, the Workload API, and trust-domain federation. SPIFFE is an
open-governance project (Steering Committee; SIG-Spec, SIG-SPIRE,
SIG-Community; public `proposals/`), not a membership consortium. It
is also the identity substrate the IETF WIMSE working group builds on
for agents (`draft-ietf-wimse-aims`, *AI Identity Management System*,
an Internet-Draft — direction, not a finished standard).

**Positioning (binding):** SPIFFE's trust comes from **runtime
attestation** — SPIRE issues an SVID only after verifying the
workload. SafeAI observes none of that. SafeAI aligns by treating
SPIFFE configuration committed to a repository as **static identity
evidence** for the agent authority model (Layer 5, Lane B): which
SPIFFE ID an agent workload is *configured* to receive, which trust
domains it is *configured* to federate with, and which services
*declare* that identity as an allowed caller. An issued SVID is never
inferred: deployed identity is `RUNTIME_UNVERIFIED` and stays separate
from static classes. SafeAI runs no SPIRE agent, calls no SPIRE server,
issues no SVIDs, and claims no SPIFFE conformance or adopter status
until it actually consumes SPIFFE configuration.

**Fit with the current model:** `safeai/iac/` already models
`aws_iam_role` and `kubernetes_service_account` identities and links
workload → ServiceAccount → binding → role; the benchmark already
measures *agent → identity* attribution as one of its eight levels.
SPIFFE adds the identity layer most agent deployments now authenticate
with, and gives the Blueprint crosswalk's *workload identity* row a
concrete static evidence source.

### Alignment work items

- **S1 — Static SPIFFE identity collector (P3, PLANNED, Lane B only).**
  Parse repository-committed SPIFFE configuration: SPIRE controller
  manager `ClusterSPIFFEID` (ID templates, pod/namespace selectors,
  `federatesWith`), `ClusterFederatedTrustDomain`, SPIRE server
  configuration, and service-mesh authorization policy naming SPIFFE
  principals. Add a `spiffe_id` identity kind and link agent workload
  → ServiceAccount → SPIFFE ID. Templates or selectors that cannot be
  resolved statically stay `unknown` — never guessed, never widened
  into a match.
- **S2 — Identity change types (P1, PLANNED).** Map onto the existing
  change dimensions rather than adding new ones: new or broadened
  SPIFFE ID template → `authority`; new federated trust domain or new
  JWT-SVID audience → `destination`; new authorization-policy rule
  admitting the agent's SPIFFE ID to another service → `authority`;
  removed workload identity or regression to static credentials →
  `credential_dependency`. Benchmark cases precede any gating.
- **S3 — Static-credential-where-workload-identity-exists signal
  (Layer 1/5, PLANNED).** Using the existing name-only secret
  inventory, flag an agent relying on a long-lived API key in a
  repository that also configures SPIFFE identity. Review-lane signal,
  not a block; cite WIMSE/AIMS only against the draft text itself.
- **S4 — Identity in the manifest and attestation (P4, RESEARCH
  ITEM).** Add the agent's SPIFFE / WIMSE identifier as an evidence
  field with provenance (`declared` | `repo-iac-observed`;
  `RUNTIME_UNVERIFIED` reserved for externally supplied issuance
  evidence). Feeds B3's re-attestation baseline.
- **S5 — SPIFFE benchmark cases (P5, RESEARCH ITEM).** Fixtures for
  template resolution, ambiguous selectors, federation widening, and
  principal-based authorization; publish agent → identity attribution
  precision and unknown rate for SPIFFE cases (RQ2, RQ3).
- **S6 — Community engagement (no membership required).** Attend
  SPIFFE Community Day 2026 (27 October 2026, London + online; agenda
  includes SPIFFE for agents under the AIMS model) and the SPIFFE
  Slack; once S1 exists, present it in SIG-SPIRE or SIG-Community as
  pre-deployment detection of identity and federation drift for
  agents; offer evidence-boundary feedback to IETF WIMSE on the AIMS
  draft; request an integrations listing only after S1 ships.

**Not adopted:** runtime attestation, SVID issuance or validation,
Workload API clients, live SPIRE server queries, and any claim that a
configured identity was actually issued — these conflict with the
offline, static-evidence commitments and the runtime boundary.

---

## External developments review (2026-10-28)

Checked against recent research and open-source agent scanners.
Adopted only where static authority evidence is the right instrument;
nothing here reopens the REMOVE list or the runtime boundary.

**Context.** A 2026 study of 117,062 dependency changes found coding
agents selected known-vulnerable versions more often than humans
(2.46% vs 1.64%; [Singla et al.](https://arxiv.org/abs/2601.00205)).
Judging the package belongs to OpenPulse's plane. Whether an agent
*can* change dependencies at all is agent authority, which is SafeAI's.
Open-source scanners with overlapping scope now exist: [Agentic
Radar](https://github.com/splx-ai/agentic-radar), [Cisco MCP
Scanner](https://github.com/cisco-ai-defense/mcp-scanner), Snyk Agent
Scan (formerly Invariant MCP-Scan) and
[Aguara](https://github.com/garagon/aguara), all Apache-2.0. None
publishes authority attribution measured against human-reviewed truth,
which is where SafeAI should compete.

### Work items

- **E1 — Package-manager authority (Layer 1/3, P1, PLANNED).**
  Recognise agent authority to add, upgrade, remove or publish
  dependencies: shell allowlist entries for package managers
  (`npm install`, `pip install`, `cargo add`, `go get`, publish
  commands), registry credential names via the existing name-only
  secret inventory, and write access to manifests and lockfiles. Map
  widening onto the existing `dependency`, `authority` and
  `credential_dependency` change dimensions; add no new dimension.
  Benchmark cases come before any gating. SafeAI states *that* the
  agent can change dependencies, never *whether* a chosen package is
  safe.
- **E2 — Comparative measurement against open-source agent scanners
  (Layer 8, P5, RESEARCH ITEM).** Run the scanners above, at pinned
  versions, on the corpus cases they can parse. Score every tool on
  SafeAI's authority rubric (entity discovery, attribution, change
  detection, unknown preservation) rather than on each tool's own
  finding labels. LLM-backed analysers are disabled or reported
  separately because their output varies between runs. Publish as a
  technical report with the cases each tool misses, SafeAI included.
  No superiority claim before results.
- **E3 — External malicious-skill corpus (Layer 8, P5, RESEARCH
  ITEM).** Evaluate MCP and skill poisoning detection on
  [MalSkillBench](https://arxiv.org/abs/2606.07131) (3,944 malicious
  and 4,000 benign coding-agent skills, malicious behaviour verified in
  a sandbox) once its dataset location and licence are confirmed. Its
  runtime labels also measure the static boundary: behaviour that only
  shows at runtime is expected as `unknown`, and is counted separately
  from a miss.

**Not adopted:** runtime enforcement (AgentSpec, guardrail frameworks)
and kill switches, which stay outside the runtime boundary (HaltAI's
plane); dependency vulnerability or lifecycle intelligence
(OpenPulse's plane); LLM analysis in the scan path; dynamic MCP
probing.

---

## Priority sequence

- **P0 — Research Evidence Foundation:** schema hardening, provenance
  completeness, deterministic manifests, assurance boundary honesty,
  unknown handling, evidence verification (mostly shipped; manifest
  unknown-rate surfacing shipped v2.7; remaining gaps: provenance
  audits; Blueprint crosswalk + control mapping, B1).
- **P1 — ChangeGuard:** material-change precision measurement,
  delegation-change types, review-lane UX, portable exceptions,
  explainable decisions (core shipped; measure + deepen; delegation
  and SoD change types, B2; SPIFFE identity change types, S2;
  package-manager authority, E1).
- **P2 — Authority Depth:** MCP depth, delegated authority model,
  tool→implementation mapping precision, destination/resource
  modelling, dataflow precision (scaffolding shipped).
- **P3 — Declared vs Repository/IaC Authority:** CFN/Helm/serverless,
  mismatch precision/recall publication, Lane-A graduation case
  (v2.6); static SPIFFE identity collector and static-credential
  signal, S1/S3.
- **P4 — Agent Authority Attestation:** canonical representation,
  evidence chain object, external consumer contract; re-attestation
  baseline shape, B3; SPIFFE / WIMSE identity field, S4 (research).
- **P5 — Research Benchmark:** fixture corpus, expected-truth
  annotations, evaluation harness, reproducibility; Blueprint
  scenario fixtures + coverage report, B5; SPIFFE identity cases,
  S5 (research); comparative scanner measurement and external
  malicious-skill corpus, E2/E3 (research).
- **P6 — Accountability:** review decisions, approvals, exceptions,
  expiry, escalation records.
- **P7 — Cross-Plane Assurance Research:** integration contract,
  dependency-context export, combined policy experiment; file-only
  OCSF / SSF-CAEP exports and open reference integration, B4/B6
  (research).
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

- **v2.7.0** — Evidence metrics on every scan (manifest + JSON +
  brief), `CAP_subprocess_shell` multi-line false negative fixed, full
  authority corpus gated in CI, Blueprint / SPIFFE roadmap alignment.
- **v2.6.0** — Hardened authority evidence validation benchmark
  (58 cases, canonical v2 truth), decision-support HTML reporting.
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
