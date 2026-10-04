# Ikarus AI Labs — Research Alignment

## Research thesis

**Evidence-Based Assurance for AI-Mediated Software Change.**

Ikarus AI Labs investigates how organisations can make AI-mediated
software changes observable, explainable and accountable. The core
claim under test: decisions about such changes improve when each
contributing evidence plane is explicit, bounded, and independently
evaluable — before anyone attempts to combine them.

## The four evidence/decision planes

1. **Agent Authority Evidence** — what an AI agent can potentially
   reach and change, derived from source and configuration.
   Primary implementation: **SafeAI**.
2. **Software Ecosystem / Dependency Evidence** — what is happening
   to the components underneath the software (lifecycle, security,
   support, distribution). Primary implementation: **OpenPulse**.
3. **Assurance Policy / Decision** — deterministic rules mapping
   evidence to allow/review/block outcomes, with reasons attached.
   Implemented per-plane today (SafeAI policy engine); cross-plane
   policy is future research.
4. **Human Accountability** — named owners, approvals, exceptions,
   review decisions, and expiry. Recorded as evidence, never as
   automation replacing judgment.

## SafeAI's role

SafeAI is the **Agent Authority Evidence Plane** instrument. It
constructs source-derived, evidence-bounded models of agent authority,
detects material authority changes against approved baselines, and
emits portable, machine-consumable evidence (KYA manifest) for policy
and human review. It does not certify safety and does not prove
runtime state.

## OpenPulse's role

OpenPulse is the **Software Ecosystem Intelligence Plane**
instrument. It tracks dependency lifecycle, security, support, and
distribution signals with applicability scoping (affected version vs
merely related project). It does not model agent authority and does
not gate agent changes.

## The boundary (binding)

- SafeAI answers: *which agent authority or components depend on
  this software component?*
- OpenPulse answers: *what is happening to that component in the
  external ecosystem?*
- Neither product is merged into the other. SafeAI never duplicates
  OpenPulse's intelligence engine; OpenPulse never duplicates
  SafeAI's authority model.
- The shared vocabulary is limited to: component/dependency identity,
  evidence with provenance, confidence, applicability scope, and
  temporal context.

## Research questions

1. Can portable agent-authority evidence be evaluated by an
   independent system without SafeAI internals? (Evidence Contract)
2. How accurately does static repository/IaC evidence constrain an
   agent authority model? (IaC correlation validity)
3. What unknown rate is irreducible vs unjustified, per evidence
   class? (Uncertainty metrology)
4. Does combined authority + dependency evidence improve change
   decisions vs either plane alone? (Flagship experiment)
5. Can authority attestation represent identity, delegation, and
   constraints so third parties can reason over them? (Attestation)

## Planned experiments

- **E1 — IaC correlation validity** (P3): declared vs detected vs
  IaC-observed authority on the benchmark corpus; report precision,
  recall, false-positive/negative rates per verdict class.
- **E2 — Attribution accuracy** (P5): tool/capability/access-mode
  attribution scored against annotated fixtures. Hardened measurement
  (`docs/benchmarks/authority/VALIDATION_REPORT.md`, canonical truth
  v2.0, 56 cases): attributable-only accuracy 1.0 (58/58), end-to-end
  0.464 (58/125) with 67 capabilities in `unknown:unattributed` — the
  quantified code-defined-tools gap (rate moved 0.4222 → 0.464 from
  corpus mix alone: 19 targeted cases added attributable MCP/other
  capabilities; the scanner did not improve and no benchmark change
  raised any score); authority attribution LANE-B, overall NOT
  LANE-A READY with unknown veto. Lane-A graduation correctly
  withheld.

## Benchmark strategy

Grow the existing IaC benchmark corpus (`tests/fixtures/iac/`) into
the Agent Authority Benchmark: capability-escalation,
governance-change, delegation-change, MCP, IaC-mismatch, and unknown
scenarios, each with expected evidence and expected authority
classification, plus an evaluation harness reporting the methodology
metrics (detection, attribution, evidence, change, uncertainty).
Publish dataset + harness + results as the reproducibility package.
Academic publication follows measurement, never precedes it.

First slice delivered (2026-10-04): 37-case corpus
(`tests/benchmarks/authority/`), `safeai benchmark` harness
(`safeai/benchmark/`), published measurements
(`docs/benchmarks/authority/`). Discovery P/R/F1 1.0, determinism
1.0, evidence completeness 1.0, uncertainty expression 1.0, false
escalation rate 0.0. E1 verdict classes measured per-case; full
per-verdict-class precision/recall publication remains open.

Hardened slice (canonical truth v2.0, 56 cases): entity discovery
P/R/F1 with insufficient_evidence; 8 attribution levels;
material-change/escalation P/R/F1 with measured corpus
false-escalation (0.0, 4 observed) and missed-material (0.0)
rates; unknown preservation 1.0 across five uncertainty kinds;
per-class Lane-A (4× CANDIDATE, authority LANE-B at 0.464, overall
NOT READY + veto); 8-area mutation tests; determinism digests.
E1 verdict classes measured per-case; full
per-verdict-class precision/recall publication remains open.
- **E3 — Flagship: combined assurance** (P7): conditions A
  (dependency-only), B (agent-only), C (combined + deterministic
  policy); measure unsafe changes detected, false
  positives/negatives, unnecessary human review, explainability,
  evidence completeness, unknown exposure, human effort,
  reproducibility. The combined model is **not proven**; E3 tests
  whether it holds.

## What this alignment does NOT claim

- No combined SafeAI/OpenPulse assurance model exists yet.
- No cross-plane integration is implemented or committed.
- No runtime authority is proven by either plane.
- Regulatory framings (CRA, AI Act, DORA) are secondary context for
  evidence design, not validation of it.
