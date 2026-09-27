# ADR 0008 — Lane-A graduation criteria for correlations

- Status: accepted
- Date: 2026-09-26
- Context: Lane A gates on uncertain evidence would convert unknown into
  unsafe-or-safe silently. All v2.5 IaC output starts Lane B; the project
  needs a written, measurable bar before any correlation can gate CI.
- Decision: an IaC correlation verdict may become Lane A only when (a)
  both cited sides carry `declared` or `detected` provenance (never
  `inferred`, `unknown`, `repo-iac-observed`-alone, or
  `partially-resolved`); (b) precision on the pinned IaC benchmark corpus
  meets a published threshold (≥95% for the graduated verdict class);
  (c) a policy profile explicitly opts in. Inferred authority never
  blocks, in any release. IaC unknowns flow through the existing
  `authority.unknown` policy section — no parallel mechanism.
- Alternatives: graduate on maintainer judgement alone (rejected:
  unmeasurable, unreviewable); allow `partially-resolved` to gate
  (rejected: unresolved values are unknowns wearing syntax).
- Consequences: v2.5 ships zero Lane-A IaC surface; graduation is a
  future roadmap item with its own tests, corpus numbers, and CHANGELOG
  entry.
