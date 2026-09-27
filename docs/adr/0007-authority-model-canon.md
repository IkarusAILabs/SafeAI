# ADR 0007 — Canonical authority model

- Status: accepted
- Date: 2026-09-26
- Context: the authority model existed implicitly across `tool_surface`
  entries, capability diffs, and policy lanes, but was never canonized —
  IaC correlation needs named nodes (Identity, Grant) and named edges
  (Agent→Identity, Identity→Grant) with uncertainty attached.
- Decision: canonize the minimum model. Existing entities unchanged
  (Agent, Tool with stable `tool_key`, Capability, AccessMode,
  Destination/DataScope). Add: **Identity** (a name string — service
  account, role, principal — never resolved) and **Grant** (a
  `(principal, action-pattern, resource-pattern, source_ref)` triple with
  `provenance` in `repo-iac-observed | partially-resolved`).
  Correlation verdicts: `MATCH | EXCESS_AUTHORITY | AUTHORITY_MISMATCH |
  UNVERIFIED_LINK | UNKNOWN`, with `UNVERIFIED_LINK` the default whenever
  the Agent→Identity edge lacks static evidence. Keep `change_type`
  (semantic vocabulary) separate from `change_class` (magnitude);
  vulnerability severity never determines change magnitude.
- Refined by ADR-0009: Identity gains namespace isolation; Grants carry
  per-field resolution and bind to identities via explicit GrantBinding
  chains; links require workload/config evidence; verdicts carry full
  evidence refs and strict semantics (MATCH/EXCESS/MISMATCH conditions,
  UNKNOWN preferred over false conclusions).
- Alternatives: a 10-level entity hierarchy (rejected: conflates entities,
  pipeline stages, and evidence states); reusing severity as magnitude
  (rejected: conceptually distinct dimensions, existing severity caps
  stay).
- Consequences: manifest gains optional `iac_correlations`; verdicts cite
  both sides' evidence refs or are UNKNOWN; model documented in
  `docs/manifest/` and the architecture docs.
