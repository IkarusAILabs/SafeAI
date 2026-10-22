# Implementation Plan — v2.7 → v2.11

> Derived from `ROADMAP.md` (priority sequence P0–P8) including the
> external framework alignment items B1–B6 (Blueprint Alliance) and
> S1–S6 (SPIFFE / SPIRE). Baseline: **v2.6.0** (2026-10-04).
>
> Every release keeps the standing commitments: offline, deterministic,
> static evidence only, unknown is an evidence state, additive-only
> manifest evolution, no Lane-A promotion without published precision
> (ADR-0008), DCO sign-off.

## Release gate (applies to every version)

1. `python -m pytest tests/ -q` and `ruff check safeai/ tests/` green.
2. `safeai benchmark` re-run; no previously holding case regresses; any
   new measurement published under `docs/benchmarks/` with its digest.
3. Manifest changes are additive; `safeai manifest validate` accepts
   both the new output and v2.6 manifests.
4. New detections ship **Lane B (review-only)** first.
5. CHANGELOG entry states what changed and what was *not* changed.

## Sequencing rationale

Measure before extending: v2.7 makes evidence quality visible on every
scan (the P0 gap the roadmap names explicitly), so every later release
can report whether it moved the unknown / inferred / unattributed
rates. Identity evidence (v2.8) comes before identity *change* semantics
(v2.9) because change types need the collector's output to diff.
Attestation (v2.10) waits for the identity field it must carry.
Standards exports (v2.11) wait for a stable evidence shape to export.

---

## v2.7.0 — Evidence Metrology  *(P0, B1)*

| # | Item | Roadmap | Notes |
|---|---|---|---|
| 2.7-1 | **Authority evidence metrics** on every scan: evidence-backed, inferred, unattributed authority rates; evidence completeness; finding provenance distribution; unknown authority-dimension rate when a baseline diff exists. Emitted in the JSON report and `manifest.summary.evidence_metrics`; summarised in the security brief coverage section. | Layer 2 research metric; P0 "manifest unknown-rate surfacing" | Rates use the benchmark convention (`insufficient_evidence`, never 0/1 on empty denominators). Metrics never gate. **In progress.** |
| 2.7-2 | Provenance audit: test that every emitted finding / capability carries an enum-valid provenance class and evidence ref shape. | P0 "provenance audits" | Test-only guard. |
| 2.7-3 | Wire existing control mappings (`safeai/controls/`) into JSON and SARIF output (currently computed nowhere outside the module). | Layer 4 evidence mapping | Taxonomy only; no coverage claim. |
| 2.7-4 | Blueprint reference-architecture component catalog + mappings for authority / change / MCP / IaC rules. | B1 | Prefixed control IDs to avoid catalog key collisions; "publicly available architecture" wording, no membership claim. |

**Exit criteria:** metrics present and deterministic on the 58-case
benchmark corpus; benchmark digest unchanged (metrics are additive
report fields, not benchmark inputs).

## v2.8.0 — Workload Identity Evidence  *(P3, S1, S3, S5)*

| # | Item | Roadmap |
|---|---|---|
| 2.8-1 | `safeai/iac/spiffe.py`: parse `ClusterSPIFFEID` (`spiffeIDTemplate`, pod/namespace selectors, `federatesWith`) and `ClusterFederatedTrustDomain`; new identity kind `spiffe_id`. | S1 |
| 2.8-2 | Link agent workload → ServiceAccount → SPIFFE ID in `safeai/iac/linking.py`; unresolvable templates/selectors stay `UNKNOWN` / `UNVERIFIED_LINK`. | S1 |
| 2.8-3 | Service-mesh authorization policy principals (Istio `AuthorizationPolicy`) as declared callers of a SPIFFE identity. | S1 |
| 2.8-4 | Static-credential-where-workload-identity-exists review signal. | S3 |
| 2.8-5 | Benchmark cases: template resolution, ambiguous selectors, federation widening, principal-based authorization; publish agent → identity attribution for SPIFFE cases. | S5 |

**Exit criteria:** Lane B only; v2.7 metrics show the agent → identity
unknown rate before/after on the corpus.

## v2.9.0 — Delegation & Identity Change Semantics  *(P1/P2, B2, S2)*

| # | Item | Roadmap |
|---|---|---|
| 2.9-1 | Explicit delegation change types (new sub-agent, delegation depth/breadth increase, sub-agent capability not held by delegator) replacing `ESC_COMBO_*` proxies as the primary signal. | B2, Layer 3 |
| 2.9-2 | Separation-of-Duties rule class for conflicting capability pairs. | B2 |
| 2.9-3 | Identity change types on existing dimensions (new/broadened SPIFFE ID, new federated trust domain, new JWT-SVID audience, regression to static credentials). | S2 |
| 2.9-4 | Material-change precision measurement for the new types. | P1 |

**Exit criteria:** each new type has benchmark cases with P/R/F1
published before any `--fail-on-authority-change` path consumes it.

## v2.10.0 — Attestation & Accountability  *(P4, P6, B3, S4)*

| # | Item | Roadmap |
|---|---|---|
| 2.10-1 | Experimental Agent Authority Attestation object (in-toto-style predicate), machine-derived / declared / unknown fields separated; behind an explicit experimental flag; no schema-stability promise. | B3, Layer 7 |
| 2.10-2 | SPIFFE / WIMSE identity field with provenance (`declared`, `repo-iac-observed`; `RUNTIME_UNVERIFIED` reserved). | S4 |
| 2.10-3 | Approval metadata on exceptions/decisions (who, when, expiry, escalation owner). | P6 |

**Exit criteria:** attestation round-trips through `manifest verify`;
manifest contract minor bump (new optional section) per
`docs/manifest/COMPATIBILITY.md`.

## v2.11.0 — Interoperability Exports  *(P7, B4, B6)*

| # | Item | Roadmap |
|---|---|---|
| 2.11-1 | File-only OCSF export of findings and authority changes. | B4 |
| 2.11-2 | File-only SSF/CAEP Security Event Token payloads for MATERIAL / HIGH_RISK changes (no transmission in CE). | B4 |
| 2.11-3 | Apache-2.0 reference integration example + reproducible write-up. | B6 |

**Exit criteria:** CE still has a single explicit network path
(`--pr-comment-post`); exports validated against the published
standard schemas offline.

---

## Explicitly out of scope for v2.7–v2.11

Runtime enforcement or monitoring, SPIRE agents / SVID issuance, live
IAM or SPIRE server queries, risk scores or tiers, compliance
determinations, CloudFormation / Helm / serverless collectors (still
DEFER), and the Enterprise Evidence Plane (P8).
