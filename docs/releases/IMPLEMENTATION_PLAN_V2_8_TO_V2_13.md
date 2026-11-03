# Implementation Plan — v2.8 → v2.13

> Derived from `ROADMAP.md` (priority sequence P0–P8), including the
> Blueprint Alliance items B1–B6, the SPIFFE / SPIRE items S1–S6 and the
> external developments review items E1–E3 (2026-10-28).
> **Baseline: v2.7.0 (2026-10-22) plus `main` at `7941831` (2026-10-31).**
> Status: v2.8.0, v2.9.0 and v2.10.0 shipped 2026-11-01. v2.10.0 also
> carries v2.11 items 2.11-1 to 2.11-3; 2.11-4 (published precision)
> waits on human review (#300). v2.12.0 shipped 2026-11-03.
> Supersedes `IMPLEMENTATION_PLAN_V2_7_TO_V2_11.md`; item IDs from that
> plan are kept in the *Was* column so nothing is lost in renumbering.
>
> Every release keeps the standing commitments: offline, deterministic,
> static evidence only, unknown is an evidence state, additive-only
> manifest evolution, no Lane-A promotion without published precision
> (ADR-0008), DCO sign-off.

## Status at 2026-11-01

*Baseline snapshot from when this plan was written (before v2.8). The
current state of each release is in its own **Status** section below.*

| Area | State |
|---|---|
| Latest release | v2.7.0 (2026-10-22); floating tags `v2.7` and `v2` on it |
| `main` since v2.7.0 | 21 commits: 14 features, fixes, tests and docs (#257–#277, #287, #288) and 7 dependency/CI bumps |
| CI on `main` | green (CI, GitHub Action tests, Scorecard) |
| Open PRs | none |
| Security alerts | 0 Dependabot; 2 Scorecard (`CII-Best-Practices`, `Code-Review`), both process alerts with no file |
| Authority benchmark | 58/58 cases hold, CI-gated on every PR |
| Planned v2.7.1 | **not released.** Its one item (2.7-2 provenance audit) is half done: #277 made the enums single-source with schema-parity tests, but no test checks emitted output against them |
| v2.8 items | none started: control mappings exist in `safeai/controls/` but no JSON or SARIF output uses them; no Blueprint catalog; no `safeai/iac/spiffe.py` |
| E1–E3 | in the roadmap since #288, in no implementation plan until this one |

### What the old plan missed

1. **v2.7.1 can't be a patch any more.** `main` now carries additive
   features: per-side provenance on access-mode transitions (#257) and
   evidence metrics in the HTML report (#274). Under SemVer, the next
   release is a minor version.
2. **The changelog lags `main`.** `[Unreleased]` covers #257–#260.
   #269 (UTF-8 I/O fix), #274 (HTML evidence metrics) and #277 (single
   source for the provenance and gateability enums) are user-visible and
   absent; #270, #272, #276 and #287 are docs and tests.
3. **DCO is a standing commitment but not a required check.** #269,
   #274, #276 and #277 merged without every commit signed off. Either
   make `DCO` a required status check on `main`, or record when an
   unsigned merge is accepted.
4. **E1 (package-manager authority) is P1** but had no release slot.
   The priority sequence puts P1 ahead of the P3 SPIFFE collector.
5. **The roadmap's change dimensions are not the implemented ones.**
   ROADMAP.md lists `authority | destination | data_reach |
   governance_control | delegation | autonomy | credential_dependency |
   dependency | unknown` as machine-readable in `contract.py`.
   `contract.py` defines no dimensions; the per-tool authority block
   (`capability_diff.authority_for`, mirrored in
   `evidence_metrics.AUTHORITY_DIMENSIONS`) carries `destinations`,
   `data_scope`, `approval`, `autonomy`, `delegation`, `credential` and
   `identity`. There is no `dependency` dimension, and `credential` is
   always `unknown`. E1 and S2 both say "map onto existing dimensions",
   so this has to be settled first (item 2.8-4).

## Release gate (applies to every version)

1. `python -m pytest tests/ -q` and `ruff check safeai/ tests/` green.
2. `safeai benchmark` re-run; no previously holding case regresses; any
   new measurement published under `docs/benchmarks/` with its digest.
3. Manifest changes are additive; `safeai manifest validate` accepts
   the new output and v2.6/v2.7 manifests.
4. New detections ship **Lane B (review-only)** first.
5. CHANGELOG `[Unreleased]` lists every merged PR that changes behaviour
   or output before the release PR opens (new; see item 2.8-0).
6. Every new rule or change type has benchmark cases before any gate
   consumes it.

## Sequencing rationale

Ship what is already on `main` first, with the two small P0 items that
finish evidence hygiene (v2.8). Then E1 (v2.9): it is P1, reuses
existing detectors (shell allowlists, the name-only secret inventory),
and is the authority half of the dependency question OpenPulse answers
from the ecosystem side. Workload identity (v2.10) comes before identity
*change* semantics (v2.11) because change types need the collector's
output to diff. Attestation (v2.12) waits for the identity field it must
carry; standards exports (v2.13) wait for a stable evidence shape.
Research items (E2, E3, B5) produce reports, not releases, and run in
parallel.

Sizes are relative (S ≤ 3 days, M ≤ 2 weeks, L > 2 weeks of one
maintainer). Target dates assume the cadence so far (v2.5 → v2.6 took one week,
v2.6 → v2.7 two and a half) and are indicative only.

---

## v2.8.0 — Evidence Hygiene & Mapping  *(P0, B1)* — **SHIPPED 2026-11-01** (#293)

| # | Item | Was | Roadmap | Size |
|---|---|---|---|---|
| 2.8-0 | Changelog catch-up for #269, #270, #272, #274, #276, #277, #287 (credits included). Release gate item 5 below makes this a check for every later release. | — | Standing commitments | S |
| 2.8-1 | **Provenance audit:** a test that scans the authority corpus and asserts that every emitted finding, capability and authority statement carries an enum-valid `provenance_class` and a well-formed evidence ref. Builds on #277's single-source enums. | 2.7-2 | P0 provenance audits | S |
| 2.8-2 | Control mappings (`safeai/controls/mappings.py`) in JSON (`controls` per finding) and SARIF (`properties.controls`, plus `tags`). Taxonomy only, no coverage claim. | 2.8-0a | Layer 4 evidence mapping | S |
| 2.8-3 | Blueprint reference-architecture component catalog and mappings for the authority, change, MCP and IaC rules; prefixed IDs (`BP-P1-…`); "publicly available architecture" wording; no membership claim. | 2.8-0b | B1 | M |
| 2.8-4 | **Change-dimension reconciliation:** one canonical list in `contract.py` (with schema parity, as #277 did for provenance), used by `capability_diff` and `evidence_metrics`; ROADMAP.md names the same list. Decide whether `dependency` becomes a dimension (needed by E1); additive only. | — | P0, Layer 3 | S |
| 2.8-5 | ROADMAP re-baseline: status labels say "verified at v2.5.0"; update them to v2.8.0, and record S6's SPIFFE Community Day (2026-10-27) as past. | — | Roadmap hygiene | S |

**Exit criteria:** SARIF validates against the 2.1.0 schema with the new
properties; one dimension list in code, schema and ROADMAP.md; the
benchmark digest is unchanged (mappings are output-only).

## v2.9.0 — Package-Manager Authority  *(P1, E1)* — **SHIPPED 2026-11-01** (#295, #297)

| # | Item | Roadmap | Size |
|---|---|---|---|
| 2.9-1 | Benchmark cases **first**: agents with and without package-manager authority across Claude Code settings, MCP shell tools, CrewAI / LangGraph shell tools; an unknown case where the command is built at runtime. | E1, Layer 8 | M |
| 2.9-2 | Detect package-manager commands in shell allowlists and tool definitions: install/add/upgrade/remove (`npm`, `pnpm`, `yarn`, `pip`, `uv`, `poetry`, `cargo`, `go get`) and publish (`npm publish`, `twine upload`, `cargo publish`). New capability `CAP_package_manager`, access mode `write` for install and `execute` for publish. | E1, Layer 1 | M |
| 2.9-3 | Registry credential names (`NPM_TOKEN`, `PYPI_API_TOKEN`, `TWINE_PASSWORD`, `CARGO_REGISTRY_TOKEN`, …) through the existing name-only secret inventory, linked to the capability. This is the first evidence to populate the `credential` dimension, which is `unknown` for every tool today. | E1 | M |
| 2.9-4 | Write access to manifests and lockfiles (`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`, lock files) via filesystem write scopes. | E1 | S |
| 2.9-5 | Diff mapping on the dimensions settled in 2.8-4: gaining install → `dependency`; install → publish → access-mode widening on the capability; new registry credential → `credential`. | E1, Layer 3 | S |

**Exit criteria:** Lane B only; precision and recall on the new cases
published; reports state *that* the agent can change dependencies, never
*whether* a package is safe (OpenPulse's plane).

**Status.** Implemented for Claude Code grants (settings, slash-command
`allowed-tools`, subagent tools), literal commands in LangGraph, CrewAI
and AutoGen source, and MCP tool names:

| # | Done | Not yet |
|---|---|---|
| 2.9-1 | Nine cases (Claude Code grants, Python source literal and variable commands, MCP tool names), all holding, in `tests/benchmarks/authority-pending/` | Human review of their truth (#296), then promotion into the corpus |
| 2.9-2 | `CAP_package_manager` from `Bash(...)` grants and from literal `subprocess` / `os.system` commands in LangGraph, CrewAI and AutoGen source (detected); MCP tool names such as `npm_install` (inferred, surface only); all review-only | LangChain and other parsers that do not model subprocess calls; attributing Python-source capabilities to their tool function (existing gap) |
| 2.9-3 | Registry credential names from the same settings file's `env` block (names only) populate `credential` | Repository-wide inventory linking (a per-tool link from it would be inferred) |
| 2.9-4 | `Write`/`Edit` grants naming a manifest or lockfile carry it as a `dependency` target | — |
| 2.9-5 | `dependency` dimension; install → publish is a `write` → `execute` widening; Lane-B capabilities are excluded from `--fail-on-authority-change` and `--fail-on-escalation` | — |

Released before the precision exit criterion was met, at the author's
decision: the rule stays review-only and outside both gates until the
human review of 2.9-1 (#296) lets its precision be published.

## v2.10.0 — Workload Identity  *(P3, S1, S3, S5)* — **SHIPPED 2026-11-01** (v2.10.0: #299)

| # | Item | Was | Roadmap | Size |
|---|---|---|---|---|
| 2.10-1 | `safeai/iac/spiffe.py`: parse `ClusterSPIFFEID` (`spiffeIDTemplate`, pod/namespace selectors, `federatesWith`) and `ClusterFederatedTrustDomain`; identity kind `spiffe_id`. | 2.8-1 | S1 | M |
| 2.10-2 | Link agent workload → ServiceAccount → SPIFFE ID in `safeai/iac/linking.py`; unresolvable templates or selectors stay `UNKNOWN` / `UNVERIFIED_LINK`. | 2.8-2 | S1 | M |
| 2.10-3 | Istio `AuthorizationPolicy` principals as declared callers of a SPIFFE identity. | 2.8-3 | S1 | S |
| 2.10-4 | Static-credential-where-workload-identity-exists review signal. | 2.8-4 | S3 | S |
| 2.10-5 | Benchmark cases (template resolution, ambiguous selectors, federation widening, principal-based authorization); publish agent → identity attribution and unknown rate for them. | 2.8-5 | S5 | M |

**Exit criteria:** Lane B only; the v2.7 evidence metrics show the
agent → identity unknown rate before and after on the corpus.

**Status.**

| # | Done | Not yet |
|---|---|---|
| 2.10-1 | `safeai/iac/spiffe.py`: `ClusterSPIFFEID` (template, pod and namespace selectors, `federatesWith`), `ClusterFederatedTrustDomain`, `ControllerManagerConfig` (own document or inside a ConfigMap); identity kind `spiffe_id` | SPIRE server configuration (HCL); `ClusterStaticEntry` |
| 2.10-2 | Workload → ServiceAccount → SPIFFE ID, template rendered per workload; undecidable selectors and workloads with no namespace stay `unknown` with the reason; links (`workload-spiffe-id`) kept out of grant correlation | Linking a workload to an individual tool, so the per-tool `identity` dimension stays `unknown` |
| 2.10-3 | Istio `AuthorizationPolicy`: targets by selector, `principals` and `notPrincipals` matched to SPIFFE assignments or by Istio's ns/sa convention; any-caller and mesh-wide policies flagged | `requestPrincipals` (end-user JWTs) are noted, not mapped |
| 2.10-4 | `IAC_STATIC_CREDENTIAL_WITH_WORKLOAD_IDENTITY` (low, review-only) from the workload's own pod spec, names only | — |
| 2.10-5 | Five cases in `tests/benchmarks/authority-pending/identity/`, all holding; harness truth section `workload_identity`; `unknown_workload_identity_rate` in the evidence metrics | Human review of the five cases' truth |

Measured on the five pending cases (truth not yet human-reviewed): 15
workloads; before v2.10 every one had an unknown identity (no
collector), after it 6 resolve, 1 partially resolves and 8 stay unknown
(2 undecidable selectors, 6 with no matching registration). All 7 expected
SPIFFE assignments and all 3 expected callers are found, with none extra.
On the 58 reviewed cases, the 2 workload manifests stay unknown (no
registration in those repositories) and both digests are unchanged.

## v2.11.0 — Delegation & Identity Change Semantics  *(P1/P2, B2, S2)* — **2.11-1 to 2.11-3 SHIPPED in v2.10.0** (#301, #303, #304)

| # | Item | Was | Roadmap | Size |
|---|---|---|---|---|
| 2.11-1 | Explicit delegation change types (new sub-agent, depth/breadth increase, sub-agent capability not held by its delegator) as the primary signal over `ESC_COMBO_*` proxies. | 2.9-1 | B2, Layer 3 | L |
| 2.11-2 | Separation-of-Duties rule class for conflicting capability pairs. | 2.9-2 | B2 | M |
| 2.11-3 | Identity change types on the `identity` and `credential` dimensions (new or broadened SPIFFE ID, new federated trust domain, new JWT-SVID audience, regression to static credentials). | 2.9-3 | S2 | M |
| 2.11-4 | Material-change precision for the new types. | 2.9-4 | P1 | M |

**Exit criteria:** each new type has benchmark cases with P/R/F1
published before any `--fail-on-authority-change` path consumes it.

**Status.** 2.11-1, 2.11-2 and 2.11-3 shipped in v2.10.0 (released
together with the v2.10 items, at the author's decision); 2.11-4 waits
on human review of the pending cases (#300). There will be no
separate v2.11.0 feature release.

| # | Done | Not yet |
|---|---|---|
| 2.11-1 | Static delegation graph (`report.delegation_graph`, also in the manifest): Claude Code session → subagents, OpenAI Agents SDK `handoffs` (including `handoff()` and inline `Agent(...)`), CrewAI `allow_delegation` and hierarchical managers; run-time targets recorded as unresolved. Change types `DELEGATE_ADDED`, `DELEGATION_BREADTH_INCREASED`, `DELEGATION_DEPTH_INCREASED`, `DELEGATE_EXCEEDS_DELEGATOR` (by tool name), `SUBAGENT_TOOLS_WIDENED`, under `capability_diff.delegation_changes`, review-only, in the PR comment | LangGraph and AutoGen delegation; capability-level (not tool-name) comparison once Python capabilities are attributed to tool functions; replacing the `ESC_COMBO_*` proxy once precision is published |
| 2.11-2 | `SOD_CONFLICTING_AUTHORITY` (low, review-only, in `LANE_B_RULES`) over four pairs: `SOD-REQUEST-APPROVE` (same transaction object), `SOD-CHANGE-MERGE`, `SOD-ACT-ERASE-AUDIT` (IAM), `SOD-SELF-GRANT` (edit own Claude Code permission settings). Holders: Claude Code session and subagents, MCP servers, OpenAI/CrewAI agents (including tools reachable through delegation), AWS IAM roles. `report.separation_of_duties` and the manifest | Kubernetes RBAC pairs; capability-level pairs for Python tools; an organisation-supplied pair catalogue |
| 2.11-3 | `IDENTITY_ADDED`, `IDENTITY_REMOVED`, `IDENTITY_BROADENED`, `CALLER_ADDED` → `identity`; `FEDERATION_ADDED` → `destinations`; `STATIC_CREDENTIAL_ADDED` → `credential`; under `capability_diff.workload_identity_changes`, shown in the PR comment, never gating. A baseline from before v2.10 is reported as not assessed. The manifest now always carries the workload-identity block, so it works as a baseline | JWT-SVID audience changes (not statically visible) |
| 2.11-4 (delegation) | Seven pending cases: three graph cases (handoff chain with an unresolved factory, CrewAI delegation, Claude Code subagents) and four baseline pairs (handoff added, depth increased, subagent tools widened, file moved with no change); harness truth sections `delegation_edges`, `delegation_unresolved`, `delegation_changes` | Human review; P/R/F1 from reviewed truth |
| 2.11-4 (SoD) | Six pending cases (one per pair, a conflict joined by a handoff, and a look-alikes case with broad grants and unrelated verb pairs); harness truth section `sod_conflicts` | Human review; P/R/F1 from reviewed truth |
| 2.11-4 (identity) | Six pending baseline-pair cases (one per positive type, plus a reordering case with no change), harness truth section `identity_changes` | Human review of the cases; P/R/F1 published from reviewed truth |

On the six pending cases every expected change is found and nothing
extra (6/6, plus no change on the reordering case). With one case per
type that is not yet a precision estimate; it becomes one once the
truth is reviewed and more cases exist.

## v2.12.0 — Attestation & Accountability  *(P4, P6, B3, S4)* — **SHIPPED 2026-11-03** (#308, #309)

| # | Item | Was | Roadmap | Size |
|---|---|---|---|---|
| 2.12-1 | Experimental Agent Authority Attestation (in-toto-style predicate); machine-derived, declared and unknown fields separate; behind an experimental flag; no schema-stability promise. | 2.10-1 | B3, Layer 7 | L |
| 2.12-2 | SPIFFE / WIMSE identity field with provenance (`declared`, `repo-iac-observed`; `RUNTIME_UNVERIFIED` reserved). | 2.10-2 | S4 | S |
| 2.12-3 | Approval metadata on exceptions and decisions (who, when, expiry, escalation owner). | 2.10-3 | P6 | M |

**Exit criteria:** attestation round-trips through `manifest verify`;
manifest contract minor bump (new optional section) per
`docs/manifest/COMPATIBILITY.md`.

**Status.** All three items shipped in v2.12.0 (manifest contract
1.1.0), with the leading-dot path fix (#309).

| # | Done | Not yet |
|---|---|---|
| 2.12-1 | `--experimental-attestation PATH` (with `--manifest`): unsigned in-toto Statement v1, subject = manifest file SHA-256 (+ git commit), predicate `agent-authority v0.1-experimental` with `machine_derived` / `declared` / `unknown` per agent and for the repository; manifest `authority_attestation` block holds the predicate digest; `safeai manifest verify M --attestation A` checks integrity, subject and predicate (`subject-mismatch`, `predicate-mismatch`, `no-attestation-block`) | Signing stays external (documented Cosign example); Blueprint agent-governance and CIMD field mapping; agents reported under a generic parser name do not match delegation nodes |
| 2.12-2 | `agents[].workload_identity`: `declared` (`.safeai/config.yml` `agent_identities`, SPIFFE or WIMSE) and `repo-iac-observed` beside a declared ID issued by an in-repository `ClusterSPIFFEID`; states `corroborated` / `declared` / `unknown`; `runtime-unverified` reserved, accepted by the validator and schema, never emitted | Attributing an observed SPIFFE ID to an agent without a declaration (needs workload → agent linking) |
| 2.12-3 | Optional `approval` block (`approved_by`, `approved_at`, `escalation_owner`) on exceptions and suppressions, validated on load; `approval_state` `approved` / `self-approved` / `unrecorded` in report and manifest; `--require-approval` gate | Approval records for policy decisions other than exceptions and suppressions |

Reviewed benchmark digests unchanged (`ee76875d…`, `de9cb451…`); the
33 pending cases still hold. No new rule, so no new benchmark cases.

## v2.13.0 — Interoperability Exports  *(P7, B4, B6)* — target 2027-Q2

| # | Item | Was | Roadmap | Size |
|---|---|---|---|---|
| 2.13-1 | File-only OCSF export of findings and authority changes. | 2.11-1 | B4 | M |
| 2.13-2 | File-only SSF/CAEP Security Event Token payloads for MATERIAL / HIGH_RISK changes (no transmission in CE). | 2.11-2 | B4 | M |
| 2.13-3 | Apache-2.0 reference integration example and reproducible write-up. | 2.11-3 | B6 | M |

**Exit criteria:** CE still has a single explicit network path
(`--pr-comment-post`); exports validated offline against the published
schemas.

---

## Research track (parallel; output is a report, not a release)

| # | Item | Roadmap | Can start | Depends on |
|---|---|---|---|---|
| R-1 | **Comparative measurement** of Agentic Radar, Cisco MCP Scanner, Snyk Agent Scan and Aguara at pinned versions on the corpus cases each can parse, scored on SafeAI's rubric (entity discovery, attribution, change detection, unknown preservation); LLM-backed analysers off or reported separately; the cases every tool misses, SafeAI's included. | E2 | now | 58-case corpus (exists) |
| R-2 | **MalSkillBench** evaluation of MCP and skill poisoning detection; runtime-only behaviour counted as expected `unknown`, separately from misses. | E3 | once the dataset location and licence are confirmed | — |
| R-3 | **Blueprint scenario fixtures** and the technical report *which Blueprint questions can pre-deployment authority evidence answer, with what precision and unknown rate*. | B5 | after v2.8 (B1 catalog) | 2.8-3 |
| R-4 | Grow the corpus with outside contributions (issues #223, #225); every new case human-reviewed against truth schema v2. | Layer 8 | now | — |

No result from R-1 to R-3 is claimed before it is measured, and none
makes a superiority claim.

## Process items (no release)

| # | Item | Why |
|---|---|---|
| P-1 | Make `DCO` a required status check on `main`, or document the accepted exception. | Standing commitment vs four unsigned merges since v2.7.0 |
| P-2 | Apply for the OpenSSF Best Practices badge. | Clears Scorecard alert `CII-Best-Practices` |
| P-3 | Require one approving review on `main` (maintainer PRs included), or record why not. | Scorecard alert `Code-Review` |
| P-4 | Cut good first issues from this plan: SARIF `properties.controls` (2.8-2), registry credential name list (2.9-3), E1 fixture cases (2.9-1). Close or refresh the September "scan X and share results" issues (#129–#141) that have had no activity. | All six October good first issues (#262–#267) are closed; the open ones predate v2.6 |
| P-5 | Triage #229 (source-rights evidence idea) as RESEARCH ITEM or OpenPulse plane. | Unlabelled since 2026-10-04 |

## Explicitly out of scope for v2.8–v2.13

Runtime enforcement or monitoring, SPIRE agents / SVID issuance, live
IAM or SPIRE server queries, judging whether a dependency is safe
(OpenPulse), LLM analysis in the scan path, dynamic MCP probing, risk
scores or tiers, compliance determinations, CloudFormation / Helm /
serverless collectors (still DEFER), and the Enterprise Evidence Plane
(P8).
