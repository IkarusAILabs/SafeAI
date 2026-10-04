# v2.6 — Authority Evidence Validation: Architecture Assessment

Status: implemented and validated on corpus (scanner behavior
unchanged; benchmark-only change). Maps the v2.6 brief onto the
v2.5.0 tree, commit by commit verified; hardening review applied
(canonical gold truth v2.0, entity/attribution/change/unknown PRF,
per-class Lane-A, 8-area mutation tests). Verdict: overall
RESEARCH / NOT LANE-A READY (authority attribution LANE-B at
end-to-end 0.464 over all exercised capabilities; unknown veto).

## 1. Existing models (all verified in-tree)

- **Authority model** (`safeai/analysis/tool_surface.py`,
  `capabilities.py`): Agent → Tool (`tool_key`) → Capability →
  Access Mode (`none<read<write<mutate<execute`) → Resource /
  Destination. Stable identifiers: path-independent `tool_key`.
- **Evidence model** (`safeai/kya/enrich.py`, `contract.py`):
  provenance `declared | detected | inferred | unknown |
  repo-iac-observed`; gateability `deterministic | review-only`;
  confidence labels; SHA-256 fingerprints; secret redaction.
  Vocabulary is canonical — no parallel representation is created.
- **Capability model**: 23 categories + ranked access modes; AST
  documents + symbol resolution (`analysis/semantic.py`), import
  graph, 13 analyzers, 19 framework adapters via plugin SDK.
- **Change model** (`analysis/capability_diff.py`): per-tool status
  (new/removed/changed/unchanged) × `CHANGE_CLASSES`
  (NO/LOW/MATERIAL/HIGH_RISK/UNKNOWN) × `change_types`
  (AUTHORITY_ADDED, DESTINATION_ADDED, APPROVAL_REMOVED, ...);
  severity never determines magnitude (invariant-tested).
- **IaC model** (`safeai/iac/`): Terraform brace-block scanner +
  K8s RBAC reader → identities, grants (per-field
  resolved/partially-resolved/unresolved), grant bindings, workload
  refs; `linking.py` (workload-SA + explicit config refs, never
  string coincidence); `semantics.py` (provider/service/ops-class
  matching, conservative wildcards); `iac_correlation.py` verdicts
  MATCH | EXCESS_AUTHORITY | AUTHORITY_MISMATCH | UNVERIFIED_LINK |
  UNKNOWN. Lane B only (ADR-0008); inferred never blocks.
- **Identity model**: tool identity (path-independent keys),
  K8s ServiceAccount (name+namespace), AWS IAM role names resolved
  from references; IRSA-style external identity is UNKNOWN, never
  guessed.
- **Report model** (`safeai/report/`): terminal/JSON/HTML/SARIF/
  PR-comment/registry views; `security_brief.py` pure
  report→brief transform (posture/evidence/changes/authority/
  actions/uncertainty/coverage/value); deterministic rendering
  (content-derived table IDs); injection-safe escaping.
- **Benchmark/test infrastructure**: `benchmarks/catalog.yml`
  (21 entries) + `scripts/run_benchmarks.py` + `test_benchmarks.py`
  (validity, determinism, honesty); `tests/fixtures/iac/benchmark/`
  (TF/K8s/linking + catalog.yml) + `test_iac_benchmark.py`
  (precision/recall harness); `test_architectural_invariants.py`
  (12 invariants incl. UNKNOWN never gates, severity/magnitude
  separation); 1205+ tests green.

## 2. Current gaps (why v2.6 exists)

1. No public authority benchmark: fixtures are unit-test fragments,
   expected truth is code-adjacent, and IaC corpus covers only IaC.
2. No measured precision/recall/F1 for discovery, attribution,
   change detection; no false-escalation or unknown rates.
3. No explicit materiality model doc (classification exists in code).
4. No Lane-A graduation criteria beyond ADR-0008's qualitative bar.
5. No mutation-style tests for authority correlation.
6. No validation report artifact; benchmark quality not surfaced
   anywhere (and must never be confused with scan results).

## 3. Components mapping

- **KEEP**: tool_surface/capabilities, capability_diff + change
  taxonomy, iac/* collectors + linking + semantics + correlation,
  enrich/contract/manifest provenance, policy lanes + exceptions,
  security_brief, SARIF/JSON/HTML/PR renderers, invariants,
  run_benchmarks.py + catalog.yml, test_iac_benchmark harness.
- **REFACTOR (narrow)**: extend `run_benchmarks.py` entry schema with
  authority-truth fields rather than a second runner; extend the IaC
  catalog format (input/expected/metadata dirs) into the new public
  corpus layout.
- **REPLACE**: nothing. No subsystem is removed.
- **NOT to build**: live AWS/K8s access; runtime monitor; new risk
  score; LLM in analyzer; new manifest/evidence model; framework
  adapters for count; SARIF/JSON/HTML/PR behavior changes; UNVERIFIED
  runtime evidence ingestion (stays a reserved boundary).

## 4. Roadmap mapping

v2.6 implements Layer 8 (Research Validation) first slices plus the
measurement halves of Layers 2–5: benchmark corpus (P5), evaluation
methodology (P5), Lane-A graduation criteria (feeds P3), materiality
model doc (P1), unknown-rate metrics (P0/P6). No roadmap status flips
until benchmark evidence exists (§23: IMPLEMENTED vs VALIDATED vs
RESEARCH discipline).

## 5. Authority statement representation (no parallel schema)

Expected truth reuses native shapes: `tool_surface` entries
(tool_key + capabilities[] with access_mode), `capability_diff`
tools[] (status + change_class + change_types), IaC grants
(identity/actions/resources/resolution), verdicts (domain/verdict/
evidence refs), findings (rule_id + fingerprint + provenance_class
+ gateability). The benchmark `expected.json` schema references these
shapes; the harness compares structurally, never by string summary.
