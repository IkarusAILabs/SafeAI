# SafeAI Manifest Contract v1

`safeai-manifest.json` is the canonical portable artifact for SafeAI KYA
evidence — the interface between local scans, the local registry, CI
artifacts, portable import/export, and future evidence aggregation. The
SQLite registry is an implementation detail; integrations consume the
manifest.

- Normative schema: `schemas/safeai-manifest/v1.0.0.json`
  (JSON Schema draft 2020-12).
- Compatibility policy: `docs/manifest/COMPATIBILITY.md`.
- Worked examples: `docs/manifest/EXAMPLES.md`.
- Legacy field reference: `docs/reference/KYA_MANIFEST.md`.

## Identity fields

Every manifest carries three independent versions — do not conflate them:

| Field | Example | Meaning |
|---|---|---|
| `safeai.version` | `"2.2.0"` | Scanner package that produced the scan |
| `schema_version` | `"1.2"` | Legacy document shape (`1.0`/`1.1`/`1.2`, additive) |
| `contract.version` | `"1.0.0"` | Public contract version (semver; this document) |

## Validate locally (offline, no dependencies beyond PyYAML/stdlib)

```bash
safeai manifest validate safeai-manifest.json
safeai manifest verify safeai-manifest.json
```

`validate` checks structure, value domains, and compatibility semantics and
prints field-level errors. `verify` additionally recomputes the canonical
`integrity.payload_sha256` digest (see `docs/manifest/EXAMPLES.md`).

The stdlib validator (`safeai/kya/contract.py`) deliberately does not
implement the full JSON-Schema draft engine (no `$ref` resolution, no
`pattern` evaluation beyond pinned constants). Third-party consumers
should validate against the published schema file with their own tooling;
verdicts agree on every required-field and enum rule.

## Data classification

- **Source evidence** — `agents`, `tool_surface`, `components`,
  `dependency_inventory` (names only, never values), finding `location`
  (`path` + line numbers) and `fingerprint`.
- **Inferred evidence** — findings with `confidence: low`, heuristic
  provenance (`provenance.heuristic: true`), capability diffs.
- **Unverified runtime assumptions** — everything in `assurance_boundary`
  under "not statically verifiable" (IAM, runtime identity, network
  policy, deployed behavior).
- **Redacted secrets** — `message`/`evidence` pass through
  `safeai/kya/util.py:redact_secrets`; raw source blocks and secret values
  are never emitted.

## v2.4 evidence fields (additive, optional)

- Findings carry `provenance_class` (`declared | detected | inferred |
  unknown`) and `gateability` (`deterministic | review-only`).
- `authority_changes` lists per-tool `change_class`, `change_types`,
  and `inferred_only`; `summary` carries `authority_change_counts` and
  `highest_change_class`.
- `exception_evaluations` records each exception's `target_type`,
  `target_id`, `state` (`active | expired | stale | scope-mismatch |
  invalid`), owner, and expiry — so an external consumer can answer why
  a finding was permitted without reading local SQLite state.
- Pre-v2.4 manifests omit these keys and remain readable: validators
  treat absence as unknown, never as safe.

## v2.5 IaC correlation fields (additive, optional, Lane B)

- Findings from IaC correlation carry `provenance_class:
  repo-iac-observed` and `gateability: review-only` (pre-set at
  creation; normalization never overwrites explicit values).
- `iac_correlations` (schema v2) carries `identities` (kind/name/
  namespace/source_ref), `agent_identity_links` (agent/identity/
  link_type/confidence/file:line evidence), `grants` (identity,
  per-field resolved/partially-resolved/unresolved actions/resources,
  scope, source file:line, provenance, fidelity notes),
  `grant_bindings` (identity → binding → role chains), per-domain
  `verdicts` (`MATCH | EXCESS_AUTHORITY | AUTHORITY_MISMATCH |
  UNVERIFIED_LINK | UNKNOWN`) each with agent, identity, declared,
  grant, and link evidence refs plus resolution, and `counts`.
  `lane` is pinned to `"B"`; Contract v1 requires non-UNKNOWN
  verdicts to cite evidence.
- `summary` carries `iac_grant_count` and `iac_verdict_counts`.
- Fidelity ceiling: Terraform parsing is a brace-block scanner
  (ADR-0006/0009) — interpolation, modules, dynamic blocks, and
  external payloads degrade the affected fields; unresolved material
  shadows absence claims (UNKNOWN, never false mismatch). Repository
  IaC is evidence of declared grants, never proof of deployed
  permission.

## Not a guarantee

A valid manifest proves **structure**, not truth: import validates declared
schema compatibility but cannot prove the original scan was truthful or
complete. Static analysis evidence is never a security guarantee,
compliance certificate, or proof of deployed authorization. See
`assurance_boundary` in every manifest.
