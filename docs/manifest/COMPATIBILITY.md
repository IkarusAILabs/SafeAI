# Manifest Compatibility Policy (Contract v1)

## Version semantics

`contract.version` follows semver:

- **Patch** (`1.0.0` → `1.0.1`) — clarifications, new optional fields,
  looser validation. Old readers accept new documents.
- **Minor** (`1.0.x` → `1.1.0`) — new optional sections (as `integrity`
  was added). Old readers must ignore what they don't understand.
- **Major** (`1.x` → `2.0.0`) — required-field changes, removed fields,
  or changed value domains. Old readers must reject with a clear error
  (`safeai manifest validate` does this on the major number).

The legacy `schema_version` string (`1.0`/`1.1`/`1.2`) is frozen history:
`1.1` added `tool_surface`, `1.2` added `assurance_boundary`, all purely
additive. Contract v1 accepts all three.

## Unknown fields

**Unknown fields MUST be ignored, never rejected**, by any 1.x reader.
This matches long-standing SafeAI practice (`docs/reference/KYA_MANIFEST.md`:
"unknown optional fields must be ignored") and the registry importer's
forward-tolerant merge. Strict rejection modes may exist for integrity
(`--require-integrity`) but never for unknown keys.

## Reader/writer guarantees

- A Contract v1 reader accepts any `schema_version` in
  `{1.0, 1.1, 1.2}` and any `contract.version` with major `1`.
- A Contract v1 writer emits `schema_version: "1.2"` plus the `contract`
  block (name `safeai-manifest`, version `1.2.0`, minimum reader `1.0.0`).

## Contract history

| Contract | SafeAI | Change |
|---|---|---|
| `1.0.0` | 2.2 | First published contract (`schemas/safeai-manifest/v1.0.0.json`) |
| `1.1.0` | 2.12 | New optional section `authority_attestation` (experimental); optional fields `agents[].workload_identity` and `exception_evaluations[].approval` / `approval_state` (`schemas/safeai-manifest/v1.1.0.json`). A 1.0 reader ignores all of them. |
| `1.2.0` | 2.14 | New optional sections `delegation_changes` and `workload_identity_changes`: the baseline diff's review-only change blocks, null without a baseline (`schemas/safeai-manifest/v1.2.0.json`). Earlier readers ignore them. |
- Writers never remove fields within a major version; deprecations are
  announced in `CHANGELOG.md` with at least one minor-version notice
  period before removal in the next major.

## Older manifests

- Pre-2.2 manifests lack `contract` and `integrity`. They validate (with
  an informational note when `schema_version` < `1.2`) and import by
  default. `safeai manifest verify` reports `no-integrity` for them
  instead of failing — use `registry import --require-integrity` to
  enforce integrity where policy demands it.
- `registry import` additionally accepts inventory schema `1.0`/`1.1`
  (`safeai/kya/importer.py`), a separate portable-registry contract.

## Known discrepancy (documented, not hidden)

`docs/reference/KYA_MANIFEST.md` lists a `1.3` row (`evidence_type` on
every finding). As of Contract v1, `evidence_type` is emitted in
finding-enrichment/report metadata, **not** in manifest finding entries
(`safeai/kya/manifest.py:_finding_entry`). The published schema does not
require it. If manifest-level `evidence_type` ships later, it will be an
optional minor-version addition.

## What validation does not prove

Import validates **declared schema compatibility** — that the document has
the right shape. It cannot prove the original scan was truthful, complete,
or untampered (that's what the `integrity` digest + external signatures
address, and even those prove artifact integrity, not source truth).
