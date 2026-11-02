# Agent Authority Attestation — predicate v0.1 (experimental)

> **Experimental.** No schema-stability promise: any field may change in
> any release until the predicate is published as stable. The predicate
> carries `"experimental": true` and `"schema_stability": "none"`.

Predicate type (the URL of this page):

```
https://github.com/IkarusAILabs/SafeAI/blob/main/docs/attestation/agent-authority-v0.1-experimental.md
```

The attestation restates, per agent and for the repository, the
authority evidence of one SafeAI scan, so another system can reason about
it without re-running the scan (ROADMAP Layer 7, B3). It is static
evidence. It does not show that a configuration was deployed, that an
SVID was issued, or that the agent behaves as configured.

## Producing it

```bash
safeai scan . --manifest safeai-manifest.json \
  --experimental-attestation safeai-attestation.json
safeai manifest verify safeai-manifest.json --attestation safeai-attestation.json
```

The output is an unsigned [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):

| Field | Value |
|---|---|
| `_type` | `https://in-toto.io/Statement/v1` |
| `subject[0]` | the manifest file: `name` is its basename, `digest.sha256` the SHA-256 of its bytes |
| `subject[1]` | `{"name": "git-commit", "digest": {"gitCommit": "<sha>"}}` when the commit is known |
| `predicateType` | the URL above |
| `predicate` | see below |

## Binding to the manifest

The manifest written with the attestation carries an
`authority_attestation` block (manifest contract 1.1.0):

```json
"authority_attestation": {
  "experimental": true,
  "predicate_type": "https://github.com/IkarusAILabs/SafeAI/blob/main/docs/attestation/agent-authority-v0.1-experimental.md",
  "predicate_version": "0.1-experimental",
  "predicate_sha256": "<sha256 of the canonical predicate>"
}
```

The canonical predicate is its JSON with sorted keys and `(",", ":")`
separators. The manifest's integrity digest covers this block, so the
three digests bind both ways. `safeai manifest verify --attestation`
checks:

1. the manifest integrity digest (`ok`, or the usual `mismatch` and
   other statuses);
2. that a subject's `sha256` equals the manifest file's SHA-256
   (`subject-mismatch` otherwise: any edit to the file, whitespace
   included);
3. that the predicate's canonical digest equals
   `authority_attestation.predicate_sha256` (`predicate-mismatch`
   otherwise).

A manifest scanned without the flag gives `no-attestation-block`.

All of this shows only that the documents were not edited separately
after they were generated. To show who produced them, sign the
Statement as an external step. For example, with DSSE via Cosign:

```bash
cosign attest-blob --type "$(jq -r .predicateType safeai-attestation.json)" \
  --predicate <(jq .predicate safeai-attestation.json) \
  safeai-manifest.json --bundle safeai-attestation.sigstore.json
```

Cosign builds its own Statement with the same subject digest
(SHA-256 of the manifest file bytes).

## Predicate

Every level separates three groups, and nothing is invented to fill a
field:

* `machine_derived`: what SafeAI derived from the repository;
* `declared`: what people wrote down in the repository;
* `unknown`: the fields the scan could not fill, each with a `reason`.

```text
predicate
├── predicate_version          "0.1-experimental"
├── experimental               true
├── schema_stability           "none"
├── generator                  {name, version, ruleset_version}
├── project                    {project_id, name, repository{remote_fingerprint, commit_sha, branch, tag}}
├── agents[]                   one per manifest agent, sorted by agent_id
│   ├── agent_id, name, framework, agent_type
│   ├── machine_derived
│   │   ├── capabilities[]     {name, category}
│   │   ├── tools[]
│   │   ├── source_locations[]
│   │   ├── workload_identity[] repo-iac-observed identifiers (only beside a declared one)
│   │   ├── separation_of_duties[] {pair, first, second, via_delegation}
│   │   └── delegates_to[], delegated_by[]  (when the agent matches a delegation-graph node)
│   ├── declared
│   │   └── workload_identity[] declared identifiers
│   └── unknown[]              {field, reason}; always includes runtime_identity
├── repository
│   ├── machine_derived        tool_count, workload_identities, delegation{counts, edges, unresolved},
│   │                          separation_of_duties, severity_counts, highest_change_class,
│   │                          verified_statically
│   ├── declared               exceptions[] with approval and approval_state
│   └── unknown[]              the assurance boundary's not-verifiable-statically items
└── policy_decision            the scan's policy outcome
```

### Identity fields

An agent's identifiers come from its manifest record's
`workload_identity` field (v2.12, ROADMAP S4):

| `provenance_class` | Source |
|---|---|
| `declared` | `agent_identities` in `.safeai/config.yml` (a `spiffe://` or `wimse://` identifier per agent `name` or `agent_id`) |
| `repo-iac-observed` | the same identifier issued by a `ClusterSPIFFEID` in the repository (v2.10 collector) |
| `runtime-unverified` | reserved for issuance evidence supplied from outside the scan; readers must accept it, SafeAI never emits it |

The collector links SPIFFE IDs to workloads, not to agents, so an
observed identifier is attached to an agent only when it was declared for
that agent. Otherwise the agent's identity stays `unknown`, and the
reason says how many identities the repository issues that are not
attributed to an agent. `runtime_verified` is always `false`.

### Approval fields

Exceptions in `repository.declared.exceptions` carry the v2.12 approval
metadata (`approved_by`, `approved_at`, `escalation_owner`) and
`approval_state` (`approved`, `self-approved`, `unrecorded`). See
`safeai/kya/approval.py`.

## Known limits

* Agent ↔ delegation-node matching is by name and framework. Agents that
  the framework parsers report under a generic name (for example
  `Agent` for the OpenAI Agents SDK) do not match; their delegation is
  listed as `unknown`, and the repository's full graph is under
  `repository.machine_derived.delegation`.
* Blueprint agent-governance metadata and CIMD fields (ROADMAP B3) are
  not mapped yet.
