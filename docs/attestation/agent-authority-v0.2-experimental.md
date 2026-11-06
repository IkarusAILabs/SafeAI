# Agent Authority Attestation — predicate v0.2 (experimental)

> **Experimental.** No schema-stability promise: any field may change in
> any release until the predicate is published as stable. The predicate
> carries `"experimental": true` and `"schema_stability": "none"`.

Predicate type (the URL of this page):

```
https://github.com/IkarusAILabs/SafeAI/blob/main/docs/attestation/agent-authority-v0.2-experimental.md
```

v0.2 (SafeAI 2.15) adds declared governance metadata, the agent's OAuth
Client ID Metadata Document when it is in the repository, and SPIFFE IDs
attributed through the workload that runs the agent. `manifest verify
--attestation` still accepts v0.1 Statements
([v0.1](agent-authority-v0.1-experimental.md)).

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
  "predicate_type": "https://github.com/IkarusAILabs/SafeAI/blob/main/docs/attestation/agent-authority-v0.2-experimental.md",
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
├── predicate_version          "0.2-experimental"
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
│   │   ├── workload_identity[] repo-iac-observed identifiers (beside a declared one, or linked through a workload)
│   │   ├── separation_of_duties[] {pair, first, second, via_delegation}
│   │   └── delegates_to[], delegated_by[]  (when the agent matches a delegation-graph node)
│   ├── declared
│   │   ├── workload_identity[] declared identifiers
│   │   └── governance         {owner, lifecycle, purpose, client_id, client_metadata{fields, evidence}, evidence}
│   │                          (only the declared keys)
│   └── unknown[]              {field, reason}; always includes runtime_identity, and
│                              governance.<field> for each governance field not declared
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

The collector links SPIFFE IDs to workloads. Since v2.15 an identifier
is attributed to an agent through the workload that runs it, with
`link: {type, workload}`:

| `link.type` | Evidence | Adds |
|---|---|---|
| `workload-annotation` | the pod template is annotated `ai.safeai.dev/agent: <name or agent_id>` | `declared` and `repo-iac-observed` (state `corroborated`) |
| `workload-entrypoint` | a container `command` / `args` starts the one file that defines this agent | `repo-iac-observed` only (the state stays `unknown` without a declaration) |

Ambiguous evidence (a name several agents share, an entrypoint matching
several files, a file defining several agents) links nothing. Otherwise
an observed identifier is attached only when it was declared for that
agent, and the reason says how many identities the repository issues
that are not attributed to an agent. `runtime_verified` is always
`false`.

### Governance fields

Declared in `.safeai/config.yml` (all optional, at least one per entry):

```yaml
agent_governance:
  - agent: support-bot              # name or agent_id
    owner: support-team@example.com
    lifecycle: production           # proposed | development | testing | production | deprecated | retired
    purpose: Answer order questions for signed-in customers
    client_id: https://support.example.com/oauth/client.json
```

`client_id` is the agent's OAuth client identifier in Client ID Metadata
Document form (an `https` URL). When a JSON file in the repository is
that document (its own `client_id` is the declared URL, and it has at
least one other client-metadata field), its metadata fields are copied
into `client_metadata` with the file as evidence. Secrets such as
`client_secret` are never copied, and the URL is never fetched. When the
document is not in the repository, or two files claim the same
`client_id`, `governance.client_metadata` is listed as `unknown` with
the reason.

Crosswalk to the field names other governance work uses:

| Concept | Field here | Source |
|---|---|---|
| Blueprint agent directory: owner | `declared.governance.owner` | declared |
| Blueprint agent directory: lifecycle | `declared.governance.lifecycle` | declared |
| Blueprint agent directory: scope | `machine_derived.capabilities`, `tools`, `delegates_to`; `declared.governance.purpose` states the intended scope | derived / declared |
| Blueprint agent directory: risk tier | not emitted | SafeAI emits no risk scores or tiers by design |
| Blueprint identity profile (CIMD) | `declared.governance.client_id`, `client_metadata.fields` (`client_name`, `redirect_uris`, `grant_types`, `token_endpoint_auth_method`, `jwks_uri`, `scope`, …) | declared, from the repository's own metadata document |
| Workload identity (SPIFFE / WIMSE) | `declared.workload_identity`, `machine_derived.workload_identity` | declared / repo-iac-observed |

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
* Governance metadata is what the repository declares; SafeAI checks its
  shape, not whether the owner exists or the lifecycle state is accurate.
* A Client ID Metadata Document served from elsewhere is never fetched,
  so its fields are `unknown` unless the repository holds the document.
