# Agent Authority Evidence Contract

> Status: Additive extension to the KYA Manifest Contract v1
> Version: 1.0.0
> Schema: `safeai/schemas/safeai-manifest/v1.0.0.json` (`authority_evidence`)

## Purpose

The Agent Authority Evidence Contract is an additive extension to
the KYA Manifest Contract v1. It represents **statically evidenced,
potentially reachable agent authority** with explicit provenance,
uncertainty, and assurance boundaries.

The contract enables independent tooling to consume agent authority
evidence **without SafeAI internals** — answering the research
question: *Can portable agent-authority evidence be evaluated by an
independent system without SafeAI internals?*

## Design principles

1. **Additive, not replacing.** The contract is carried under the
   `authority_evidence` key of the KYA manifest. Existing manifest
   consumers are unaffected; the block is optional and absent on
   scans without authority evidence.

2. **Evidence-bounded.** Every authority claim carries provenance
   (`declared`, `detected`, `inferred`, `unknown`,
   `repo-iac-observed`) and a resolution state (`resolved`,
   `unresolved`, `contradicted`, `unknown`). Claims without
   sufficient evidence are marked `unknown`/`unresolved`, never
   invented.

3. **Uncertainty is explicit.** The `uncertainty_summary` block
   counts statements by resolution and provenance class, so
   consumers can reason about how much of the authority surface is
   actually evidenced vs inferred.

4. **Assurance boundary is stated.** The `assurance_boundary` block
   states what the scan structurally cannot prove (runtime identity,
   runtime permissions, runtime egress, dynamic tool binding,
   runtime behaviour, deployed configuration). This is the
   contract's honesty clause: static analysis evidence is not
   runtime proof.

5. **Deterministic serialization.** The manifest uses sorted keys
   and stable ordering, so diffs between runs are meaningful and
   integrity digests are reproducible.

## Contract structure

```
authority_evidence
├── contract_identity          # {name, version}
├── subject_agents[]           # [{agent_id, framework}]
├── principal_evidence[]       # [{principal_id, kind, provenance, ...}]
├── delegation_evidence[]      # [{source_agent, target_agent, delegation_type, ...}]
├── authority_statements[]     # [{statement_id, agent_id, capability, ...}]
├── evidence_references        # {ref_id: description}
├── uncertainty_summary        # counts by resolution/provenance
├── assurance_boundary[]       # structural non-claims
├── source_revision            # {commit, repository}
├── safeai_version             # string
├── ruleset_version            # string
└── change_context             # {baseline_ref, current_revision, change_class}
```

### Fields

**contract_identity** — identifies the contract itself.
- `name`: `"agent-authority-evidence"`
- `version`: semver matching `^1\.[0-9]+\.[0-9]+$`

**subject_agents** — the agents whose authority is being described.
- `agent_id` (required, non-empty string): stable agent identifier
- `framework` (string): framework that defines the agent

**principal_evidence** — identity principals the agent may act as.
- `principal_id` (required, non-empty string): principal identifier
- `kind` (enum): `aws_iam_role`, `kubernetes_service_account`,
  `kubernetes_user`, `kubernetes_group`, `unknown`
- `provenance` (enum): `declared`, `detected`, `inferred`,
  `unknown`, `repo-iac-observed`
- `source_ref`, `namespace` (optional strings)

**delegation_evidence** — agent-to-agent delegation relationships.
- `source_agent` (required string): delegating agent
- `target_agent` (required string): delegated-to agent
- `delegation_type` (required enum): `explicit_sub_agent`,
  `framework_delegation`, `workflow_delegation`, `mcp_delegation`,
  `unknown`
- `provenance` (enum): as above
- `resolvability` (enum): `resolved`, `unresolved`, `unknown`
- `evidence_refs` (string array): references into `evidence_references`
- `confidence`, `notes` (optional strings)

**authority_statements** — the core authority claims.
- `statement_id` (required, non-empty string): stable statement id
- `agent_id` (required, non-empty string): subject agent
- `principal_ref` (string|null): principal this statement binds to
- `tool_ref` (string|null): tool this statement binds to
- `capability` (required string): capability name (e.g. `shell:execute`)
- `access_mode` (enum): `none`, `read`, `write`, `mutate`,
  `execute`, `unknown`
- `resource_provider` (enum): `aws`, `kubernetes`, `gcp`, `azure`,
  `filesystem`, `shell`, `network`, `database`, `mcp`, `unknown`
- `resource`, `destination` (optional strings): resource/destination
- `provenance` (required enum): as above
- `confidence` (optional string): confidence label
- `resolution` (enum): `resolved`, `unresolved`, `contradicted`,
  `unknown`
- `evidence_refs` (string array): references into `evidence_references`
- `assurance_boundary` (string array): per-statement boundary notes

**uncertainty_summary** — counts for uncertainty metrology.
- `authority_statement_count` (integer)
- `resolved_count`, `unresolved_count`, `unknown_count` (integers)
- `inferred_count`, `evidence_backed_count` (integers)

**assurance_boundary** — structural non-claims (array of strings).
Standard statements:
- `runtime_identity_not_proven`
- `runtime_permissions_not_proven`
- `runtime_egress_not_proven`
- `dynamic_tool_binding_not_proven`
- `runtime_behaviour_not_proven`
- `deployed_configuration_not_proven`

**source_revision** — provenance of the scanned source.
- `commit` (string): commit hash
- `repository` (string): repository identifier

**safeai_version**, **ruleset_version** — tool versions (strings).

**change_context** — change detection context.
- `baseline_ref` (optional string): baseline reference
- `current_revision` (optional string): current revision
- `change_class` (enum): `NO_CHANGE`, `LOW_CHANGE`,
  `MATERIAL_CHANGE`, `HIGH_RISK_CHANGE`, `UNKNOWN`

## Provenance classes

| Class | Meaning |
|-------|---------|
| `declared` | Explicitly declared in source/config (e.g. manifest, annotation) |
| `detected` | Detected by static analysis with high confidence |
| `inferred` | Inferred from naming/usage patterns; indicative, not confirmed |
| `unknown` | Insufficient evidence; no claim made |
| `repo-iac-observed` | Observed in repository IaC (Terraform, Kubernetes, etc.) |

## Resolution states

| State | Meaning |
|-------|---------|
| `resolved` | Evidence is sufficient and consistent |
| `unresolved` | Evidence is insufficient or ambiguous |
| `contradicted` | Evidence conflicts; the claim is contradicted |
| `unknown` | No evidence either way |

## Delegation types

| Type | Meaning |
|------|---------|
| `explicit_sub_agent` | Direct sub-agent creation (e.g. CrewAI `Agent` with `allow_delegation`) |
| `framework_delegation` | Framework-level delegation (e.g. LangChain `AgentExecutor`) |
| `workflow_delegation` | Workflow/orchestration delegation (e.g. Prefect `@flow`, LangGraph) |
| `mcp_delegation` | MCP tool delegation (client or server side) |
| `unknown` | Delegation target cannot be resolved statically |

## Assurance boundary

The assurance boundary is the contract's honesty clause. It states
what the scan **structurally cannot prove**:

- **Runtime identity** — static analysis cannot prove which identity
  the agent runs as at runtime.
- **Runtime permissions** — static analysis cannot prove the
  effective permissions at runtime (IAM policy evaluation, RBAC
  admission, etc.).
- **Runtime egress** — static analysis cannot prove network egress
  at runtime (dynamic endpoints, DNS, proxies).
- **Dynamic tool binding** — static analysis cannot prove which
  tools are bound at runtime (dynamic registration, MCP discovery).
- **Runtime behaviour** — static analysis cannot prove what the
  agent actually does at runtime (LLM outputs, tool call sequences).
- **Deployed configuration** — static analysis cannot prove the
  deployed configuration (environment variables, secrets, config
  files outside the repo).

Consumers must treat authority statements as **potentially
reachable** authority, not as runtime guarantees.

## Independent consumption

The contract is designed for independent consumption. A consumer
needs only:

1. The manifest JSON (with the `authority_evidence` block).
2. The JSON Schema (`safeai/schemas/safeai-manifest/v1.0.0.json`).
3. This document.

No SafeAI internals, database, or runtime are required. The
demonstration consumer (`benchmarks/authority_consumer_demo.py`)
shows the pattern:

1. **Validate** the `authority_evidence` block against the schema.
2. **Reconstruct** delegation chains from `delegation_evidence`.
3. **Output** authority statements in a human-readable form.
4. **Reason** over `uncertainty_summary` and `assurance_boundary`.

## Mutation testing

Security-sensitive fields are covered by mutation tests
(`safeai/kya/test_manifest_mutations.py`). The tests verify that
tampering with:

- `contract_identity.version` (pattern violation)
- `safeai_version`, `ruleset_version` (type violation)
- `source_revision.commit`, `source_revision.repository` (type violation)
- `assurance_boundary` (type/enum violation)
- `uncertainty_summary` counts (type violation)
- `authority_statements` provenance/access_mode/resolution (enum violation)
- `delegation_evidence` delegation_type (enum violation)
- `change_context.change_class` (enum violation)
- `statement_id`, `agent_id`, `principal_id` (empty-string violation)

is detectable by validation.

## Benchmark corpus

The delegation benchmark corpus
(`tests/benchmarks/authority/delegation/`) covers the delegation
types with 10 cases:

- `unknown_delegation`, `unknown_delegation_2` — unresolvable targets
- `subagent_chain` — CrewAI manager/worker delegation
- `explicit_sub_agent` — direct sub-agent creation
- `framework_delegation`, `framework_delegation_2` — LangChain, AutoGen
- `workflow_delegation`, `workflow_delegation_2` — Prefect, LangGraph
- `mcp_delegation`, `mcp_delegation_2` — MCP client, MCP server

Each case has `input/` (source), `expected/` (gold truth), and
`metadata/` (case description). The canonical truth schema (v2.0)
records agents, tools, capabilities, attribution, and
unknown-expectations.

## Relationship to other planes

The Agent Authority Evidence Contract is the **Agent Authority
Evidence Plane** instrument (SafeAI). It does not model the
**Software Ecosystem / Dependency Evidence Plane** (OpenPulse),
the **Assurance Policy / Decision Plane**, or the **Human
Accountability Plane**. Cross-plane combination is future research
(E3 flagship experiment), not implemented here.

## What this contract does NOT claim

- It does not prove runtime authority, identity, or behaviour.
- It does not certify safety or compliance.
- It does not replace human review or accountability.
- It does not combine with dependency evidence (no cross-plane model).
- It does not guarantee completeness of the authority surface
  (static analysis has inherent coverage limits).

## See also

- `docs/research/RESEARCH_ALIGNMENT.md` — research thesis and planes
- `docs/manifest/INTEGRITY.md` — offline integrity block
- `safeai/kya/contract.py` — validation implementation
- `safeai/kya/manifest.py` — manifest construction
- `safeai/schemas/safeai-manifest/v1.0.0.json` — JSON Schema
- `benchmarks/authority_consumer_demo.py` — independent consumer demo
- `safeai/kya/test_manifest_mutations.py` — mutation tests
- `tests/benchmarks/authority/delegation/` — delegation benchmark corpus