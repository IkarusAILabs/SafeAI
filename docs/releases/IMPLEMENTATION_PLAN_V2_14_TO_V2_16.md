# Implementation Plan — v2.14 → v2.16

> Follows `IMPLEMENTATION_PLAN_V2_8_TO_V2_13.md`, whose items all
> shipped by v2.13.0 (2026-11-03). This plan turns the *Not yet* column
> of that plan, and the *Not yet done* lists in `CHANGELOG.md`, into
> releases. **Baseline: v2.13.0 (`main` at `f4f8baa`).**
> **Status: all three shipped together as v2.16.0 (2026-11-06)**, at
> the author's decision; there is no v2.14.0 or v2.15.0.
>
> Standing commitments are unchanged: offline, deterministic, static
> evidence only, unknown is an evidence state, additive-only manifest
> evolution, no Lane-A promotion without published precision
> (ADR-0008), DCO sign-off. Every new signal is Lane B (review-only)
> and ships with pending benchmark cases; none gates until its precision
> is published from human-reviewed truth.

## Gaps and where they go

| Gap (from the v2.8–v2.13 plan or CHANGELOG) | Goes to |
|---|---|
| Delegation and workload-identity change types are not in the OCSF export | 2.14-1 |
| Separation-of-Duties results are not in the OCSF export | Already exported: every `SOD_CONFLICTING_AUTHORITY` finding is an OCSF 2007 event. 2.14-1 corrects the docs |
| LangGraph and AutoGen delegation | 2.14-2 |
| Kubernetes RBAC Separation-of-Duties pairs | 2.14-3 |
| Organisation-supplied Separation-of-Duties pair catalogue | 2.14-3 |
| SPIFFE ID attributed to an agent only when declared (no workload-to-agent linking) | 2.15-1 |
| Attestation does not map Blueprint agent-governance or CIMD fields | 2.15-2 |
| Approval records cover exceptions and suppressions only | 2.15-3 |
| Delegate authority compared by tool name, not capability | 2.15-4 |
| CloudFormation, Serverless Framework and Helm collectors | 2.16-1 to 2.16-3 |
| JWT-SVID audience changes | **Not code.** The audience is chosen by the workload at run time and appears in no repository file. Stays a documented limit |
| Signing and delivery of attestations and SETs | **Not code in CE.** Outside the Community Edition by design (single network path) |
| Proposing the SSF event type and an OCSF extension to the standards bodies | **Not code.** Process work, tracked in ROADMAP B6 |

## v2.14 — Change Coverage  *(B2, B4)* — **SHIPPED in v2.16.0** (#314)

| # | Item | Size |
|---|---|---|
| 2.14-1 | Manifest contract 1.2.0: optional `delegation_changes` and `workload_identity_changes` sections (the baseline diff blocks). OCSF export emits one IAM Analysis Finding (2008) per delegation or identity change, `severity_id` 0 (SafeAI assigns these review-only changes no severity), change type in `finding_info.types`. SSF SETs stay limited to MATERIAL / HIGH_RISK tool changes: delegation and identity changes have no change class. | M |
| 2.14-2 | Delegation graph for LangGraph (`create_react_agent`, `create_supervisor`, `create_swarm`, `create_handoff_tool`) and AutoGen (AgentChat `AssistantAgent(handoffs=...)`, `Swarm`, `RoundRobinGroupChat`, `SelectorGroupChat`, `MagenticOneGroupChat`; 0.2 `GroupChat` + `GroupChatManager`). Existing change types apply unchanged. | M |
| 2.14-3 | Separation of Duties for Kubernetes RBAC (ServiceAccount holders: `SOD-REQUEST-APPROVE` on CertificateSigningRequests, `SOD-SELF-GRANT` through `escalate` / `bind` / writes to RBAC objects, `SOD-ACT-ERASE-AUDIT` through deleting Events) and an organisation pair catalogue (`separation_of_duties.pairs` in `.safeai/config.yml`, glob patterns over authority item names). | M |

**Exit criteria:** pending cases for each new framework, pair and
export path; the 58-case digests unchanged; OCSF events of a real scan
validate against the vendored 1.9.0 schemas.

**Status.** All three items shipped in v2.16.0. Six new
pending cases (three delegation, three Separation of Duties; 39 pending
in all, every one holding); digests `ee76875d…` and `de9cb451…`
unchanged.

| # | Not yet |
|---|---|
| 2.14-1 | SSF SETs for review-only changes (they have no change class by design) |
| 2.14-2 | `import autogen` / module-attribute calls (`autogen.AssistantAgent(...)`) and agents built in another file; LangGraph `StateGraph` edges, which route control flow rather than delegate authority |
| 2.14-3 | Precision for the new pairs (human review); RBAC bound to users and groups rather than ServiceAccounts |

## v2.15 — Identity & Governance Evidence  *(S4, B3, P6, B2)* — **SHIPPED in v2.16.0** (#315)

| # | Item | Size |
|---|---|---|
| 2.15-1 | Workload-to-agent linking: a Kubernetes workload is linked to an agent by an `ai.safeai.dev/agent` annotation (`declared`) or by a container `command` / `args` naming the Python file that defines exactly that agent (`repo-iac-observed`). The SPIFFE ID the workload is issued is then attributed to the agent through the existing states (no new state value, so 1.x readers are unaffected), never by name coincidence. | M |
| 2.15-2 | Governance metadata in the attestation: `agent_governance` in `.safeai/config.yml` (owner, lifecycle state, purpose, CIMD `client_id` URL) and in-repository OAuth Client ID Metadata Documents, mapped into the predicate's `declared` group, with a field crosswalk to Blueprint agent-governance metadata and CIMD. Predicate `v0.2-experimental`. | M |
| 2.15-3 | Baseline approval: `safeai manifest approve M --by --at [--escalation-owner]` writes `M.approval.json`, bound to the manifest's integrity digest. A scan with `--baseline M` reports the baseline's `approval_state`, and `--require-approval` also fails on an unapproved or self-approved baseline. | S |
| 2.15-4 | Capability-level delegation: Python tool functions (`@function_tool`, `@tool`, CrewAI `BaseTool._run`) get the capabilities detected inside their bodies, and `DELEGATE_EXCEEDS_DELEGATOR` compares capabilities where both sides have them, tool names otherwise. | M |

**Status.** All four items shipped in v2.16.0.
Manifest contract 1.3.0; attestation predicate v0.2. Two new pending
cases (`identity/workload_agent_links`,
`baseline_changes/delegate_capability_covered`; 41 pending in all, every
one holding); the 58-case digests are unchanged.

| # | Not yet |
|---|---|
| 2.15-1 | Agents the inventory parsers name generically (`Agent`) can only be annotated by `agent_id`; workloads outside Kubernetes |
| 2.15-2 | Fetching a CIMD document served elsewhere (never, by design); checking that the declared owner exists |
| 2.15-3 | Signed approval records (approval is unsigned metadata, like exception approvals) |
| 2.15-4 | Capabilities of tools defined in another module than the agent; Claude Code and MCP delegates (their authority is already compared by rule or tool name) |

## v2.16 — IaC Collectors  *(Layer 4)* — **SHIPPED in v2.16.0** (#316)

| # | Item | Size |
|---|---|---|
| 2.16-1 | CloudFormation (YAML with short-form intrinsics, JSON): `AWS::IAM::Role` inline policies, `AWS::IAM::Policy` / `ManagedPolicy` attached by `Ref`; intrinsic values are `partially-resolved` or `unresolved`, never guessed. | M |
| 2.16-2 | Serverless Framework `serverless.yml`: `provider.iam.role.statements` (and the v2 `iamRoleStatements`) as grants of the service role; `${...}` variables are `partially-resolved`. | S |
| 2.16-3 | Helm charts: RBAC and workload templates parsed with every `{{ ... }}` action replaced by a placeholder; fields that contained one are `partially-resolved`, documents that do not parse are counted as unresolved. No rendering, no values merge. | M |

**Exit criteria:** pending cases per collector; Lane B verdicts only.

**Status.** All three collectors shipped in v2.16.0. Three new pending cases (`iac/cloudformation_roles`,
`iac/serverless_roles`, `iac/helm_rbac_templates`; 44 pending in all,
every one holding); the 58-case digests are unchanged.

| # | Not yet |
|---|---|
| 2.16-1 | Nested stacks and `Transform` macros (SAM `Policies` templates); `Fn::If` branches |
| 2.16-2 | Variables resolved from other files (`${file(...)}`) and plugin-defined roles beyond per-function statements |
| 2.16-3 | ServiceAccounts defined in another template of the chart (bindings match within one file, as for plain YAML); SPIFFE registrations inside charts |

## Explicitly out of scope

Everything the v2.8–v2.13 plan excluded stays excluded: runtime
enforcement or monitoring, SVID issuance, live IAM / SPIRE / cluster
queries, Helm rendering or `helm template` execution, LLM analysis in
the scan path, risk scores or tiers, compliance determinations.
