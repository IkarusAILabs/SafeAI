# Authority Evidence Validation — benchmark report

## Executive summary

v2.6 Authority Evidence Validation.
Overall status: RESEARCH / NOT LANE-A READY — vetoed by 17 observed unknown/unresolved items
Lane-A status: RESEARCH / NOT LANE-A READY — vetoed by 17 observed unknown/unresolved items
Major strengths: rule-level detection P/R/F1 1.0; resolvable attribution exact wherever the model reaches; determinism 0.0; evidence completeness 1.0.
Major limitations: end-to-end exercised authority attribution coverage 0.4851 (65/134); 3 surface-blind material changes; 17 observed unknown/unresolved items veto graduation.

This report measures SafeAI on a fixed offline corpus (58 cases: 58 passed, 0 mismatched); it is not a claim about arbitrary customer scans, and benchmark numbers never belong in customer reports. 'Rule-level detection' counts fired rules only. 'Observed false-escalation rate on benchmark corpus' is exactly that — corpus-observed, not universal. Accuracy (resolvable P/R) and coverage (share of applicable expectations resolved) are distinct properties; both are shown everywhere.

## Discovery

Entity rows verify harness calibration against reviewed truth: they move only when the scanner or the truth changes, which is their scientific use. They are not product accuracy guarantees. Coverage here equals recall (detection has no unresolvable marking); the attribution section below is where coverage bites.

| Entity | TP | FP | FN | Precision | Recall | F1 | Coverage |
| --- | --- | --- | --- | --- | --- | --- | --- |
| agents | 32 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| tools | 19 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| capabilities | 134 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| identities | 25 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| grants | 18 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| relationships | 86 | 0 | 0 | 1.0 | 1.0 | 1.0 | 0.9451 |
| statements | 16 | 0 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| rule-level detection (rules only, not authority) | 61 | 0 | 0 | 1.0 | 1.0 | 1.0 | n/a |

## Attribution

Resolvable accuracy is exactness within the model's reach; resolution coverage is share of ALL applicable expectations resolved (unresolved items count in coverage, never as silent passes; contradicted items always fail the case).
- Resolvable tool attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 19, resolvable 19, correctly resolved 19, contradicted 0, unresolved 0; resolution coverage 1.0
- Resolvable capability attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 134, resolvable 65, correctly resolved 65, contradicted 0, unresolved 69; resolution coverage 0.4851
- Resolvable agent attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 32, resolvable 32, correctly resolved 32, contradicted 0, unresolved 0; resolution coverage 1.0
- Resolvable identity attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 25, resolvable 25, correctly resolved 25, contradicted 0, unresolved 0; resolution coverage 1.0
- Resolvable grant attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 18, resolvable 18, correctly resolved 18, contradicted 0, unresolved 0; resolution coverage 1.0
- Resolvable agent_identity attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 5, resolvable 5, correctly resolved 5, contradicted 0, unresolved 0; resolution coverage 1.0
- Resolvable capability_grant attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 16, resolvable 16, correctly resolved 16, contradicted 0, unresolved 0; resolution coverage 1.0
- Resolvable end_to_end attribution: resolvable precision 1.0, resolvable recall 1.0, F1 1.0; applicable 5, resolvable 5, correctly resolved 5, contradicted 0, unresolved 0; resolution coverage 1.0
- End-to-end exercised authority attribution coverage: 0.4851 (65/134 exercised capabilities correctly attributed end to end; 69 unresolved, mostly code-defined tools in unknown:unattributed). This is the blind-spot metric: it must stay visible. Attributable-only accuracy (resolvable subset): 1.0 (65/65).

## ChangeGuard (baseline pairs only)

- Material change: precision 1.0, recall 1.0, F1 1.0 (TP 5, FP 0, FN 0)
- Escalation: precision 1.0, recall 1.0, F1 1.0 (TP 4, FP 0, FN 0)
- False escalation (observed rate on benchmark corpus): 0.0
- Missed material change: 0.0
- Surface-blind cases: 3 (1 of them escalations)

Important:
Surface-blind cases are changes represented in the benchmark truth that the current SafeAI analysis surface does not attempt to evaluate (detection rests on the findings/summary channels instead). A material-change or escalation F1 of 1.0 covers only surface-expected changes; it must never be read as SafeAI detecting every possible authority change.

## Evidence

- Evidence completeness: 1.0 (76/76)
- UNKNOWN recall: 1.0 (44/44; UNKNOWN/UNVERIFIED_LINK/PARTIAL/INFERRED/UNRESOLVED all stay expressed, never downgraded to safe)
- UNVERIFIED handling: UNVERIFIED_LINK verdicts and unlinked pools preserved (see UNKNOWN recall); repo-level links without tool-scoped need stay UNKNOWN, never MATCH.
- Determinism: 0.0 (0/0 cases clean; repeat + order-shuffle; aggregate digest de9cb45150bd39da1ba793cc0b44420f32451e2ffbb474408f792fddb515c64b)
- Unknown/unresolved observed: 17

## Gold provenance

- Total benchmark cases: 58
- Independently annotated cases: 21
- Legacy-migrated cases: 37
- Other derivation types: 0
- Migrated status never passes or fails a case: provenance is transparency, not a score input. Canonical-vs-legacy contradictions fail loudly (gold contradiction) so drift cannot hide.

## Lane-A graduation (PROPOSED targets, report-only)

- capability_detection: LANE-A CANDIDATE (precision 1.0, recall 1.0, coverage 1.0; targets P 0.95 R 0.9 coverage-floor 0.9 PROPOSED)
- identity_attribution: LANE-A CANDIDATE (precision 1.0, recall 1.0, coverage 1.0; targets P 0.95 R 0.9 coverage-floor 0.9 PROPOSED)
- authority_attribution: LANE-B (precision 0.4851, recall 0.4851, coverage 0.4851; targets P 0.95 R 0.9 coverage-floor 0.9 PROPOSED) — legacy end-to-end rate over all exercised capabilities incl. unattributed bucket (65/134) resolution coverage 0.4851 below PROPOSED floor 0.9
- change_detection: LANE-B (precision 1.0, recall 1.0, coverage 0.625; targets P 0.95 R 0.9 coverage-floor 0.9 PROPOSED) — ChangeGuard model coverage 0.625 (5/8 material changes inside the surface model; 3 blind, detection via findings/summary) resolution coverage 0.625 below PROPOSED floor 0.9
- escalation_detection: LANE-B (precision 1.0, recall 1.0, coverage 0.8; targets P 0.95 R 0.9 coverage-floor 0.9 PROPOSED) — observed false-escalation rate on benchmark corpus 0.0 (max 0.05); escalation model coverage 0.8 (4/5 inside the surface model) resolution coverage 0.8 below PROPOSED floor 0.9
- Overall: RESEARCH / NOT LANE-A READY — vetoed by 17 observed unknown/unresolved items
- Note: Per-class thresholds are PROPOSED (reused global bars; ADR-0008 ratification required; no gate consumes this).
- Legacy global eligible (reference): None

## Known limitations (weakest measured categories first)

- Watch: attribution_levels/capability
- Watch: entities/relationships
- Watch: entities/agents
- Primary limitation: agent-to-tool attribution (agent_uses_tool edges beyond the current model; counted, not hidden)
- Secondary limitation: infrastructure identity correlation without tool-scoped need (repo-level links yield UNKNOWN verdicts)
- End-to-end exercised authority attribution coverage 0.4851: 69 capabilities sit in unknown:unattributed (code-defined tools).

## Cases

### [PASS] access_modes/execute_tool

### [PASS] access_modes/read_only_tool

### [PASS] access_modes/write_tool

### [PASS] adversarial/partial_identity

### [PASS] adversarial/role_name_prefix

### [PASS] adversarial/s3_read_vs_admin

### [PASS] adversarial/similar_mcp

### [PASS] adversarial/substring_trap

### [PASS] adversarial/unused_role

### [PASS] attribution/delegation_chain

### [PASS] attribution/factory_tools

### [PASS] attribution/mcp_chain

### [PASS] attribution/multiple_identities

### [PASS] attribution/shared_capability

### [PASS] attribution/shared_tool

### [PASS] attribution/similar_tools

### [PASS] attribution/workflow_chain

### [PASS] baseline_changes/identity_changed

### [PASS] baseline_changes/mcp_server_added

### [PASS] baseline_changes/mcp_tool_widened

### [PASS] baseline_changes/new_tool

### [PASS] baseline_changes/read_to_write

### [PASS] baseline_changes/removed_tool

### [PASS] baseline_changes/wildcard_introduced

### [PASS] capabilities/file_read_only

### [PASS] capabilities/network_egress

### [PASS] capabilities/shell_tool

### [PASS] delegation/subagent_chain

### [PASS] delegation/unknown_delegation

### [PASS] identity/claude_permissions

### [PASS] identity/mcp_server_identity

### [PASS] identity/unattributed_capability

### [PASS] kubernetes/cluster_admin

### [PASS] kubernetes/namespace_confusion

### [PASS] kubernetes/sa_binding

### [PASS] mcp/declared_server

### [PASS] mcp/missing_auth

### [PASS] mcp/multi_server

### [PASS] mixed/full_stack

### [PASS] mixed/minimal_clean

### [PASS] terraform/attachment_chain

### [PASS] terraform/linked_match

### [PASS] terraform/role_inline_policy

### [PASS] terraform/wildcard_unresolved

### [PASS] unknown/ambiguous_identity

### [PASS] unknown/dynamic_policy

### [PASS] unknown/dynamic_tool

### [PASS] unknown/external_policy

### [PASS] unknown/generated_manifest

### [PASS] unknown/mcp_auth_unresolved

### [PASS] unknown/missing_sa_link

### [PASS] unknown/runtime_identity

### [PASS] unknown/tf_module

### [PASS] unknown/tf_variables

### [PASS] unknown/unresolved_egress

### [PASS] unknown/unsupported_framework

### [PASS] workflows/langgraph_tools

### [PASS] workflows/n8n_webhook
