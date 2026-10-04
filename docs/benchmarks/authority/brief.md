# Authority Evidence Validation — benchmark report

Status: RESEARCH / NOT LANE-A READY — vetoed by 17 observed unknown/unresolved items

This report measures SafeAI on a fixed offline corpus (56 cases); it is not a claim about arbitrary customer scans. 'Rule-level detection' counts fired rules only. 'Observed false-escalation rate on benchmark corpus' is exactly that — corpus-observed, not universal.

Cases: 56 total, 56 passed, 0 mismatched.

## Discovery (entity P/R/F1 on corpus; n/a = no gold truth)

Entity rows verify harness calibration against reviewed truth: they move only when the scanner or the truth changes, which is their scientific use. They are not product accuracy guarantees.
- Entity agents: precision 1.0, recall 1.0, F1 1.0 (TP 31, FP 0, FN 0)
- Entity tools: precision 1.0, recall 1.0, F1 1.0 (TP 17, FP 0, FN 0)
- Entity capabilities: precision 1.0, recall 1.0, F1 1.0 (TP 121, FP 0, FN 0)
- Entity identities: precision 1.0, recall 1.0, F1 1.0 (TP 22, FP 0, FN 0)
- Entity grants: precision 1.0, recall 1.0, F1 1.0 (TP 17, FP 0, FN 0)
- Entity relationships: precision 1.0, recall 1.0, F1 1.0 (TP 79, FP 0, FN 0)
- Entity statements: precision 1.0, recall 1.0, F1 1.0 (TP 16, FP 0, FN 0)
- Rule-level detection: precision 1.0, recall 1.0, F1 1.0 (TP 59, FP 0, FN 0; rule firing only, not authority discovery)

## Attribution (8 levels, P/R/F1 where gold permits)

- Attribution tool: precision 1.0, recall 1.0, F1 1.0 (TP 17, FP 0, FN 0)
- Attribution capability: precision 1.0, recall 1.0, F1 1.0 (TP 58, FP 0, FN 0)
- Attribution agent: precision 1.0, recall 1.0, F1 1.0 (TP 31, FP 0, FN 0)
- Attribution identity: precision 1.0, recall 1.0, F1 1.0 (TP 24, FP 0, FN 0)
- Attribution grant: precision 1.0, recall 1.0, F1 1.0 (TP 18, FP 0, FN 0)
- Attribution agent_identity: precision 1.0, recall 1.0, F1 1.0 (TP 5, FP 0, FN 0)
- Attribution capability_grant: precision 1.0, recall 1.0, F1 1.0 (TP 16, FP 0, FN 0)
- Attribution end_to_end: precision 1.0, recall 1.0, F1 1.0 (TP 5, FP 0, FN 0)
- End-to-end legacy rate (incl. unattributed bucket): 0.464 (58/125); attributable-only accuracy: 1.0 (58/58)

## ChangeGuard (baseline pairs only)

- Material change: precision 1.0, recall 1.0, F1 1.0 (TP 5, FP 0, FN 0)
- Escalation: precision 1.0, recall 1.0, F1 1.0 (TP 4, FP 0, FN 0)
- Observed false-escalation rate on benchmark corpus: 0.0
- Missed material-change rate: 0.0
- Surface-blind material entries (explicitly out of the surface model, detection via findings/summary): 3

## Evidence

- Evidence completeness: 1.0 (73/73)
- Unknown preservation recall: 1.0 (43/43)
- Determinism: 1.0 (56/56 cases clean)
- Unknown/unresolved observed: 17

## Lane-A graduation (PROPOSED targets, report-only)

- capability_detection: LANE-A CANDIDATE (precision 1.0, recall 1.0; targets P 0.95 R 0.9)
- identity_attribution: LANE-A CANDIDATE (precision 1.0, recall 1.0; targets P 0.95 R 0.9)
- authority_attribution: LANE-B (precision 0.464, recall 0.464; targets P 0.95 R 0.9) — legacy end-to-end rate over all exercised capabilities incl. unattributed bucket (58/125)
- change_detection: LANE-A CANDIDATE (precision 1.0, recall 1.0; targets P 0.95 R 0.9)
- escalation_detection: LANE-A CANDIDATE (precision 1.0, recall 1.0; targets P 0.95 R 0.9) — observed false-escalation rate on benchmark corpus 0.0 (max 0.05)
- Overall: RESEARCH / NOT LANE-A READY — vetoed by 17 observed unknown/unresolved items
- Note: Per-class thresholds are PROPOSED (reused global bars; ADR-0008 ratification required; no gate consumes this).
- Legacy global eligible (reference): None

## Known limitations (weakest measured categories first)

- Watch: attribution_levels/agent
- Watch: attribution_levels/agent_identity
- Primary limitation: agent-to-tool attribution (agent_uses_tool edges beyond the current model; counted, not hidden)
- Secondary limitation: infrastructure identity correlation without tool-scoped need (repo-level links yield UNKNOWN verdicts)
- End-to-end legacy rate 0.464: 67 capabilities sit in unknown:unattributed (code-defined tools).

## Cases

### [PASS] access_modes/execute_tool

### [PASS] access_modes/read_only_tool

### [PASS] access_modes/write_tool

### [PASS] adversarial/partial_identity

### [PASS] adversarial/role_name_prefix

### [PASS] adversarial/s3_read_vs_admin

### [PASS] adversarial/substring_trap

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
