# Authority Evidence Validation — benchmark report

Cases: 37 total, 37 passed, 0 mismatched.

## Corpus metrics (measured, not targets)

- Discovery: precision 1.0, recall 1.0, F1 1.0 (TP 38, FP 0, FN 0)
- Tool recall: 1.0
- Capability recall: 1.0
- Attribution end-to-end (incl. unattributed bucket): 0.4222 (38/90); attributable-only accuracy: 1.0 (38/38)
- False escalation rate: 0.0 (0/0 observed)
- Evidence completeness: 1.0 (52/52)
- Uncertainty expression recall: 1.0 (33/33)
- Determinism: 1.0 (37/37 cases clean)
- Unknown/unresolved observed: 10

## Lane-A graduation (PROPOSED targets, report-only)

Eligible: False
- [PASS] discovery_precision: 1.0 (target 0.95)
- [PASS] discovery_recall: 1.0 (target 0.9)
- [FAIL] attribution_accuracy: 0.4222 (target 0.95)
- [PASS] false_escalation_rate: 0.0 (target 0.05)
- [PASS] evidence_completeness: 1.0 (target 0.95)
- [PASS] determinism: 1.0 (target 1.0)
- Note: Targets are PROPOSED per ADR-0008; no gate consumes this output.
- Note: Unresolved/unknown items veto class-level graduation until resolved or explicitly scoped.

## Cases

### [PASS] access_modes/execute_tool

### [PASS] access_modes/read_only_tool

### [PASS] access_modes/write_tool

### [PASS] adversarial/partial_identity

### [PASS] adversarial/role_name_prefix

### [PASS] adversarial/s3_read_vs_admin

### [PASS] adversarial/substring_trap

### [PASS] baseline_changes/identity_changed

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

### [PASS] unknown/dynamic_tool

### [PASS] unknown/runtime_identity

### [PASS] unknown/unresolved_egress

### [PASS] workflows/langgraph_tools

### [PASS] workflows/n8n_webhook
