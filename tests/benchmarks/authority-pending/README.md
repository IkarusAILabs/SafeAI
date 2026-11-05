# Pending authority benchmark cases

Cases here have truth that **no human annotator has reviewed yet**. The
authority corpus (`tests/benchmarks/authority/`) admits only
human-reviewed truth (`annotation.basis: human_reviewed_source`, enforced
by `tests/test_authority_benchmark.py`), so these cases are kept apart.
They are not part of the published measurements or digests.

They still run on every test job: `tests/test_package_manager_authority.py`
runs this corpus through the same harness, and every case must hold.

The identity cases use the harness's `workload_identity` truth section:
each listed key (`assignments`, `unknown`, `callers`, `federations`,
`static_credentials`) is compared as an exact set; a key left out is
not checked.
The optional `workload_states` key compares per-workload `identity_state`
and `unknown_reason` values exactly. Use it when an aggregate `unknown`
set would hide a meaningful distinction, such as a selector that cannot
be evaluated versus a known non-matching registration. These labels are
still AI-assisted pending review; the assertions verify scanner behavior
against candidate truth, not independent human ground truth. Baseline-pair identity cases use `identity_changes`: the
exact set of `(type, workload, subject)` in
`capability_diff.workload_identity_changes`. Delegation cases use
`delegation_edges` (exact set of `framework:name` edges with their
`exceeds` tools, `null` where not evaluated), `delegation_unresolved` (a
count) and `delegation_changes` (exact set of `(type, subject)`).
Separation-of-Duties cases use `sod_conflicts`: the exact set of
`(holder, pair)` in `report.separation_of_duties.conflicts`.
Workload-to-agent link cases (v2.15) use `agent_identity_links`: the
exact set of `(agent_path, id, provenance_class, link)` for identifiers
attributed through a workload (`agent_path` is the agent's first source
file), and `agent_identity_states`: the expected `workload_identity.state`
per agent source file.

To run them by hand:

```bash
python -m safeai benchmark --corpus tests/benchmarks/authority-pending
```

## Promoting a case

1. A human reviewer reads the case input and checks every expected
   tool, capability, access mode, change and rule against it, fixing
   the truth where it is wrong (never the input to fit the scanner).
2. Set `annotation.basis` to `human_reviewed_source` and
   `annotation.derivation` to `independent_annotation`, and replace the
   rationale with the reviewer's.
3. Move the case directory into the same category under
   `tests/benchmarks/authority/`, update the case count in
   `tests/test_authority_benchmark.py`, and record the new digests in
   `docs/benchmarks/authority/VALIDATION_REPORT.md`.

## Cases

| Case | Added | What it checks |
|---|---|---|
| `capabilities/package_manager_install` | v2.9 (E1) | Allowlisted install commands give `package_manager` at write |
| `capabilities/package_manager_publish` | v2.9 (E1) | Allowlisted publish commands give `package_manager` at execute, with a registry credential name |
| `adversarial/package_manager_lookalikes` | v2.9 (E1) | `npm run build`, `npm test`, `pip list`, `go test` and `Write(*.json)` are not dependency authority |
| `access_modes/manifest_write` | v2.9 (E1) | Writes naming a manifest are filesystem writes, not package-manager runs |
| `baseline_changes/install_to_publish` | v2.9 (E1) | Install → publish widens `package_manager` from write to execute: a material change |
| `unknown/caller_supplied_package_command` | v2.9 (E1) | A package-manager subcommand supplied at run time claims no dependency authority |
| `capabilities/package_manager_python_literal` | v2.9 (E1) | A literal `npm install` in a LangGraph tool is `package_manager` at write (detected, unattributed) |
| `unknown/python_variable_command` | v2.9 (E1) | A command held in a variable claims no dependency authority |
| `mcp/package_tool_names` | v2.9 (E1) | MCP tools named `npm_install` / `publish_package` give an inferred `package_manager`; `update_issue` does not |
| `identity/spiffe_template_resolution` | v2.10 (S5) | SPIFFE ID templates render per workload; a generated pod name leaves the ID partially resolved; an unmatched workload stays unknown |
| `identity/spiffe_ambiguous_selector` | v2.10 (S5) | Namespace selectors needing labels not in the repository, or a workload with no namespace, create no identity |
| `identity/spiffe_federation_widening` | v2.10 (S5) | `federatesWith` trust domains are recorded per workload, declared or not |
| `identity/istio_principal_authorization` | v2.10 (S5) | Istio principals become declared callers (SPIFFE assignment or ns/sa convention); `*` is flagged |
| `identity/static_credential_with_spiffe` | v2.10 (S3/S5) | A Secret-sourced token beside a SPIFFE ID fires `IAC_STATIC_CREDENTIAL_WITH_WORKLOAD_IDENTITY`; no ID, no finding |
| `baseline_changes/spiffe_registration_broadened` | v2.10 (S2) | Dropping a podSelector broadens the registration and issues a new identity |
| `baseline_changes/spiffe_federation_added` | v2.10 (S2) | New `federatesWith` domain → `FEDERATION_ADDED` (destinations) |
| `baseline_changes/istio_caller_added` | v2.10 (S2) | A policy newly admits the agent's SPIFFE ID → `CALLER_ADDED` |
| `baseline_changes/static_credential_regression` | v2.10 (S2) | A workload with an ID gains a Secret token → `STATIC_CREDENTIAL_ADDED` (credential) |
| `baseline_changes/spiffe_identity_removed` | v2.10 (S2) | Deleting the registration → `IDENTITY_REMOVED` |
| `baseline_changes/identity_unchanged_reordered` | v2.10 (S2) | Moving and reordering the same configuration reports no change |
| `delegation/openai_handoff_chain` | v2.10 (B2) | Handoffs incl. `handoff()`; a delegate holding a tool its delegator lacks; a factory target stays unresolved |
| `delegation/crewai_delegation` | v2.10 (B2) | `allow_delegation` is one-way; a hierarchical manager delegates to every member |
| `delegation/claude_code_subagents` | v2.10 (B2) | Session → subagents; `exceeds` not evaluated |
| `baseline_changes/delegation_handoff_added` | v2.10 (B2) | New handoff: added, breadth increased, exceeds delegator |
| `baseline_changes/delegation_depth_increased` | v2.10 (B2) | A second hop: depth 1 → 2 |
| `baseline_changes/subagent_tools_widened` | v2.10 (B2) | Subagent gains Bash; another drops its tools restriction |
| `baseline_changes/delegation_file_moved` | v2.10 (B2) | Moving the agents to another file reports no change |
| `separation_of_duties/claude_code_change_and_merge` | v2.10 (B2) | `Edit(src/**)` + `Bash(gh pr merge:*)` on the session |
| `separation_of_duties/mcp_create_and_approve` | v2.10 (B2) | `create_invoice` + `approve_invoice` on one server; different objects do not conflict |
| `separation_of_duties/aws_act_and_erase_audit` | v2.10 (B2) | `s3:PutObject` + `cloudtrail:StopLogging` on one role |
| `separation_of_duties/claude_code_self_grant` | v2.10 (B2) | `Edit(.claude/settings.json)` |
| `separation_of_duties/split_duties_joined_by_handoff` | v2.10 (B2) | Split duties re-joined by a handoff; a split with no handoff stays clean |
| `adversarial/sod_lookalikes` | v2.10 (B2) | Broad grants, unrelated verb pairs and IAM `*` are not SoD conflicts |
