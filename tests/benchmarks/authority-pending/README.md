# Pending authority benchmark cases

Cases here have truth that **no human annotator has reviewed yet**. The
authority corpus (`tests/benchmarks/authority/`) admits only
human-reviewed truth (`annotation.basis: human_reviewed_source`, enforced
by `tests/test_authority_benchmark.py`), so these cases are kept apart.
They are not part of the published measurements or digests.

They still run on every test job: `tests/test_package_manager_authority.py`
runs this corpus through the same harness, and every case must hold.

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
