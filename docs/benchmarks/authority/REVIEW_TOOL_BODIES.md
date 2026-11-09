# Review sheet: expected answers affected by tool-body attribution

Status: **awaiting human review.** Nothing in `tests/benchmarks/` has
been changed. The authority benchmark fails on the 13 cases below until
a reviewer decides each one.

## Why these cases change

SafeAI now reports the shell, file and HTTP calls in the body of a
Python function registered as a tool as that tool's capabilities
(`safeai/analysis/tool_bodies.py`). Before, it reported most of them
as `unknown:unattributed`, or did not report them at all.

These 13 expected answers record that old behaviour. Several of them
say so directly: "known blind spot" (`capabilities/shell_tool`), "the
surface cannot tell which tool does what" (`attribution/similar_tools`),
"surface carries no filesystem capability" (`baseline_changes/read_to_write`).

Most of these answers were marked `migrated_from_legacy`, which means
they were derived from earlier scanner output.

## How to review

For each case:

1. Read the input file and decide what the code does.
2. Compare that with the *Observed now* column, without relying on the
   *Proposed* column.
3. Record **accept**, **reject** or **amend** in *Decision*, with your
   initials.

The proposed revisions were drafted with AI assistance from the case
inputs. They are not labels. Under the credibility protocol a case counts
only once a human has decided it. Its `annotation` should then record the
reviewer and `derivation: independent_annotation`.

## Cases

| Case | What the input does | Expected now | Observed now | Proposed | Decision |
|---|---|---|---|---|---|
| `capabilities/shell_tool` | `deploy` runs `subprocess.run(cmd, shell=True)`; registered with `Tool(name="deploy", func=deploy)` | shell not on the surface ("known blind spot") | `tool:deploy` shell_execution / execute | add `tool:deploy` {shell_execution: execute}; drop blind-spot note | |
| `access_modes/execute_tool` | `maintain` runs a shell command; registered as a tool | no tool entry | `tool:maintain` shell_execution / execute | add `tool:maintain` {shell_execution: execute} | |
| `access_modes/write_tool` | `save_note` opens a file with `"w"` | no tool entry | `tool:save-note` filesystem_access / write | add `tool:save-note` {filesystem_access: write} | |
| `capabilities/file_read_only` | `read_note` opens a file for reading | no tool entry | `tool:read-note` filesystem_access / read | add `tool:read-note` {filesystem_access: read} | |
| `capabilities/network_egress` | `post_report` makes an HTTP POST | no tool entry | `tool:post-report` external_apis / write | add `tool:post-report` {external_apis: write} | |
| `attribution/similar_tools` | `read_note` reads; `write_note` opens with `"w"` | neither attributed ("cannot tell which tool does what") | `tool:read-note` read; `tool:write-note` write | add both; revise note | |
| `attribution/shared_tool` | one `run` function (shell) shared by two CrewAI agents through `Tool(name="run", func=run)` | shell unattributed; uncertainty `unlinked shell_execution` | `tool:run` shell_execution / execute | attribute to `tool:run`; drop the `unlinked` uncertainty | |
| `attribution/delegation_chain` | the worker's `run` tool (`Tool(name="run", func=run)`) runs a shell command; two supervising agents delegate to it | shell unattributed; `UNVERIFIED_LINK` expected | `tool:run` shell_execution / execute | attribute to `tool:run`; reviewer to decide whether the link is still unverified | |
| `delegation/subagent_chain` | same pattern as above | same as above | `tool:run` shell_execution / execute | same as above | |
| `workflows/langgraph_tools` | `ToolNode([shell_run])`; `shell_run` runs `subprocess.run(shell=True)` | shell unattributed | `tool:shell-run` shell_execution / execute | attribute shell to `tool:shell-run`. The unattributed `filesystem_access` here comes from `ChatOpenAI` matching "open" (separate LangGraph parser fix, not in this change) | |
| `baseline_changes/new_tool` | current version adds a `diagnose` tool that runs a shell command | change seen through findings only | `tool:diagnose` shell_execution / execute; MATERIAL_CHANGE on that tool | expect MATERIAL_CHANGE on `tool:diagnose` through the surface channel | |
| `baseline_changes/read_to_write` | `read_note` gains an `open(path, "w")` branch | change seen through findings only ("surface carries no filesystem capability") | `tool:read-note` read → write; MATERIAL_CHANGE | expect MATERIAL_CHANGE on `tool:read-note` through the surface channel | |
| `unknown/unresolved_egress` | `notify` POSTs to a URL read from `NOTIFY_URL` | `DEP_UNDECLARED_CAPABILITY` must fire | `tool:notify` external_apis / write; the rule is silent, because the URL now has a consumer | **reviewer decision.** If "undeclared" means "no tool consumes it", remove the rule from `must_fire`. If the case is meant to test unknown destinations, keep the rule and change the rule instead | |

## Effect on the numbers, if every proposal is accepted

These numbers come from `--no-determinism` and are measured with the
change in place against the *current* expected answers:

- 45 of 58 cases pass;
- capability attribution: 65 of 134 applicable statements resolved.

Once the cases are decided, rerun `python -m safeai.cmd.cli benchmark`,
update the digests in `VALIDATION_REPORT.md`, and regenerate
`evaluation.json` and `brief.md`. Until then the published digests
(`ee76875d…`, `de9cb451…`) describe the scanner before this change.
