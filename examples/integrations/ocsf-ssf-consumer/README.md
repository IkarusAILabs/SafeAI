# Reference integration: SafeAI manifest → OCSF / SSF receiver

An Apache-2.0 example of a receiver for SafeAI's file-only exports
(plan 2.13-3; ROADMAP B6), with a fixture and a script that reproduce
its output. It needs Python 3.10+, SafeAI, and `jsonschema` for the
validation step; nothing goes over the network.

| File | Role |
|---|---|
| `fixture/baseline/.mcp.json` | one MCP server, `docs`, with a read-only tool |
| `fixture/current/.mcp.json` | `docs` gains `fetch_page` and `run_command`; a new `shell` server appears |
| `consumer.py` | the receiver: validates both files against the published schemas, checks the manifest digest, joins SETs to OCSF findings, prints a review queue. Standard library plus optional `jsonschema`; does not import SafeAI |
| `reproduce.py` | runs the whole pipeline and compares the queue with `expected/review_queue.json` |
| `expected/review_queue.json` | the queue the fixture must produce |

## Reproduce

```bash
python examples/integrations/ocsf-ssf-consumer/reproduce.py
```

It runs, in a temporary directory:

1. `safeai scan fixture/baseline --manifest baseline.json`
2. `safeai scan fixture/current --baseline baseline.json --manifest manifest.json`
3. `safeai manifest verify manifest.json`
4. `safeai manifest export manifest.json --format ocsf` and
   `--format ssf-set --ssf-audience https://receiver.example`
5. `consumer.validate(...)` against `schemas/ocsf/1.9.0/` and
   `schemas/safeai-ssf-set/v0.1.0.json`
6. `consumer.review_queue(..., manifest_digest=<manifest integrity digest>)`

and prints `reproduced: review queue matches expected/review_queue.json`.
`tests/test_interop_exports.py` runs the same pipeline in CI.

## Result

13 findings (OCSF 2007 events: 2 informational, 9 medium, 2 high) and two
authority changes. Both changes are `HIGH_RISK_CHANGE`, so both become
SETs, and the queue holds:

| Tool | Change | Escalations | Now granted |
|---|---|---|---|
| `mcp_server:docs` | `AUTHORITY_ESCALATED` | `ESC_MCP_READ_TO_MUTATE` (critical) | `mcp:execute`, `mcp_tool:fetch_page:read`, `mcp_tool:run_command:execute`, `mcp_tool:search_docs:read`, `shell:execute` |
| `mcp_server:shell` | `AUTHORITY_ADDED`, `AUTHORITY_ESCALATED` | `ESC_SHELL_ADDED` (critical), `ESC_ACCESS_MODE_INCREASED`, `ESC_MCP_SERVER_ADDED`, `ESC_WRITE_TOOL_ADDED` (high) | `mcp:execute`, `mcp_tool:run_command:execute`, `shell:execute` |

The queue leaves out scan IDs, times, commit and project IDs. Those differ
on every run and machine; the rest is a function of the fixture, so the
expected file holds on any checkout.

## What a receiver should check

- **Schema.** Reject a record that does not validate; the consumer exits 1.
- **Binding.** Each SET carries the manifest's integrity digest. Pass
  the digest you expect (`--manifest-digest`, taken from a manifest that
  `safeai manifest verify` accepted); SETs from any other scan are
  listed under `rejected`, and the consumer exits 1.
- **Lane.** `inferred_only: true` changes are inferred evidence; SafeAI's
  own gate ignores them, and an automated receiver should too.
- **Signature.** In production, sign the SETs in your pipeline and verify
  the JWS before anything else; this example reads unsigned payloads
  from a local file.

The queue is a list for a reviewer. Revoking access or blocking a
deployment on it is the receiver's decision, outside SafeAI's static
evidence boundary.
