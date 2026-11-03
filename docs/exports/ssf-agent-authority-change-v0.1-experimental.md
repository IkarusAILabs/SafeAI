# SSF event type: agent authority change — v0.1 (experimental)

> **Experimental.** Any field may change in any release until this event
> type is published as stable. Each event carries
> `"event_version": "0.1-experimental"`.

Event type URI (the URL of this page):

```
https://github.com/IkarusAILabs/SafeAI/blob/main/docs/exports/ssf-agent-authority-change-v0.1-experimental.md
```

`safeai scan --ssf-set PATH` and `safeai manifest export M --format
ssf-set` write one [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)
Security Event Token claims set per line, one for each tool authority
change classed `MATERIAL_CHANGE` or `HIGH_RISK_CHANGE`. Code:
`safeai/report/ssf.py`; schema:
[`schemas/safeai-ssf-set/v0.1.0.json`](../../schemas/safeai-ssf-set/v0.1.0.json).

## Why not a CAEP event type

[CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html) defines eight
event types; none describes a repository change that widens what an
agent's tool may do. `risk-level-change` needs a `LOW` / `MEDIUM` / `HIGH`
risk level, which SafeAI does not produce; `token-claims-change` and
`credential-change` describe credentials at run time. Reusing one of
them would assert something the evidence does not show, so the event type
is SafeAI's own. Its body borrows CAEP's common `event_timestamp` and
`reason_admin` members so receivers can display it the same way.

## Claims set

```json
{
  "iss": "urn:safeai:project:<project_id>",
  "aud": "https://receiver.example",
  "iat": 1793719782,
  "jti": "<sha256 of manifest digest + tool key>",
  "txn": "<scan_id>",
  "sub_id": {"format": "opaque", "id": "<project_id>:<tool_key>"},
  "events": {
    "https://github.com/IkarusAILabs/SafeAI/blob/main/docs/exports/ssf-agent-authority-change-v0.1-experimental.md": {
      "event_version": "0.1-experimental",
      "event_timestamp": 1793719782,
      "change_class": "HIGH_RISK_CHANGE",
      "change_types": ["AUTHORITY_ESCALATED"],
      "status": "escalated",
      "inferred_only": false,
      "tool": {"key": "mcp_server:docs", "kind": "mcp_server", "name": "docs", "framework": "mcp"},
      "escalations": [{"id": "ESC_MCP_READ_TO_MUTATE", "severity": "critical",
                       "before": "read", "after": "execute",
                       "summary": "MCP server gained mutating tools (mcp, mcp_tool:run_command)"}],
      "evidence": {"manifest_payload_sha256": "<manifest integrity digest>",
                   "commit_sha": "<commit>"},
      "reason_admin": {"en": "Tool mcp_server:docs: HIGH_RISK_CHANGE (...)"}
    }
  }
}
```

| Claim | Rule |
|---|---|
| `iss` | `--ssf-issuer`, default `urn:safeai:project:<project_id>`. SSF requires it to match the stream's configured issuer, so set it to what your receiver expects |
| `aud` | `--ssf-audience` (repeatable); omitted when not given |
| `iat` | the scan completion time, not the time of writing, so the payload is reproducible. Re-stamp it when signing if your receiver checks freshness |
| `jti` | SHA-256 of the manifest digest and the tool key: unique per scan and tool |
| `txn` | the scan ID, shared by every SET of one scan |
| `sub_id` | RFC 9493 `opaque` subject: project ID and tool key |
| `sub`, `exp` | never present (SSF 1.0) |
| `events` | exactly one member, this event type |
| `evidence.manifest_payload_sha256` | the manifest's integrity digest: a receiver can ask for the manifest and check it with `safeai manifest verify` |
| `inferred_only` | `true` when every changed capability is inferred (Lane B); `--fail-on-authority-change` ignores such changes, and so should an automated receiver |

## Signing and delivery

The file holds claims sets, not JWTs. RFC 8417 requires integrity
protection for any SET in transit: sign each line as a JWS with header
`{"typ": "secevent+jwt", "alg": ...}` with your own key, then deliver it
by push (RFC 8935) or poll (RFC 8936). Both steps are outside Community
Edition.

## Validation

`tests/test_interop_exports.py` validates every payload of a real scan
against `schemas/safeai-ssf-set/v0.1.0.json` and checks that a payload
with `sub`, `exp`, a second event, a missing `sub_id` or a malformed
digest is rejected.
