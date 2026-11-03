# Interoperability exports (OCSF, SSF)

SafeAI can write its findings and authority changes in two open formats,
so a SIEM, a data lake or a Shared Signals receiver can use them without
parsing the manifest (plan v2.13; ROADMAP B4, B6).

**File only.** Both exports are files. Community Edition sends nothing,
signs nothing and opens no network connection for them;
`--pr-comment-post` remains its one network path. Delivering the files
is your pipeline's job.

```bash
# during a scan
safeai scan . --baseline baseline.json --manifest safeai-manifest.json \
  --ocsf safeai.ocsf.jsonl --ssf-set safeai.set.jsonl \
  --ssf-issuer https://ci.example.com --ssf-audience https://receiver.example.com

# later, from a manifest whose integrity digest verifies
safeai manifest export safeai-manifest.json --format ocsf -o safeai.ocsf.jsonl
safeai manifest export safeai-manifest.json --format ssf-set -o safeai.set.jsonl
```

Both files are JSON Lines (one record per line, keys sorted). They are
built from the manifest, so paths are repository-relative and the same
manifest always gives the same bytes; `manifest export` refuses a
manifest whose digest does not verify.

| Export | Records | Validated against |
|---|---|---|
| `--ocsf` | OCSF 1.9.0: one **Application Security Posture Finding** (2007) per finding, one **IAM Analysis Finding** (2008) per tool authority change other than `NO_CHANGE` | the published OCSF 1.9.0 class schemas, vendored in [`schemas/ocsf/`](../../schemas/ocsf/README.md) |
| `--ssf-set` | one unsigned SET claims set per `MATERIAL_CHANGE` or `HIGH_RISK_CHANGE` tool authority change | [`schemas/safeai-ssf-set/v0.1.0.json`](../../schemas/safeai-ssf-set/v0.1.0.json), transcribed from RFC 8417, OpenID SSF 1.0 and RFC 9493 (none of them publishes a JSON Schema) |

Details: [OCSF mapping](OCSF.md) ·
[SSF event type (experimental)](ssf-agent-authority-change-v0.1-experimental.md) ·
[reference integration](../../examples/integrations/ocsf-ssf-consumer/README.md).

## What the exports do not claim

- No compliance result: control mappings are not exported as OCSF
  `compliance` objects.
- No risk score: OCSF `risk_*` attributes are not set, and no CAEP
  `risk-level-change` event is emitted.
- No runtime fact: every record restates static repository evidence,
  with the same Lane A / Lane B meaning as the manifest
  (`unmapped.safeai.gateability`, `inferred_only`).
- Delegation, Separation-of-Duties and workload-identity change types are
  not exported yet; they are review-only and stay in the manifest and the
  PR comment.
