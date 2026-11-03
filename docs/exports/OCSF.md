# OCSF export — mapping (OCSF 1.9.0)

`safeai scan --ocsf PATH` and `safeai manifest export M --format ocsf`
write one OCSF event per line. Code: `safeai/report/ocsf.py`. See the
[exports overview](README.md) for what is and is not claimed.

## Common fields

| OCSF attribute | Value |
|---|---|
| `category_uid` | `2` (Findings) |
| `activity_id` | `1` (Create): every export is a fresh snapshot of one scan |
| `type_uid` | `class_uid * 100 + 1` |
| `time` | scan completion time (`scan.completed_at`), milliseconds |
| `metadata.version` | `1.9.0` |
| `metadata.product` | `{name: SafeAI, vendor_name: IkarusAILabs, version}` |
| `metadata.correlation_uid` | the scan ID (all events of one scan share it) |
| `metadata.uid` | SHA-256 of the record's identity (see below) |
| `metadata.profiles` | `[]` — no OCSF profile is claimed |

## Findings → Application Security Posture Finding (2007)

| OCSF attribute | From the manifest finding |
|---|---|
| `finding_info.uid` | `fingerprint` (stable across scans; the baseline and suppression key) |
| `finding_info.title` / `desc`, `message` | `title`, `message` |
| `finding_info.types` | `[rule_id]` |
| `severity_id` | `info` 1, `low` 2, `medium` 3, `high` 4, `critical` 5 |
| `confidence_id` | `low` 1, `medium` 2, `high` 3 (omitted when unknown) |
| `status_id` | `3` (Suppressed) for suppressed findings; otherwise omitted |
| `application` | `{uid: project_id, name}` |
| `resources` | `[{type: file, name: path, uid: path}]`, path repository-relative |
| `remediation.desc` | `remediation` |
| `unmapped.safeai` | `rule_id`, `status` (new / existing / regressed / suppressed), `provenance_class`, `gateability`, `line_start`, `line_end` |

## Tool authority changes → IAM Analysis Finding (2008)

The tool is the analysed principal: OCSF's identity-centric
`permission_analysis_results` describe what it may now do.

| OCSF attribute | From the manifest |
|---|---|
| `finding_info.uid` | SHA-256 of project, tool key, change class and change types (the same change gives the same UID on every scan) |
| `finding_info.title`, `message` | `Authority change on <tool_key>: <change_class>` |
| `finding_info.types` | `change_types` (`AUTHORITY_ADDED`, `AUTHORITY_ESCALATED`, …) |
| `finding_info.desc` | the summaries of the tool's escalations |
| `severity_id` | the higher of the change class (`LOW_CHANGE` 2, `MATERIAL_CHANGE` 3, `HIGH_RISK_CHANGE` 4, `UNKNOWN` 0) and the tool's highest escalation severity |
| `applications` | `[{uid: project_id, name}]` |
| `permission_analysis_results[0].policy` | `{name: tool_key, type: tool kind}` |
| `permission_analysis_results[0].granted_privileges` | the tool's current capabilities as `<capability>:<access_mode>`, from `tool_surface` |
| `unmapped.safeai` | `tool_key`, `change_class`, `change_types`, `status`, `inferred_only`, `escalations[]` (`id`, `severity`, `before`, `after`, `summary`) |

`NO_CHANGE` tools are not exported. Without `--baseline` there are no
authority changes, so only findings are exported.

## Validation

`tests/test_interop_exports.py` validates every event of a real scan
against the vendored class schemas (JSON Schema draft-07, no profiles)
and checks that the vendored files are unmodified. To validate your own
export:

```python
import json, jsonschema
schemas = {2007: "schemas/ocsf/1.9.0/application_security_posture_finding.json",
           2008: "schemas/ocsf/1.9.0/iam_analysis_finding.json"}
for line in open("safeai.ocsf.jsonl", encoding="utf-8"):
    event = json.loads(line)
    schema = json.load(open(schemas[event["class_uid"]], encoding="utf-8"))
    jsonschema.validate(event, schema)
```

## Limits

- OCSF `unmapped` has no stable structure by design; a receiver that
  needs `unmapped.safeai` fields should key on the SafeAI version.
  A dedicated OCSF extension would remove this; none is registered.
- Findings carry their file as a `resources` entry; OCSF's code-location
  structure (`vulnerabilities[].affected_code`) would label every
  finding a vulnerability, which most are not.
