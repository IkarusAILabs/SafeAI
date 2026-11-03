# Vendored OCSF schemas

These files are the [Open Cybersecurity Schema Framework](https://schema.ocsf.io)
1.9.0 JSON Schemas for the two classes SafeAI's `--ocsf` export emits,
copied byte for byte as the OCSF schema server publishes them. They are
used only to validate the export offline (`tests/test_interop_exports.py`,
`examples/integrations/ocsf-ssf-consumer/`); SafeAI never fetches them at
run time.

| File | Class | Source (fetched 2026-11-03, server default version 1.9.0) | SHA-256 |
|---|---|---|---|
| `1.9.0/application_security_posture_finding.json` | Application Security Posture Finding (2007) | `https://schema.ocsf.io/schema/classes/application_security_posture_finding?profiles=` | `19f8987cce020a36edfe2872be3b4427031b723e68533c352644dcb18543cdeb` |
| `1.9.0/iam_analysis_finding.json` | IAM Analysis Finding (2008) | `https://schema.ocsf.io/schema/classes/iam_analysis_finding?profiles=` | `4d16cba131673def94dbc8be6adb71e0e193af6e6385354f8a6e9a734000ec97` |

`?profiles=` selects the class with no profile applied. The export sets
`metadata.profiles` to `[]` and claims none (with every profile applied,
the server marks `cloud` and `osint` required, which do not apply to a
repository scan).

The OCSF schema is © OCSF contributors and licensed under the
[Apache License 2.0](https://github.com/ocsf/ocsf-schema/blob/main/LICENSE),
the same license as SafeAI. The digests above are checked by the tests,
so an edit to these files fails CI. To move to a newer OCSF version, add a
new version directory, update `OCSF_VERSION` in `safeai/report/ocsf.py`,
and record the new digests here and in the tests.
