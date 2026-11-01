# SARIF Review Guidance

SARIF makes scanner findings portable across code-hosting and security tools, but a rendered finding still needs context. Reviewers should confirm the affected capability, the source manifest or file, the severity rationale, and whether the finding is new or already covered by an approved baseline.

Use stable rule identifiers so findings can be tracked across runs. Keep the report free of secrets and private prompt content, and configure CI artifacts with an appropriate retention period. A successful upload or a green workflow does not by itself mean that an agent is safe to deploy.

When a finding is accepted as a known limitation, record the reason and an owner rather than deleting the evidence. Revisit exceptions when the agent's tools, data sources, or autonomy change.

## Control references

Each SARIF result lists the control-framework entries its rule maps to in
`properties.controls`, as `framework:control_id` (for example
`owasp_agentic:AGENTIC05` or `blueprint:BP-P2-GOVERNANCE`), and each rule's
`properties.tags` carries the same control IDs so code-scanning views can
filter by them. The JSON report carries the full entries per finding in
`control_mappings`. The mappings are a taxonomy for routing and grouping
findings: they are not a compliance, coverage or conformance claim, and the
`blueprint` entries cite the publicly available Blueprint Alliance reference
architecture without implying membership or endorsement. The KYA manifest
does not carry them, so its digest is unaffected.
