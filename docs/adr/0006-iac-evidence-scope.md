# ADR 0006 — v2.5 IaC authority evidence scope

- Status: accepted
- Date: 2026-09-26
- Context: the roadmap promises static declared-versus-granted authority
  correlation, but no IaC parsing exists (only a `CAP_kubernetes`
  import-regex). Terraform HCL has no stdlib parser, and the project's
  stdlib-plus-PyYAML dependency discipline is a non-negotiable.
- Decision: v2.5 ships IaC **evidence collectors**, not an IaC analyzer:
  `safeai/iac/terraform.py` (brace-block scanner → Grant triples) and
  `safeai/iac/k8s.py` (RBAC YAML via PyYAML). Terraform-only plus
  Kubernetes RBAC YAML; CloudFormation/Helm/serverless deferred to v2.6.
  All IaC output is Lane B (review-only): no new gates, no exit-code
  changes. Resolution is per-field (`resolved | partially-resolved |
  unresolved`; ADR-0009): interpolation, modules, dynamic blocks, and
  external payloads degrade the affected fields, never the whole grant
  silently. Wildcards are observed breadth (flagged), not uncertainty.
- Alternatives: add `python-hcl2` dependency (rejected: dependency
  discipline, installer weight, offline guarantee); full HCL evaluation
  (rejected: execution-adjacent, out of static scope); IaC-gated CI in
  v2.5 (rejected: precision unmeasured — see ADR-0008).
- Alternatives: add `python-hcl2` dependency (rejected: dependency
  discipline, installer weight, offline guarantee); full HCL evaluation
  (rejected: execution-adjacent, out of static scope); IaC-gated CI in
  v2.5 (rejected: precision unmeasured — see ADR-0008).
- Consequences: correlation verdicts carry `partially-resolved`
  provenance where the scanner cannot resolve values; benchmark corpus
  (issue #167) measures precision before any gate graduation.
