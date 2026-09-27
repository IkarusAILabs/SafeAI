# ADR-0009 — Explicit authority graph for IaC correlation

- Status: accepted
- Date: 2026-09-26
- Context: the first v2.5 implementation correlated broad capability
  families (`s3 -> cloud`) against flat grant lists, matched identities
  by string coincidence, and turned attachments into fake
  `action="attached-policy"` permissions. Review showed this answers
  "does this repo contain a cloud capability and some cloud
  permission" — insufficient for authority intelligence.
- Decision: rebuild correlation on an explicit graph
  (`safeai/iac/model.py`): Identity (kind, name, namespace),
  Grant (per-field resolved/partially-resolved/unresolved),
  GrantBinding (identity → binding → role chains for both Terraform
  attachments and Kubernetes RBAC), AgentIdentityLink (workload
  service-account and explicit config references only — never string
  coincidence), and verdicts carrying agent/identity refs plus
  declared, grant, and link evidence refs. Verdict strictness:
  MATCH needs an evidenced link + compatible resolved semantics;
  EXCESS needs a linked grant strictly beyond need; MISMATCH needs a
  linked identity with authoritatively visible absence (no unresolved
  material, no modules, no unparsed IaC shadowing the provider);
  otherwise UNVERIFIED_LINK (ambiguous) or UNKNOWN (insufficient).
  Unrelated grants are recorded UNKNOWN, never excess; absent grants
  without links are UNKNOWN, never mismatch.
- Alternatives: keep family matching (rejected: false excess and false
  mismatch by construction); resolve identities by name similarity
  (rejected: the precise failure mode under review); infer links from
  tool keys or inventory names (rejected: coincidence is not evidence).
- Consequences: manifest `iac_correlations` moves to schema v2
  (identities, agent_identity_links, grants, grant_bindings, verdicts
  with evidence refs; additive, Contract v1 validates); benchmark
  corpus (`tests/fixtures/iac/benchmark/`) pins the precision
  boundary; Lane-A graduation still requires measured precision per
  ADR-0008 — unit-test pass rates alone never qualify.
