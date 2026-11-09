# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **One parser failure aborted the whole scan.** A JSON file whose top
  level was a list and that mentioned "bedrock" crashed the Bedrock
  Agent parser with `AttributeError`, so the scan wrote no report. Found
  by the C-5 census on a public MCP server repository. The parser now
  skips JSON that is not an object. Any parser error is now recorded as
  a `framework_parsing` diagnostic (`kind: parse_error`), the scan
  continues, and the assurance boundary lists the file as not fully
  analysed. A new test feeds every parser lists, scalars and nulls in
  each file type. Digests unchanged.

- **`safeai scan` on a mistyped path passed as a clean scan.** A path
  that does not exist was created (to hold `.safeai/config.yml`) and
  scanned as an empty project, exit 0: a CI step with a wrong path
  passed its gate. A file path crashed with exit 1. Both now exit 2 with
  `give the project directory to scan`, as `SUPPORT_MATRIX.md` documents.
- **`TOOL_ORPHAN_IMPLEMENTED` was reported for the unattributed bucket.**
  Capabilities SafeAI cannot tie to a tool are not a tool, but were
  reported as an "implemented but undeclared" tool `unknown:unattributed`
  with no evidence. Digests unchanged.
- **Wrong numbers in the README and support matrix:** 20 frameworks (said
  19, and 16 parsers elsewhere), 20 capability categories (said 19), 10
  `GOV_*` rules (said 8), 21 `CAP_*` rules (said 19); the `IAC_*` and
  `SOD_*` rows were missing. `scripts/claims_check.py` now fails CI when
  these drift.

- **AutoGen agents were never inventoried by a real scan.** The AutoGen
  parser was missing from `discover_parsers()`, so it registered only
  when another module happened to import it. `safeai scan` reported no
  AutoGen agents, while pytest workers that had imported the parser for
  another test did report them, which made the pending-corpus test
  depend on test order. The parser is now registered, and
  `tests/test_parser_discovery.py` fails when any
  `safeai/frameworks/<name>/parser.py` is left out. Scans of AutoGen
  code now list AutoGen agents. The 58-case digests are unchanged (no
  published case contains AutoGen code).
- **AutoGen agents are named by their own name.** The parser named every
  agent after its constructor (`AssistantAgent`), so all agents in a
  file collapsed into one. It now uses `name=` or the first positional
  argument when it is a string literal; a name built at run time falls
  back to the constructor name with `name_resolved: false`. The pending
  case `delegation/autogen_teams` now expects its six agents by name.
- **Azure AI Foundry and n8n were reported for files that only mention
  them.** Any YAML file containing "azure" counted as a Foundry agent
  definition (Azure Pipelines and GitHub workflow files, `pnpm-lock.yaml`)
  and added a `cloud_service` capability; any file containing "n8n"
  counted as an n8n project (a `package.json` depending on
  `@n8n/json-schema-to-zod`), with the package name reported as a
  workflow. Foundry YAML now needs the shape of an agent (a top-level
  `tools`, `actions` or `instructions` key; lockfiles are skipped); n8n
  needs a workflow JSON with n8n node types, or Python code naming n8n
  outside comments. Found by the credibility track's target eligibility
  check on three public MCP server repositories. The 58-case digests are
  unchanged and the 44 pending cases hold.

**Credibility track (roadmap C-1 to C-8).** A new roadmap track that
measures SafeAI on code its authors did not write, ahead of new signals.
Plan and pre-registered protocols in
`docs/research/CREDIBILITY_TRACK.md`. Study tooling only, in `scripts/`;
the scanner is unchanged and gains no network path.

- `scripts/label_kit.py`: review packets and sheets for the pending
  corpus (C-1); blind labelling packets for a history study, with
  SafeAI's change class withheld (C-2); Cohen's kappa between two
  sheets; precision, materiality and miss rate with 95% Wilson
  intervals, *insufficient* below 10 labelled units.
- `scripts/history_study.py` (C-2): replays a repository's first-parent
  history through `--baseline` and records every reported change.
  Trees are exported with `git archive`; target code is never run.
- `scripts/incident_replay.py` (C-3): scans the vulnerable revision of
  disclosed advisories from `research/credibility/incidents.yml` and
  reports recall over statically visible incidents; runtime-only
  incidents are counted apart as expected `unknown`.
- `scripts/incident_search.py` (C-3): runs the recorded GitHub Advisory
  Database search and applies written keyword, flaw-class and
  fix-commit screens. Search of 2026-11-07: 7,657 advisories, 726
  keyword matches, **183 candidate incidents** (none verified); every
  match and the screen that excluded it is in
  `research/credibility/incident_screening.json`.
- `scripts/incident_verify.py` (C-3): verification in a pre-registered
  seeded order; one packet per candidate (advisory, fix diff, SafeAI's
  rule catalogue, never SafeAI's output, so expected rules are chosen
  blind) and a sheet per verifier; `apply` writes only what two
  verifiers agree on, or an adjudicator settles, with `verified_by` and
  `verified_on`. `incident_replay.py --check` refuses a verified or
  rejected entry without two named verifiers.
- **Claims ledger (C-8):** `research/credibility/claims.yml` lists 28
  public claims (README, package and repository descriptions, both
  websites) with what backs each; `scripts/claims_check.py` and
  `tests/test_claims_ledger.py` check quotes, counts and named tests.
  `tests/test_scan_offline_runtime.py` checks at run time that a scan
  opens no socket and starts no process, and that the CLI runs only four
  read-only `git` metadata commands.
- **Authority surface census (C-5):** `scripts/census.py` snapshots the
  official MCP registry, draws a seeded sample of 200 eligible
  repositories pinned to a commit, scans them, and keeps only five
  attributes per repository (surface, execute, write-or-broader,
  approval missing, hardcoded credential). It publishes aggregates with
  Wilson intervals, never repository names, and includes a blind human
  check. The frame and sample are committed before any census scan.
- `scripts/claims_check.py --web` fetches the website and checks every
  web quote. The release version is now a counted fact, so a release
  flags a site that still shows the old version.
- History study export works on Windows for paths Windows cannot hold
  (`config /agents.yaml`): `study_common.portable_name`.
- `scripts/target_check.py` (C-2): records each proposed target's
  licence, flags, first-parent commit count and, at the head commit,
  the frameworks, tools and MCP assets SafeAI finds (no findings), and
  suggests a 300-commit range for the owner to pin.
- `research/credibility/`: nine proposed C-2 targets (none confirmed;
  6 eligible by the check of 2026-11-08) with their eligibility facts, the candidate incident registry and its
  screening record.

### Not yet done

- No study has run. C-2 targets await the owner's confirmation and
  pinned ranges; no incident has been verified (each needs two people to
  set its visibility and expected rules); no reviewer has labelled anything.

## [2.16.0] - 2026-11-06

Ships plans v2.14, v2.15 and v2.16 in one release; there is no 2.14.0
or 2.15.0. Manifest contract 1.3.0 (1.2.0 and 1.3.0 together: new
optional sections and fields only). Attestation predicate
`v0.2-experimental`. The 58-case digests are unchanged; eleven new
pending cases (44 in all).

**Change Coverage (plan v2.14).** Every new signal is review-only
(Lane B) and ships with pending benchmark cases; the 58-case digests are
unchanged. Manifest contract 1.2.0 (two new optional sections).

### Added

- Delegation and workload-identity changes in the manifest and the OCSF
  export (plan 2.14-1; ROADMAP B4). The manifest keeps the baseline
  diff's `delegation_changes` and `workload_identity_changes` blocks
  (null without a baseline; schema `v1.2.0.json`), and `--ocsf` /
  `manifest export --format ocsf` write one IAM Analysis Finding (2008)
  per change with `severity_id` 0, because SafeAI gives these changes
  no severity. They never become SSF SETs. Separation-of-Duties
  conflicts were already exported, as findings.
- LangGraph and AutoGen in the delegation graph (plan 2.14-2; ROADMAP
  B2): LangGraph `create_supervisor` (nested, with compiled supervisors
  as members) and swarm `create_handoff_tool`; AutoGen `AssistantAgent`
  handoffs (a name or `Handoff(target=...)`), `RoundRobinGroupChat`,
  `SelectorGroupChat` and `MagenticOneGroupChat` teams, and 0.2
  `GroupChat` with its `GroupChatManager`. Handoff tools are not counted
  as authority; a name that matches no agent in the file is unresolved.
  The existing delegation change types and Separation of Duties apply to
  the new agents.
- Kubernetes Separation of Duties (plan 2.14-3; ROADMAP B2): each
  ServiceAccount is a holder. Creating and approving
  CertificateSigningRequests is `SOD-REQUEST-APPROVE`; `escalate` /
  `bind` on Roles or ClusterRoles, or `impersonate`, is
  `SOD-SELF-GRANT`; a write verb plus deleting Events is
  `SOD-ACT-ERASE-AUDIT`. Wildcard rules and plain RBAC writes name no
  pair.
- Organisation Separation-of-Duties pairs (plan 2.14-3):
  `separation_of_duties.pairs` in `.safeai/config.yml`, each with
  glob patterns for its two halves, checked against every holder
  (`catalogue: organisation`). A malformed catalogue is skipped whole and
  reported in `separation_of_duties.notes`.
- Implementation plan v2.14–v2.16
  (`docs/releases/IMPLEMENTATION_PLAN_V2_14_TO_V2_16.md`).

**Identity & Governance Evidence (plan v2.15).** Manifest contract 1.3.0
(one new optional section, two new optional fields; no value domain
changes). The attestation predicate moves to `v0.2-experimental`.

- Workload-to-agent identity links (plan 2.15-1; ROADMAP S4). A
  Kubernetes workload annotated `ai.safeai.dev/agent: <name or
  agent_id>` attributes the SPIFFE IDs it is issued to that agent as
  `declared` and `repo-iac-observed` (state `corroborated`). A container
  `command` / `args` that starts the one file defining an agent adds the
  `repo-iac-observed` identifier only, so the state stays `unknown`
  without a declaration. Linked identifiers carry `link: {type,
  workload}`. Ambiguous evidence links nothing, and an annotation that
  names no single agent is reported.
- Governance metadata in the attestation (plan 2.15-2; ROADMAP B3).
  `agent_governance` in `.safeai/config.yml` (owner, lifecycle, purpose,
  OAuth Client ID Metadata Document `client_id`) becomes
  `agents[].governance`. When the repository holds the client metadata
  document, its fields are copied with the file as evidence. The URL is
  never fetched and secrets are never copied. Predicate v0.2 adds
  `declared.governance` per agent, `governance.<field>` unknowns, and a
  crosswalk to Blueprint agent-directory fields and CIMD; v0.1
  Statements still verify.
- Baseline approval (plan 2.15-3; ROADMAP P6). `safeai manifest approve
  M --by X [--owner Y]` writes `M.approval.json`, bound to the
  manifest's integrity digest. A scan with `--baseline` reports
  `baseline_approval.state` (`approved`, `self-approved`, `unrecorded`,
  `digest-mismatch`, `unverifiable`); `--require-approval` now also
  fails when the baseline is not approved. `--baseline-approval PATH`
  names a record elsewhere.
- Capability-level delegation (plan 2.15-4; ROADMAP B2). Python tool
  functions and tool classes defined in the agent's file get the
  capabilities detected inside them (`tool_capabilities`). A delegate's
  tool no longer counts as exceeding its delegator when every capability
  detected in it is one the delegator already holds
  (`exceeds_capability_check`). A tool with no detected capability
  still counts.

**IaC Collectors (plan v2.16).** All three are Lane B; grants feed the
existing IaC correlation, verdicts and Separation of Duties.

- CloudFormation (plan 2.16-1): YAML templates (short-form intrinsic
  tags included) and JSON templates. `AWS::IAM::Role` identities
  (`RoleName`, or the logical ID noted `logical-id-name`); grants from
  inline `Policies` and from `AWS::IAM::Policy` / `ManagedPolicy`
  attached through `Roles`; `ManagedPolicyArns` as bindings. Intrinsic
  functions are never evaluated: they degrade the field
  (`intrinsic-function`). `Deny`, `NotAction` and `NotResource`
  statements are not grants. A CloudFormation YAML file with `!Ref` tags
  was previously listed as unparsed.
- Serverless Framework (plan 2.16-2): `provider.iam.role.statements`,
  `provider.iamRoleStatements` and per-function `iamRoleStatements` as
  grants; a string `provider.iam.role` is a binding to an external role.
  `${...}` variables are never resolved (`serverless-variable`).
- Helm (plan 2.16-3): templates under a chart's `templates/` are parsed
  without rendering. Template-only lines are blanked, other actions
  become placeholders, so one expression stays one token; templated
  verbs and resources are unresolved (`helm-template-value`), templated
  names are shown as the expression (`helm-templated-name`), and
  `if` / `range` are not evaluated (`helm-conditional`).

### Not yet done

- Precision for every new signal: the eleven new pending cases, like the
  thirty-three before them, await human review, so all of them stay
  review-only (Lane B).
- JWT-SVID audience changes (the audience is chosen at run time and is
  in no repository file); signing and delivery of attestations, SETs and
  approval records (outside the Community Edition by design).
- The SSF event type and an OCSF extension have not been proposed to
  OpenID SSF or OCSF.
- Collector limits: CloudFormation nested stacks, SAM `Transform`
  policy templates and `Fn::If` branches; Serverless `${file(...)}`;
  a Helm ServiceAccount in another template than its binding; delegation
  agents and tools defined in another module.

## [2.13.0] - 2026-11-03

**Interoperability Exports (plan v2.13).** File only: nothing is signed
or sent, and `--pr-comment-post` stays the one network path. The
manifest contract stays at 1.1.0.

### Added

- OCSF export (plan 2.13-1; ROADMAP B4). `safeai scan --ocsf PATH`
  writes OCSF 1.9.0 events as JSON Lines: one Application Security
  Posture Finding (2007) per finding and one IAM Analysis Finding (2008)
  per tool authority change other than `NO_CHANGE`, with the tool's
  current capabilities as granted privileges. SafeAI-specific fields
  (rule ID, provenance class, gateability, change types, escalations)
  are under `unmapped.safeai`. The published OCSF 1.9.0 class schemas
  are vendored in `schemas/ocsf/` and every event of a real scan is
  validated against them in CI. See `docs/exports/OCSF.md`.
- SSF Security Event Token payloads (plan 2.13-2; ROADMAP B4).
  `safeai scan --ssf-set PATH` writes one unsigned SET claims set
  (RFC 8417, OpenID SSF 1.0) per `MATERIAL_CHANGE` or `HIGH_RISK_CHANGE`
  tool authority change: `opaque` `sub_id`, one event, no `sub` or
  `exp`, the manifest integrity digest as evidence. `--ssf-issuer` and
  `--ssf-audience` set `iss` and `aud`. The event type is SafeAI's own
  and experimental (no CAEP 1.0 event type fits a static authority
  change); see `docs/exports/ssf-agent-authority-change-v0.1-experimental.md`
  and `schemas/safeai-ssf-set/v0.1.0.json`.
- `safeai manifest export M --format ocsf|ssf-set -o PATH` writes either
  export from an existing manifest, after checking its integrity digest.
  Exports are built from the manifest, so the same manifest gives the
  same bytes.
- Apache-2.0 reference integration (plan 2.13-3; ROADMAP B6) in
  `examples/integrations/ocsf-ssf-consumer/`: a receiver that validates
  both exports against the published schemas, rejects SETs bound to
  another manifest and prints a review queue, with a fixture and a
  `reproduce.py` whose output CI compares with the committed result.

### Fixed

- Manifests no longer contain the scanning machine's paths. Tool-surface
  evidence (`tool_surface[].capabilities[].evidence[].path`) held
  absolute paths for MCP and Claude Code configuration files, so every
  manifest exposed the local directory layout and differed between
  checkouts. Models, MCP assets and components are now made
  repository-relative before anything is derived from them, which also
  fixes the JSON report's tool-implementation map and module paths.
- The component diff no longer reports every component as added and
  removed when the baseline is a manifest. Current components were
  compared by absolute path against the relative paths the manifest
  stores. Fingerprints, agent IDs and tool keys are unchanged.

### Not yet done

- Delegation, Separation of Duties and workload-identity change types
  are not exported to OCSF or SSF yet.
- SET payloads are unsigned and nothing delivers them; signing and
  transmission are outside the Community Edition by design.
- The SSF event type is SafeAI's own and experimental, and the
  `unmapped.safeai` OCSF fields are not a registered OCSF extension;
  neither has been proposed to OpenID SSF or OCSF.

## [2.12.0] - 2026-11-03

**Attestation & Accountability (plan v2.12).** There is no 2.11.0:
the v2.11 items shipped in 2.10.0. The manifest contract
moves to 1.1.0: one new optional section and new optional fields, so a
1.0 reader is unaffected.

### Added

- Experimental Agent Authority Attestation (plan 2.12-1; ROADMAP B3,
  Layer 7). `safeai scan --manifest M --experimental-attestation A`
  writes an unsigned in-toto Statement v1 whose subject is the manifest
  file and whose predicate restates each agent's and the repository's
  authority evidence in three separate groups: `machine_derived`,
  `declared` and `unknown` (each unknown field with its reason). The
  manifest records the predicate digest in a new optional
  `authority_attestation` block covered by its integrity digest, and
  `safeai manifest verify M --attestation A` checks manifest integrity,
  the subject digest and the predicate digest. No schema-stability
  promise; see `docs/attestation/agent-authority-v0.1-experimental.md`.
- SPIFFE / WIMSE identity field on agents (plan 2.12-2; ROADMAP S4).
  `agents[].workload_identity` carries identifiers with provenance:
  `declared` (new `agent_identities` list in `.safeai/config.yml`) and,
  beside a declared one, `repo-iac-observed` when the repository's own
  `ClusterSPIFFEID` issues the same ID. States `corroborated`,
  `declared` and `unknown`; an observed ID is never attached to an
  agent that declared nothing. `runtime-unverified` is reserved for
  externally supplied issuance evidence and never emitted.
- Approval metadata on exceptions and suppressions (plan 2.12-3;
  ROADMAP P6). An optional `approval` block (`approved_by`,
  `approved_at`, `escalation_owner`) is validated on load (no future
  date, not after the expiry) and reported with an `approval_state`
  (`approved`, `self-approved`, `unrecorded`) in the JSON report and the
  manifest. New `--require-approval` fails the scan when an active
  exception or an applied suppression has no approval by someone other
  than its owner.
- Manifest schema `schemas/safeai-manifest/v1.1.0.json`; `v1.0.0.json`
  is kept unchanged.

### Fixed

- Reported paths keep the leading dot of dot-files and dot-directories.
  Path normalization used `lstrip("./")`, which removed every leading
  `.` and `/`, so findings, manifest locations, agent source locations
  and SARIF results named `claude/settings.json` for
  `.claude/settings.json`, `mcp.json` for `.mcp.json` and
  `github/workflows/...` for `.github/workflows/...`. Only the display
  changes: fingerprints and agent IDs still hash the old path form, so
  baselines, suppressions and registry history keep matching. Path globs
  in suppressions and policies match either form, so a glob written
  against the old output (`claude/**`) still applies.

### Not yet done

- The attestation is unsigned (sign it as an external step) and does
  not map Blueprint agent-governance or CIMD fields yet.
- An observed SPIFFE ID is attributed to an agent only when it was
  declared for that agent; workload-to-agent linking does not exist yet.
- Approval records cover exceptions and suppressions only.

## [2.10.0] - 2026-11-01

**Workload Identity, Delegation & Separation of Duties.** Ships plan
items 2.10-1 to 2.10-5 and 2.11-1 to 2.11-3 together. Everything new is
Lane B: reported for review, never failing a gate.

### Added

- Static SPIFFE workload identity (ROADMAP S1, plan items 2.10-1 to
  2.10-3). Repository YAML is read for SPIRE controller manager
  `ClusterSPIFFEID` registrations, `ClusterFederatedTrustDomain`, the
  `ControllerManagerConfig` (as a document or inside a ConfigMap) and
  `Namespace` labels. Each workload matched by a registration's pod and
  namespace selectors gets its SPIFFE ID rendered from the template:
  `resolved`, or `partially-resolved` with the placeholder kept when a
  field such as a generated pod name or an out-of-repository trust
  domain is not static. A selector that cannot be decided from the
  repository creates no identity; the workload stays `unknown` with the
  reason. Istio `AuthorizationPolicy` principals are reported as
  declared callers of the workloads they select. All of it is under
  `iac_correlations.workload_identity` (identity kind `spiffe_id`, link
  type `workload-spiffe-id`). SPIFFE links are kept out of grant
  correlation: a SPIFFE ID holds no RBAC or IAM grant.
- `IAC_STATIC_CREDENTIAL_WITH_WORKLOAD_IDENTITY` (low, review-only; S3,
  plan item 2.10-4): a workload that is issued a SPIFFE ID is also
  handed a static credential (Secret-sourced env, `envFrom`, Secret
  volume, or a literal env value with a credential name). Names only;
  no value is read into any output.
- Evidence metric `unknown_workload_identity_rate`, the share of
  workloads whose SPIFFE identity stays unknown (insufficient evidence
  when a scan has no workload manifests).
- Workload-identity change types against a baseline (ROADMAP S2, plan
  item 2.11-3), under `capability_diff.workload_identity_changes`:
  `IDENTITY_ADDED`, `IDENTITY_REMOVED`, `IDENTITY_BROADENED`,
  `CALLER_ADDED` (dimension `identity`), `FEDERATION_ADDED`
  (`destinations`) and `STATIC_CREDENTIAL_ADDED` (`credential`).
- Static delegation graph (ROADMAP B2, plan item 2.11-1) in
  `report.delegation_graph` and the manifest: the Claude Code session
  delegates to each subagent; OpenAI Agents SDK `handoffs=[...]`
  (including `handoff(agent)` and inline `Agent(...)`); CrewAI agents
  with `allow_delegation=True` and hierarchical crew managers. A handoff
  target built at run time is recorded as unresolved, not guessed.
  Delegation change types under `capability_diff.delegation_changes`:
  `DELEGATE_ADDED`, `DELEGATION_BREADTH_INCREASED`,
  `DELEGATION_DEPTH_INCREASED`, `DELEGATE_EXCEEDS_DELEGATOR` (a delegate
  holds a tool its delegator does not, compared by tool name) and
  `SUBAGENT_TOOLS_WIDENED`. Claude Code subagents are never said to
  exceed the session: their tools restrict the session's.
- Separation of Duties (ROADMAP B2, plan item 2.11-2):
  `SOD_CONFLICTING_AUTHORITY` (low, review-only) when one holder can do
  both halves of a conflicting pair: create and approve the same kind of
  transaction, change code and merge it, act and erase the audit trail
  (IAM), or rewrite its own Claude Code permission settings. Holders are
  the Claude Code session and subagents, MCP servers, OpenAI Agents SDK
  and CrewAI agents (with the tools of agents they can hand work to) and
  AWS IAM roles. Only authority that names the operation counts; broad
  grants (`Bash`, `Write(*)`, IAM `*`) do not. Results in
  `report.separation_of_duties` and the manifest.
- The PR comment has "Workload identity changes" and "Delegation
  changes" sections (review-only).
- 86 rules in all (two new: `IAC_STATIC_CREDENTIAL_WITH_WORKLOAD_IDENTITY`,
  `SOD_CONFLICTING_AUTHORITY`).
- Twenty-four pending benchmark cases (five workload identity, six
  identity change, seven delegation, six Separation of Duties) and harness
  truth sections `workload_identity`, `identity_changes`,
  `delegation_edges`, `delegation_unresolved`, `delegation_changes` and
  `sod_conflicts`. Their truth awaits human review (#300).

### Changed

- The manifest's `iac_correlations` block is present for every scan that
  collects IaC evidence and carries `workload_identity` even when empty;
  `delegation_graph` and `separation_of_duties` are new top-level fields.
  A manifest used as `--baseline` then tells "nothing found" from "not
  collected". All additions are optional fields of Manifest Contract
  1.0.0.
- CI runs the test and benchmark jobs in parallel with lint, runs pytest
  with `pytest-xdist`, caches pip and cancels superseded PR runs; the
  duplicate test job in `action-test.yml` is gone (#302).

### Fixed

- Terraform: an inline policy attached with `role = aws_iam_role.X.id`
  now resolves to the role's name, as `.name` already did (for a role,
  `id` is the name in the AWS provider).

### Not yet measured

- Precision for SPIFFE attribution, the identity and delegation change
  types and `SOD_CONFLICTING_AUTHORITY` is measured only on unreviewed
  pending cases (all holding). It is not a published measurement until
  that truth is reviewed (#300); until then every one of them stays
  review-only.

## [2.9.0] - 2026-11-01

**Package-Manager Authority.**

### Added

- Package-manager authority (ROADMAP E1, plan items 2.9-1 to 2.9-5). A
  Claude Code `Bash(...)` allow grant whose command runs a package
  manager (settings, slash-command `allowed-tools`, subagent tools) adds a
  `package_manager` capability on the same tool: `write` for install
  routes (`npm`/`pnpm`/`yarn` install, add or remove, `pip install`,
  `uv add`, `poetry add`, `cargo add`, `go get`) and `execute` for publish
  routes (`npm publish`, `twine upload`, `cargo publish`, `uv publish`,
  `poetry publish`). It fires the new rule `CAP_package_manager`.
  `Write`/`Edit` grants that name a dependency manifest or lockfile
  (`package.json`, `requirements*.txt`, `go.mod`, `Cargo.lock`, …) carry
  it as a target. Broad grants (`Bash`, `Write(*)`, `*.json`) add nothing:
  their shell or filesystem authority is already reported, and reading a
  dependency route into them would be a guess. SafeAI states *that* the
  agent can change dependencies, never whether a package is safe.
- A `dependency` authority dimension listing each tool's dependency routes
  (`npm:install`, `npm:publish`, `manifest:package.json`, …). The
  `credential` dimension is populated for the first time: registry
  credential names (`NPM_TOKEN`, `TWINE_PASSWORD`, …) set in the same
  settings file's `env` block are bound to the package-manager
  capability. Only names are read; values never enter any output. Other
  tools keep `credential: unknown`, now with `values` alongside `state`
  when names are bound.
- `capability_diff.highest_gating_escalation` and a per-tool
  `review_only` flag: what the two diff gates act on.
- Six benchmark cases for E1 in `tests/benchmarks/authority-pending/`.
  Their truth is AI-assisted and awaits human review, so they stay out of
  the human-reviewed corpus, its measurements and its digests; a test runs
  them on every job, and all hold. `tests/benchmarks/authority-pending/README.md`
  says how to promote them.
- Package-manager authority from two more sources (E1 follow-up).
  Literal `subprocess` / `os.system` commands in LangGraph, CrewAI and
  AutoGen source (`subprocess.run(["npm", "install", pkg])`,
  `os.system("npm publish")`) add a detected `package_manager` capability
  and fire `CAP_package_manager`; a command held in a variable adds
  nothing. Like other Python-source capabilities it is unattributed.
  MCP tools whose *name* names a package operation (`npm_install`,
  `add_dependency`, `publish_package`) add an *inferred* `package_manager`
  capability to the server, with no finding. Three more pending
  benchmark cases cover them (nine in all, review in #296); the 58
  reviewed cases keep their outcomes and digests.

### Changed

- `CAP_package_manager` ships in Lane B (ADR-0008): its findings are
  review-only, and a tool change made only of `package_manager` (or
  inferred) evidence is `review_only`, so it never fails
  `--fail-on-authority-change` or `--fail-on-escalation`. Escalations are
  still reported in full; `--fail-on-escalation` now acts on
  `highest_gating_escalation`, which is `highest_escalation` minus
  Lane-B capabilities. This also keeps an upgrade from failing either
  gate against a baseline taken before v2.9, when nothing in the
  repository changed.
- `evidence_metrics.authority_dimensions` gains a `dependency` entry, so
  the unknown authority-dimension rate has one more dimension per tool;
  the existing dimensions' counts are unchanged.
- The MCP tool-name access-mode heuristic counts `install` as a write, so
  `npm_install` is no longer read as a read-only tool.

### Not yet measured

- The precision of `CAP_package_manager` is not published. Its nine
  benchmark cases await human review of their truth (#296); until then
  the rule stays review-only and outside both diff gates.

## [2.8.0] - 2026-11-01

**Evidence Hygiene & Mapping.**

### Added

- Control mappings in the JSON and SARIF output (plan item 2.8-2). Every
  JSON finding carries `control_mappings` (framework, control ID, family,
  title, description); every SARIF result carries `properties.controls`
  as `framework:control_id`, and each SARIF rule tags its control IDs.
  The mappings existed in `safeai/controls/` but reached no output. They
  are added to a copy of the report, so the KYA manifest, its digest and
  the registry record are unchanged. Taxonomy only: no compliance,
  coverage or conformance claim.
- A `blueprint` control framework (plan item 2.8-3, ROADMAP B1): the six
  components of the publicly available Blueprint Alliance reference
  architecture that static authority evidence speaks to (posture
  management, agent directory, agent import, delegation and inheritance,
  permission ceilings and approval, re-attestation against a baseline),
  mapped from MCP, skill, IaC, approval and authority-change rules.
  Runtime components are deliberately absent. Ikarus AI Labs is not an
  Alliance member, and the mapping implies no membership, endorsement or
  conformance.
- A provenance audit over the authority corpus (plan item 2.8-1,
  `tests/test_provenance_audit.py`): every finding, capability and
  per-tool authority statement that a scan of any of the 58 cases emits
  must carry an enum-valid provenance class, an enum-valid gateability
  and a well-formed evidence reference (path and non-negative line). All
  58 cases pass; no detection changed.
- The HTML report's Security Brief shows the v2.7 evidence metrics as an
  *Evidence metrics* card under the KPI row. It reads
  `manifest.summary.evidence_metrics` through the same `summary_lines()`
  the terminal brief uses, so the two cannot word them differently; a
  manifest without metrics shows no card.
  Thanks to [@LetMeSleep8h](https://github.com/LetMeSleep8h) (PR #274).

### Changed

- Access-mode transitions now record their provenance per side. Every
  `access_mode_changes` entry on a capability-diff tool, and every result
  of `escalation.access_changes_for()`, carries `before_inferred` and
  `after_inferred` next to the existing `inferred`. The two new fields
  answer different questions: `before_inferred` is how well the
  *baseline* knew the access mode, `after_inferred` is how well the
  *current* scan knows the one it now reports. A reviewer can now tell
  "the old state was guessed" apart from "the new state is".
  `inferred` itself is unchanged and stays the disjunction ADR-0008
  requires: a verdict may block only when both cited sides carry
  `declared` or `detected` provenance, and inferred authority never
  blocks in any release. Blocking on a "confirmed current, inferred
  baseline" transition is deliberately not enabled, because it would
  fail `--fail-on-authority-change` for every user carrying an older
  baseline as soon as a SafeAI upgrade or a detection refactor improved,
  with nothing about the tool having changed. The detected current state
  is still reported, as its own signal rather than as a change, through
  the `authority` block per-capability `provenance_class`. Gate outcomes,
  severity capping, and exit codes are unchanged.
  Thanks to [@tyza66](https://github.com/tyza66) (PR #257).
- `docs/github-actions-example.md` documents the workflow trust boundary:
  `contents: read` for the minimal scan, the extra `pull-requests: write`
  needed only for `pr-comment-post`, and keeping broad tokens out of
  `extra-args` and the environment.
  Thanks to [@HectorGuerilla](https://github.com/HectorGuerilla) (PR #259).
- `PROVENANCE_CLASSES` and `GATEABILITY_VALUES` are defined once, in
  `safeai/kya/contract.py`; `safeai/kya/enrich.py` re-exports them, so
  existing imports keep working. A test asserts the manifest JSON Schema
  enums equal the contract constants.
  Thanks to [@chiragjangiir](https://github.com/chiragjangiir) (PR #277).
- The per-tool authority dimensions are defined once, as
  `AUTHORITY_DIMENSIONS` in `safeai/kya/contract.py` (plan item 2.8-4);
  `capability_diff` and `evidence_metrics` use it, and a test checks that
  ROADMAP.md names the same list. ROADMAP.md previously listed
  roadmap-only names (`data_reach`, `governance_control`,
  `credential_dependency`, `dependency`) that no output carried. Output
  is unchanged. A `dependency` dimension is deferred to the
  package-manager authority work (E1), when it first carries evidence.
- `docs/github-actions-example.md` installs the published package
  (`SafeAI-Static-Analyzer`) and uses the scan flags the CLI has
  (`--sarif <path>`).
  Thanks to [@yoreva-01](https://github.com/yoreva-01) (PR #270).

### Fixed

- Text files are read and written as UTF-8 regardless of the locale. On
  a non-UTF-8 default locale (for example Windows with a Chinese locale)
  the rule pack failed to decode, the error was swallowed, and scanner
  metadata reported `rule_count: 0`; the JSON and SARIF writers had the
  same latent problem.
  Thanks to [@bfs2021](https://github.com/bfs2021) (PR #269).

- `scan --fail-on-authority-change` / `--fail-on-escalation` /
  `--unknown-authority block` are no longer silent when they cannot fire.
  A baseline carrying neither `tool_surface` nor
  `normalized_capabilities` yields no `capability_diff`, so all three
  passed vacuously with no diagnostic; a warning is now printed to
  stderr naming the gates that cannot fail this run. Exit codes are
  unchanged. `--unknown-authority pass` and `review` cannot fail a run,
  so they are not named.
  Thanks to [@tyza66](https://github.com/tyza66) (PR #258).
- That warning now decides the unknown-authority gate from the
  *effective* policy — a policy file or profile setting
  `authority.unknown: deny` is the same gate as
  `--unknown-authority block`, and only the merged policy says which is
  in force. The check moved from baseline loading to policy evaluation,
  so a `deny` set through `.safeai/policy.yml` or a profile is named
  alongside the flag gates, an explicit `allow`/`require_review` setting
  wins over the flag and is not named, and the warning is labelled by
  whichever source put `deny` in force. Exit codes are unchanged.
  Thanks to [@tyza66](https://github.com/tyza66) (PR #260).

### Tests and documentation

- Every test runs with its own telemetry state directory, so the suite no
  longer reads, writes or removes the real `~/.safeai`.
  Thanks to [@MarioZhang420](https://github.com/MarioZhang420) (PR #287).
- The wheel-build test skips with a named reason when the setuptools
  build backend is unavailable.
  Thanks to [@MarioZhang420](https://github.com/MarioZhang420) (PR #272).
- The good-first-issues index matches the tracker's counts and links.
  Thanks to [@chiragjangiir](https://github.com/chiragjangiir) (PR #276).
- `ROADMAP.md` gains the external developments review (E1–E3, #288);
  `docs/releases/IMPLEMENTATION_PLAN_V2_8_TO_V2_13.md` supersedes the
  v2.7–v2.11 plan (#292).

## [2.7.0] - 2026-10-22

**Evidence Metrology.**

### Added

- Authority evidence metrics (v2.7 Evidence Metrology, ROADMAP Layer 2
  / P0 unknown-rate surfacing): every scan now reports how much of its
  authority picture is evidence-backed, inferred, or unattributed,
  plus evidence completeness, the finding provenance distribution, and
  — when a baseline diff exists — the unknown authority-dimension rate
  (`safeai/analysis/evidence_metrics.py`). Emitted as the optional
  `summary.evidence_metrics` manifest field and as `evidence_metrics`
  in the JSON report; summarised in the security brief coverage
  section. Empty denominators report `insufficient_evidence`, never 0
  or 1. Statement and finding metrics are recomputable from a manifest
  alone. Informational only: no gate, policy, score, or exit code
  consumes them, and no detection changed. Manifest `contract.version`
  stays `1.0.0` (optional field; see `docs/manifest/README.md`).
- `docs/releases/IMPLEMENTATION_PLAN_V2_7_TO_V2_11.md`: versioned
  implementation plan derived from the roadmap.
- ROADMAP external framework alignment: Blueprint Alliance reference
  architecture (B1–B6) and SPIFFE / SPIRE workload identity (S1–S6).

### Changed

- CI: new `authority-benchmark` job (Python 3.11–3.13) runs the full
  authority corpus with determinism checks on every pull request and
  push to `main`; it fails when any case stops holding. Results are
  uploaded as artifacts.
- `docs/benchmarks/authority/VALIDATION_REPORT.md` now documents both
  digests: committed records (`--no-determinism`, `de9cb451…`) and the
  default/CI path with determinism checks (`ee76875d…`).

### Fixed

- `CAP_subprocess_shell` (critical) now fires on multi-line subprocess
  calls such as black/ruff-wrapped `subprocess.run(\n    cmd,
  shell=True, ...)`. The detector matched one source line at a time,
  so `shell=True` on a later line than the call was a silent false
  negative; six authority-benchmark cases
  (`capabilities/shell_tool`, `access_modes/execute_tool`,
  `attribution/{delegation_chain,factory_tools,shared_tool}`,
  `delegation/subagent_chain`) reported `must_fire rule silent`
  against the committed fixtures. An AST pass over `.py` files now
  resolves `import subprocess [as x]` / `from subprocess import ...`
  bindings and reports literal `shell=True` calls at their first line.
  Single-line detections keep their exact line, evidence, and
  fingerprint; non-literal `shell=` values stay unflagged.

## [2.6.0] - 2026-10-04

### Added

- Hardened Authority Evidence Validation benchmark (v2.6, benchmark
  only — no scanner behavior changed): canonical implementation-
  independent gold truth (`truth_schema_version: "2.0"`,
  human-reviewed annotations with `annotation.derivation`) over a 58-case
  corpus (`tests/benchmarks/authority/`); entity discovery P/R/F1 with
  `insufficient_evidence` (never 0/1); 8 attribution levels with
  TP/FP/FN; three-state outcomes (RESOLVED/UNRESOLVED/CONTRADICTED)
  with coverage fields (applicable/resolvable/correct/contradicted/
  unresolved/coverage); material-change and escalation P/R/F1 with
  measured corpus false-escalation and missed-material rates;
  UNKNOWN / UNVERIFIED_LINK / PARTIAL / INFERRED / UNRESOLVED
  preservation checks; per-class Lane-A verdicts (overall RESEARCH /
  NOT LANE-A READY: authority attribution LANE-B at end-to-end 0.4851
  with 69/134 capabilities unattributed, change detection LANE-B at
  model coverage 0.625, escalation detection LANE-B at model coverage
  0.8, plus 17 unknown veto); deterministic digests; 8-area mutation
  tests; gold provenance tracking (21 independent_annotation / 37
  migrated_from_legacy); canonical-vs-legacy consistency checking.
  Measured: 58/58 hold, determinism 58/58, digest
  `de9cb45150bd39da1ba793cc0b44420f32451e2ffbb474408f792fddb515c64b`,
  discovery P/R/F1 1.0, attributable-only 1.0, evidence 1.0, unknown
  preservation 1.0, zero contradicted expectations. Report:
  `docs/benchmarks/authority/`.
- Decision-support HTML reporting backed by a new `security_brief`
  reporting layer (`safeai/report/security_brief.py`): pure
  deterministic scan report → brief transformation (posture, evidence,
  changes, authority, actions, uncertainty, coverage, value) consumed
  by the HTML report. New sections: Security Brief, What SafeAI
  Found, Recommended Review Actions, Capability Changes, Authority
  Review, Evidence Confidence; the assurance boundary moved before
  detailed evidence. Table IDs are now content-derived (deterministic
  renders). No scanner, scoring, or CI behavior changed.

### Fixed

- Release pipeline treats any floating tag (`v2`, `v2.5`, ...) as a
  release-pointer move: the checklist detects the floater and all
  downstream jobs skip neutrally instead of failing red (or worse,
  republishing to PyPI). `check_release.py` floater detection
  generalized from `v2`-only to a version-pattern rule.

## [2.5.0] - 2026-09-27

**IaC Authority Evidence (Lane B).**

### Added — v2.5 IaC Authority Evidence (Lane B)

- Explicit authority graph (`safeai/iac/model.py`, ADR-0009):
  Identity (kind/name/namespace), Grant (per-field
  resolved/partially-resolved/unresolved), GrantBinding chains,
  AgentIdentityLink (workload/config evidence only), and verdicts
  carrying agent, identity, declared, grant, and link evidence refs.
- Terraform relationship extraction: identities, policy statements
  (inline, attached, data-document-inherited), Role → policy →
  statement bindings; attachments are relationships, never fake
  permissions; trust policies excluded; managed/external/module
  content recorded unresolved, never guessed.
- Kubernetes RBAC chains: ServiceAccount → Binding → Role → rule
  with namespace isolation, cluster scope, multi-subject/rule
  support, workload references, and dangling-reference honesty.
- Identity-link resolver: workload `serviceAccountName` and explicit
  config references (role ARNs, identity keys) with file:line
  evidence; string coincidence never links (namespace-aware).
- Semantic matcher: provider/service/operation-class comparison with
  conservative wildcard reasoning; un-normalizable semantics →
  UNKNOWN. Strict verdicts: MATCH (evidenced link + compatible
  resolved grant), EXCESS (linked grant strictly beyond need),
  MISMATCH (authoritatively visible absence only), UNVERIFIED_LINK
  (ambiguous default), UNKNOWN (preferred over false conclusions).
- Orchestrator `collect_iac_evidence()` first-class stage;
  assurance-boundary IaC inspection notes; manifest
  `iac_correlations` schema v2 + summary counts (additive, Contract
  v1 + JSON schema validate verdicts, evidence refs, Lane B);
  PR "Infrastructure authority" Lane-B section inside the 60-line
  cap with control-character sanitization.
- Benchmark corpus (`tests/fixtures/iac/benchmark/catalog.yml`:
  Terraform, Kubernetes, linking, verdict cases) with a
  precision/recall harness, adversarial tests, and invariant
  extensions (IaC never gates; unresolved shadows absence claims).
  Findings `IAC_EXCESS_AUTHORITY` / `IAC_AUTHORITY_MISMATCH` /
  `IAC_UNVERIFIED_LINK` remain `repo-iac-observed` / `review-only`;
  no new gates, no exit-code changes, no new dependencies.

### Added — v2.4.x Security Architecture Hardening

- Release pipeline signs *and* verifies: `cosign verify-blob` against
  the artifact with the expected repository identity and OIDC issuer
  runs before asset preparation; verification failure blocks publish.
  `cosign-release` pinned explicitly to v2.6.1; `tests/test_release_workflow.py`
  statically asserts SHA pins, the verify stage, and fail-closed wiring.
- Governable UNKNOWN authority: policy-file `authority: unknown`
  (`allow | warn | require_review | deny`), `--unknown-authority
  pass|review|block` CLI fallback (explicit file setting wins), and an
  optional `unknown-authority` GitHub Action input. Default behavior
  unchanged: UNKNOWN never fails alone and is never shown as safe.
- Authority dimension block on capability-diff tool entries
  (`capabilities`, `destinations`, `data_scope`, `approval`, `autonomy`,
  `delegation` with per-dimension provenance; `credential`/`identity`
  honestly `unknown`), plus semantic `change_types` derived from
  escalation ids and structural status.
- Manifest evidence: top-level `exception_evaluations` (id, target,
  state, owner, expiry) and `authority_changes` entries plus
  `summary.authority_change_counts` / `summary.highest_change_class`
  (additive; Contract v1 + JSON schema validate the new enums).
- PR comments separate CI-gate escalations from a **Human review**
  Lane-B questions section inside the 60-line cap; data-flow paths
  remain heuristic-labelled and gate-inert.
- Exception model: explicit `target_type` (`finding | policy |
  escalation | authority_change`) + `target_id` with legacy
  `finding_or_policy` back-compat; distinct `scope-mismatch` and
  `invalid` states; review triggers documented as metadata-only.

## [2.4.0] - 2026-09-21

**Agent Authority ChangeGuard precision and evidence hardening.**

### Added — Review decision lanes (WS1)

- Lane A (deterministic gates) vs Lane B (mandatory-review questions):
  `evaluate_policy` publishes canonical outcomes (`pass | warn |
  review-required | block`) mapped from the policy-DSL actions, plus the
  winning `action`, `lane`, per-match lanes, and a `lanes` summary.
  Terminal prints Lane-B matches as review questions; gates print
  verdicts — never blended.
- Review floor: new-or-changed prompt/config-definition findings
  (`PROMPT_*`, `PROMPT_FILE_*`, `SKILL_*`, `TOOL_DEF_*`, `MODEL_CONFIG_*`,
  `WORKFLOW_*`, `CC_*`) resolve to at least `require_review`, never
  `pass` — even with zero other matches.
- Fixed: SafeAI's own manifests failed Contract v1 validation on every
  non-`warn` policy outcome (`deny`/`require_review`/`allow` are not
  contract outcomes). Decisions now publish mapped outcomes, so
  `safeai manifest validate` accepts real scan output.

### Added — Material-change classification and authority gate (WS2)

- Per-tool `change_class` (`NO_CHANGE | LOW_CHANGE | MATERIAL_CHANGE |
  HIGH_RISK_CHANGE | UNKNOWN`, never a score) with `inferred_only`
  tracking, `by_change_class` counts, and `highest_change_class` on the
  capability diff. UNKNOWN (unattributed baselines) never fails a gate.
- New `--fail-on-authority-change material|high-risk` gate (requires
  `--baseline`); inferred-only changes never trip it. Wired through the
  GitHub Action (`fail-on-authority-change` input) and `extra-args`.

### Added — Evidence hardening (WS3)

- Per-finding `provenance_class` (`declared | detected | inferred |
  unknown`) and `gateability` (`deterministic | review-only`) attached
  at normalization, carried in manifests, validated by Contract v1 and
  the manifest JSON schema (optional, backward-compatible enums).
- Registry schema v7 (additive): `scan_findings.provenance_class` and
  `scan_findings.gateability` columns; pre-v2.4 rows read NULL.
- Deterministic report generation covered by double-scan digest test.

### Added — File-backed exception schema (WS4)

- `.safeai/exceptions.yml` records: `exception_id`, `finding_or_policy`,
  scope, named `risk_owner`, `rationale`, `compensating_controls`,
  `expires_at`, `review_trigger`. Expired or stale (nothing live matches)
  exceptions warn on stderr by default; `--strict-exceptions` fails the
  scan (exit 1). Invalid files are hard errors — silent exceptions are
  never permitted.

### Added — Source-to-destination paths in PR output (WS5)

- New-or-regressed `DATAFLOW_*` paths render alongside escalations in
  `--pr-comment` inside the existing 60-line cap, labelled heuristic
  and single-file. No heuristic fails a Lane-A gate on its own.

## [2.3.0] - 2026-09-16

**Plugin SDK and Rule Ecosystem (CE 2.3).**

### Added — CE 2.3 Plugin SDK and Rule Ecosystem

- Analyzer plugin registry (`safeai.analyzers`: `@register_analyzer`,
  `discover_analyzers`, `safeai.analyzers` entry-point group) mirroring
  the parser pattern; built-in run order preserved; third-party
  analyzers run isolated and never fail a scan.
- Per-scan plugin/pack versions: manifest `safeai` block stamps
  `analyzer_versions`, `parser_versions`, and `policy_profile`;
  registry `scans` row carries `plugin_versions_json` (schema v6,
  additive migration); portable imports record NULL for pre-v2.3 exports.
- Pack lifecycle: `registry export` carries pack pins per project,
  `registry import --dry-run` warns on pin drift (advisory, never a gate).
- Lockfile-style component integrity: `registry components --lockfile`
  writes pinned `{type, name, path, content_hash}` pins,
  `--check-lockfile` exits 1 on added/removed/changed components.
- Rule-authoring scaffold: `safeai init` writes `pack_example.yaml`,
  `fixtures/` safe/risky examples, and `tests/test_pack.py`; new
  `safeai rules check [dir]` validates rules and runs expected-findings
  fixtures offline (pack rules act as overrides of built-in rule IDs).
- Community pack contract (`docs/guides/COMMUNITY_PACKS.md`): layout,
  fixture requirements, compatibility policy, pinning, sharing.
- ADR 0005: no `integrations` command namespace yet —
  `--pr-comment-post` stays the single explicit network path.

### Added

- `safeai scan --digest-file PATH` (with `--manifest`) writes a detached sidecar
  `<canonical-sha256>  <manifest-basename>` for independent-channel checks in CI.
  The digest equals the one `safeai manifest verify` reports; the sidecar is
  intentionally not `sha256sum -c` compatible.
  Thanks to [@burakeyler](https://github.com/burakeyler) (PR #148).
- OpenClaw (`.openclaw/` JSON/YAML, root `.openclaw.yaml`) and GitHub Copilot
  (`.github/copilot-instructions.md`, `.copilot/instructions.md`, `.copilot/*.yml`)
  config-file adapters with structured-first parsing, free-text fallback,
  capability scanning, and MCP server references.
  Thanks to [@YaoSong808](https://github.com/YaoSong808) (PR #159).
- Benchmark corpus expanded to 21 fixtures: new `benign-static-subprocess-limitation`
  documents the static-argument precision gap (`CAP_shell:high` fires on safe
  `subprocess.run(["git", "--version"])`).
  Thanks to [@Teachmeplaycode](https://github.com/Teachmeplaycode) (PR #174).
- Policy profile name displayed in terminal and HTML reports alongside policy
  outcome; profile omitted when absent; HTML-escaped to prevent injection.
  Thanks to [@nikitajos7](https://github.com/nikitajos7) (PR #175).

## [2.2.1] - 2026-09-12

**Release-evidence integrity + offline-boundary clarity.**

### Fixed — Release asset scoping
- Release automation uploads only artifacts built for the running tag;
  historical SBOM/provenance can no longer leak into a release.
- New `scripts/verify_release_assets.py` gate fails the release on foreign
  versions, unversioned `provenance.json`, missing Cosign sidecars, or
  SHA256SUMS mismatches; SLSA provenance is version-named.
- Removed committed historical release evidence from `release-artifacts/`
  (generated evidence lives on GitHub Releases, not in-repo).

### Changed — Offline boundary
- Promise sharpened: "Offline and source-private by default. Network
  activity occurs only through explicitly enabled integration commands
  (currently only `--pr-comment-post`)."
- `--pr-comment-post` announces itself on stderr before requesting and
  documents token scope (`pull-requests: write`) and transmitted data
  (rendered redacted comment only) in `docs/guides/REPORTING_GUIDE.md`.

## [2.2.0] - 2026-09-12

**Contract & Proof.** Governance, trust, evidence, and developer-confidence
release: a versioned KYA manifest contract, offline integrity, structured
escalation remediation, a reproducible benchmark corpus, and public
Community/Corporate governance clarity. Offline, static, and backward
compatible throughout.

### Added — Manifest Contract v1
- Published JSON Schema `schemas/safeai-manifest/v1.0.0.json` plus
  `docs/manifest/{README,COMPATIBILITY,EXAMPLES}.md`.
- `contract{}` block on every manifest; `safeai manifest validate` (stdlib-only).

### Added — Offline Manifest Integrity
- Canonical SHA-256 digest on manifests and registry exports;
  `safeai manifest verify`; `registry import --require-integrity`
  (default off); GPG-envelope docs (`docs/manifest/INTEGRITY.md`).

### Added — Escalation Remediation
- Structured remediation for all 14 `ESC_*` rules, rendered in JSON,
  manifest, HTML, terminal, PR comment, and scorecard.

### Added — Benchmarks
- 20-fixture corpus (`benchmarks/catalog.yml`), offline runner
  (`scripts/run_benchmarks.py`), published results (`BENCHMARKS.md`).

### Added — Governance
- `DCO.md` with CI sign-off check; `docs/GOVERNANCE_AND_EDITIONS.md`;
  MCP scope/export-privacy policy; ADRs 0001–0004; re-baselined `ROADMAP.md`.

## [2.1.2] - 2026-09-09

**Cosign signing for OpenSSF Scorecard.** Adds keyless Cosign signatures to
release artifacts to satisfy the Signed-Releases check.

### Added
- Cosign keyless signing of wheel and tarball artifacts in release workflow.

## [2.1.1] - 2026-09-09

**PyPI release fix.** Version 2.1.0 was already published; bumped to 2.1.1.

### Fixed
- Release pipeline: PyPI publish step now uses trusted publishing (OIDC).
- Release pipeline: artifact paths corrected for downloaded attestations.
- Release pipeline: GitHub release created before artifact upload.

## [2.1.0] - 2026-09-09

**CI/CD Hardening & Developer Experience.** Makes SafeAI a true CI gate with
rich developer feedback, brings governance into the IDE, and makes installation
trivial with standalone binaries.

### Added — Quality Gates
- **`--fail-on-rule`** — fail when any finding matches a rule ID pattern
  (glob-style: `GOV_*`, `MCP_*`, `ESC_*`, etc.).
- **`--fail-on-category`** — fail when any finding belongs to a category
  (security, governance, capability, dataflow, prompt, mcp, dependency).

### Added — PR Decoration Auto-Posting
- **`--pr-comment-post`** — post or update the PR comment on GitHub via the
  GitHub API. Uses marker to find and update existing comments.
- GitHub Action input `pr-comment-post` added.

### Added — Extended MCP Tool-Poisoning Detection
- **`MCP_TOOL_SCHEMA_INJECTION`** — detects hidden instructions in input_schema
  property descriptions, titles, and default values.
- **`MCP_RESOURCE_DESCRIPTION_INJECTION`** — detects hidden instructions in MCP
  resource descriptions.

### Added — Standalone Binaries
- PyInstaller spec file and build script for creating standalone binaries.
- No Python installation required for end users.

### Added — VS Code Extension MVP
- Workspace scan and file scan commands.
- Inline diagnostics (problem markers) for findings.

### Added — Test Coverage
- Golden fixtures for 7 new adapters: azure_foundry, bedrock_agent, dify,
  haystack, langchain, mastra, microsoft_agent.
- `TestFixtureCoverageCompleteness` test prevents silent coverage regression.

### Fixed
- **Issue #93** — Claude Code permission precedence correctly implements
  `deny > ask > allow`.
- **Issue #120** — SUPPORT_MATRIX.md now consistent with code.
- **Issue #121** — Fixture coverage completeness check added to release CI.
- **Issue #15** — Trust score category weights differentiated.

### Changed
- Version bumped to 2.1.0.
- 780 tests passing (up from 751 in v2.0.1).

## [2.0.1] - 2026-09-03

**Release hardening.** Consolidated release pipeline with mandatory
verification gates, GPG-signed artifacts, cross-platform verification
instructions, and pre-release checklist.

### Added

- **Consolidated release pipeline** (`.github/workflows/release.yml`) —
  6-job pipeline: checklist → build → attest → sign → publish → release.
  Every gate must pass before the next starts. Builds are pinned to the
  exact release commit SHA.
- **Pre-release checklist** — blocks publication if version string, rules,
  analyzers, compatibility tests, SARIF output, JSON report, Action I/O
  contract, failure-class matrix, or CHANGELOG entry is inconsistent.
- **GPG-signed release artifacts** — wheel, sdist, checksums, provenance,
  and SBOM are all GPG-signed with detached `.asc` signatures.
- **Cross-platform verification instructions** (`VERIFICATION.md`) —
  step-by-step GPG, checksum, and provenance verification for Linux,
  macOS, and Windows (PowerShell). Includes pip hash-checking.
- **Compatibility test suite** (`tests/test_compatibility.py`) — 36 tests
  covering golden fixtures (7 frameworks), JSON/SARIF/CLI/Action contracts,
  and adapter contract (detect/parse for all 17 parsers).
- **Golden fixtures** for Google ADK, OpenAI Agents, Semantic Kernel.
- **Release channels documentation** (`RELEASE_CHANNELS.md`).
- **Security policy** (`SECURITY.md`) with vulnerability reporting and
  response targets.
- **Support matrix** (`SUPPORT_MATRIX.md`) — Python versions, platforms,
  adapters, CI, Action I/O, exit codes, rule coverage.

### Changed

- Version bumped to 2.0.1.
- 731 tests passing (up from 695 in v2.0.0).

## [2.0.0] - 2026-09-03

**Governance Depth & Ecosystem Expansion.** Deepens governance detection with
runaway-loop and recursion-guard rules, adds Windsurf config-file adapter,
and presents governance gaps as a failure-class coverage matrix.

### Added — Runaway-loop / recursion-guard detection

- Two new `GOV_*` rules: `GOV_MAX_ITERATIONS_MISSING` (detects agent loops
  with no max-iteration bound — `while True`, recursive calls without depth
  limit) and `GOV_RECURSION_GUARD_MISSING` (detects recursive tool calls
  without a recursion depth guard).
- Both rules slot into the existing `GovernanceAnalyzer` with per-tool dedup
  and ±10-line source confirmation.
- Mapped to OWASP LLM06, OWASP Agentic AGENTIC08, and NIST AI RMF MANAGE_1.
- Severity: `high` for unbounded loops, `medium` for missing recursion guards.

### Added — Failure-class coverage matrix

- New `failure_class_matrix` section in HTML report and JSON output groups
  `GOV_*` findings by the class of failure they leave the agent unprepared
  for: dependency timeout, dependency unavailable, resource exhaustion,
  cascading failure, unbounded recursion, missing accountability.
- Shifts operator question from "which rules fired?" to "which failure modes
  can this agent survive?"
- Source: Reddit community feedback (2026-09).

### Added — Windsurf config-file adapter

- Framework adapter for `.windsurfrules` (Windsurf IDE config file).
- JSON/YAML/free-text structured-first parsing, capability keyword scanning,
  tool/model extraction, unrestricted grant detection, MCP reference detection.
- 13 tests covering detection, parsing, and integration.

### Added — Evidence type schema (v1.3)

- `evidence_type` field on every finding: `static-config` (parsed fields),
  `static-pattern` (regex matches), or `runtime-observed` (reserved, nothing
  emits it today). KYA manifest bumped to v1.3.

### Changed

- Governance analyzer now checks 10 controls (up from 8): added
  `max_iterations` and `recursion_guard`.
- 695 tests passing (up from 675 in v1.9.1).

## [1.9.1] - 2026-08-30

Post-release fixes for v1.9.0.

### Fixed

- **AGENTIC04 mojibake** — removed CJK fragment from English description in
  `safeai/controls/catalogs.py`.
- **Scoped governance source suppression** — suppression now scoped to tool
  line ±10 window, avoiding masking missing controls in poly-tool modules.
- **Removed unused regex patterns** — `_TOOL_TIMEOUT_RE`, `_TOOL_RETRY_RE`,
  `FUNCTION_PARAM_RE` cleaned up from `safeai/analyzers/governance/analyzer.py`.
- **Hardened LangGraph detection** — `detect()` now requires an import or
  `StateGraph(` call, not a bare substring match.
- **Browser rule enrichment** — added `CAP_browser_playwright`,
  `CAP_browser_selenium`, `CAP_browser_use` to `RULE_MAPPINGS` in
  `safeai/controls/mappings.py`.

### Community contributors

Thank you to the following community members for their contributions to
SafeAI v1.9.1:

- **[@i-safonoff](https://github.com/i-safonoff)** — filled missing entries
  in RULES_REFERENCE.md (PR [#108](https://github.com/ikaruscareer/SafeAI/pull/108))
  and fixed dataflow rule ID casing mismatch (PR
  [#109](https://github.com/ikaruscareer/SafeAI/pull/109)).
- **[@Solarthis](https://github.com/Solarthis)** — added MCP tool
  description injection detection (PR
  [#107](https://github.com/ikaruscareer/SafeAI/pull/107)).
- **[@ARAVIND281](https://github.com/ARAVIND281)** — implemented
  interprocedural data-flow tracking within a single file (PR
  [#110](https://github.com/ikaruscareer/SafeAI/pull/110)) and resolved
  Claude Code permission evaluation order (PR
  [#111](https://github.com/ikaruscareer/SafeAI/pull/111)).
- **[@hadbiaghiles](https://github.com/hadbiaghiles)** — added AutoGen
  to supported frameworks documentation (PR
  [#98](https://github.com/ikaruscareer/SafeAI/pull/98)).
- **[@mikemikimike](https://github.com/mikemikimike)** — added adapter
  negative detection tests (PR
  [#90](https://github.com/ikaruscareer/SafeAI/pull/90)).
- **[@asarakhatun17-lgtm](https://github.com/asarakhatun17-lgtm)** —
  fixed supported frameworks consistency (PR
  [#91](https://github.com/ikaruscareer/SafeAI/pull/91)).
- **[@mah](https://github.com/mahirhir)** — documented Claude Code deep
  analysis fixtures and detection approach (PR
  [#92](https://github.com/ikaruscareer/SafeAI/pull/92)).

## [1.9.0] - 2026-08-28

**Curated theme — "Component Depth & Ecosystem Foundations."** Carries the
remaining depth items not in v1.8.0: CE 1.6 component-record depth, CE 1.4/1.5
governance and data-flow leftovers, and CE 2.0 ecosystem foundations.

### Added — Component version/hash (WS1)

- Component `content_hash` (SHA-256, truncated to 16 chars) stored in the KYA
  registry's `component_snapshots` table (schema v5).
- `safeai registry components` CLI lists tracked components with deduplication,
  type filtering, and consuming-agent resolution.
- Hash-based `_has_changed()` in `component_diff` replaces data-equality checks.

### Added — `safeai init` + custom rule scaffold (WS2)

- `safeai init [--profile NAME] [--force]` scaffolds `.safeai/` with `config.yml`,
  `policy.yml`, `suppressions.yml`, and `rules/example_rules.yaml`.
- Identity-preserving init: existing `local_project_uuid` and `project_id` are
  never overwritten.
- `load_rules()` auto-discovers `.safeai/rules/` with validation and metadata.

### Added — Governance signal detection (WS3)

- `GovernanceAnalyzer` detects missing operational governance controls:
  timeout, retry, approval (HITL), audit logging, rate limiting, circuit breaker
  pattern, backpressure/concurrency limits, and health check/readiness probes.
- Eight rules: `GOV_TIMEOUT_MISSING`, `GOV_RETRY_MISSING`,
  `GOV_APPROVAL_MISSING`, `GOV_AUDIT_MISSING`, `GOV_RATE_LIMIT_MISSING`,
  `GOV_CIRCUIT_BREAKER_MISSING`, `GOV_BACKPRESSURE_MISSING`,
  `GOV_HEALTH_CHECK_MISSING`.
- Findings carry `risk_category: "Governance"` for scoring and reporting.
- Per-tool deduplication: same tool missing the same control produces one finding.
- Source-level confirmation scoped to tool definition ±10 lines to reduce
  false positives from poly-tool modules.

### Added — Control mappings taxonomy (WS4)

- Structured mapping layer between SafeAI rules and external control
  frameworks: OWASP Top 10 for LLM Applications (2025), OWASP Top 10 for
  Agentic Applications (2025), and NIST AI RMF 1.0.
- `map_rule_to_controls()` and `map_findings_to_controls()` API for
  framework-based filtering and grouping.
- Taxonomy only — never a compliance or coverage claim.

### Added — Adapter completion (WS5)

- AutoGen framework adapter for Microsoft AutoGen multi-agent systems.
  Detection tightened: requires import, class usage, or `register_for_llm`/
  `register_for_exec` — no bare substring match.
- LangGraph parser now detects `add_conditional_edges()` calls; detection
  tightened to require `StateGraph` — no loose `Graph(` match.
- Browser automation rules split: `CAP_browser_playwright`,
  `CAP_browser_selenium`, `CAP_browser_use`.

### Added — Heuristic data-flow depth (WS6)

- `DataFlowAnalyzer` tracks untrusted input propagation into sensitive sinks
  (prompts, tool calls, shell, file writes, HTTP requests, database queries).
- Six new rules: `DATAFLOW_prompt`, `DATAFLOW_tool_call`, `DATAFLOW_shell`,
  `DATAFLOW_file_write`, `DATAFLOW_http_request`, `DATAFLOW_database`.
- Placeholder-aware confidence: variables starting with `test_`, `example_`,
  `dummy_`, `mock_`, `fake_`, `sample_`, `fixture_`, `stub_`, `temp_`, `tmp_`
  are skipped as likely test fixtures.
- `.py`-only file filter eliminates false positives on JSON/YAML configs.

### Fixes (post-review)

- **Governance deduplication** — changed from per-rule-id to per-tool
  `(path, tool_name, rule_id)` granularity; same tool not duplicated.
- **AutoGen detection tightened** — removed loose `"autogen" in content.lower()`
  substring match; now requires import, class usage, or registration pattern.
- **LangGraph detection tightened** — removed loose `Graph(` match that
  false-positived on `networkx.Graph`.
- **DataFlow `.py`-only filter** — non-Python files (JSON, YAML configs) no
  longer produce data-flow false positives.
- **Governance source confirmation scoped** — `_find_governance_controls` now
  checks only within ±10 lines of the tool definition, not the entire file.
- **Orchestrator null guard** — `parse_frameworks` skips `None` returns from
  framework parsers.
- **Mojibake fixed** — removed CJK fragment from `AGENTIC04` description.

### Community contributors

Thank you to the following community members for their contributions to
SafeAI v1.9.0:

- **[@Aming9303](https://github.com/Aming9303)** — `safeai registry components`
  CLI (PR [#82](https://github.com/ikaruscareer/SafeAI/pull/82)) and
  `safeai init` command (PR [#83](https://github.com/ikaruscareer/SafeAI/pull/83)).
- **[@D05TL3](https://github.com/D05TL3)** — GitHub Actions scanning example
  (PR [#84](https://github.com/ikaruscareer/SafeAI/pull/84)).

## [1.7.0] - 2026-08-16

### Added — Multi-source MCP discovery

- IDE-scoped MCP config discovery for Cursor (`.cursor/mcp.json`), Windsurf
  (`.windsurf/mcp.json`), and VS Code (`.vscode/mcp.json`). Out-of-repo scopes
  are behind an explicit `--mcp-ide-scopes` flag and excluded from exports by
  default, preserving the source-private guarantee.

### Added — Named policy profiles

- Five built-in profiles: `developer`, `strict-ci`, `mcp`, `rag`,
  `production-agent`. Each profile is a composable set of policy rules that
  extends (not replaces) the user's `.safeai/policy.yml`.
- `--policy-profile NAME` loads the preset profile plus user overrides.
- Profiles documented in `POLICY.md`.

### Added — Registry freshness indicators

- Agent records now track `last_scan_timestamp` and `scan_count` in the local
  SQLite registry.
- `safeai registry list` surfaces freshness status (fresh / stale / never
  scanned).
- HTML report includes freshness indicators per agent.

### Added — Suppression CI failure

- `--strict-suppressions` fails the scan (exit 1) when expired or moved
  suppressions are detected, enabling CI enforcement of suppression hygiene.
- Expired suppressions already produce warnings; this flag promotes them to
  failures.

### Added — Component registry persistence

- Component snapshots (type, name, path, source, line, and full data JSON) are
  now stored in the local KYA registry in a new schema-v3 `component_snapshots`
  table, alongside agent and tool records, with `first_seen_scan` /
  `last_seen_scan` provenance. (Component *version/hash* columns are deferred;
  the schema records identity and last-seen, not an integrity hash yet.)
- Internal query `get_component_agents` resolves which agents reference a
  given component (via scan co-occurrence); surfaced in `component_diff` output
  and intended for a future `safeai registry components` view (not yet exposed
  as a standalone subcommand).

### Added — Component-change diffs

- When a scan detects a changed, added, or removed component (MCP configuration,
  skill, prompt, tool definition, or model config), the consuming agents are
  flagged via the `component_diff` section in the JSON report and HTML output.
  The diff is computed against the baseline scan; with no baseline, all current
  components are reported as newly added.

### Added — Framework compatibility test fixtures (community)

- LangGraph detection validation test and representative fixture (`tests/test_langgraph_framework.py`, `tests/fixtures/langgraph/representative/graph.py`). [#63]
- LlamaIndex detection validation test and representative fixture (`tests/test_llamaindex_framework.py`, `tests/fixtures/llamaindex/representative/agent.py`). [#61]
- CrewAI detection validation test and representative fixture (`tests/test_crewai_framework.py`, `tests/fixtures/crewai/representative/crew.py`). [#62]
- Claude Code project compatibility test and fixture (`tests/test_claude_code_deep.py`, `tests/fixtures/claude_code/compatibility/`). [#59]

Thanks to @adnqcr7-code for these contributions.

### Changed

- Version bumped to `1.7.0`.

## [1.8.0] - 2026-08-23

**Curated theme — "True Authority & Complete Lifecycle."** This release bundles
the remaining CE 1.4, CE 1.5, and CE 1.8 gaps into four cohesive workstreams
and is the gate for starting CE 2.0.

### Shipped — Workstream 1: Lifecycle & Ownership (CE 1.4 completion)

- **Finding Lifecycle Event Engine** — `finding_lifecycle` table (registry
  schema v4) tracking state transitions on existing fingerprints: `introduced` →
  `persisting` → `resolved` → `reopened`. `ESC_RECURRING_RISK` escalation rule
  fires when a previously resolved finding is reintroduced.
- **Stale Suppression Guard** — `detect_stale_suppressions()` in
  `safeai/kya/suppressions.py` compares a suppression's fingerprint against the
  current AST/location; `--strict-suppressions` fails when a waiver exists but
  the underlying code has materially shifted.
- **Agent Enrichment Schema** — `safeai registry metadata set <agent_id>
  --owner "platform-sec" --env "production"` stored in a dedicated
  `agent_metadata` table, decoupled from automated scan snapshots and rendered in
  the HTML report.

### Shipped — Workstream 2: Code-Level Authority (CE 1.5 completion)

- **Tool ↔ Implementation Mapping** — a correlator in `safeai/analysis/` that
  bridges `tool_def` findings with skill/capabilities and surfaces orphan states
  in reports with full declaration/implementation provenance (path, line, source).
- **Command-Aware MCP Resolution** — extend `safeai/analyzers/mcp/analyzer.py` to
  statically resolve a local MCP server `command` (e.g. `node build/index.js`,
  depth-capped, never executed), attempt static extraction on the target, and
  label output `assurance: resolved` vs `assurance: unresolved-command` vs
  `assurance: external-package` (for `npx`/`uvx`/`docker run`).
- **Target Taxonomy Engine** — extend `safeai/report/html_kit.py` and
  `json_report.py` to aggregate external-network capabilities into explicit
  buckets (Database, Object Storage, SaaS APIs) as a first-class report view.

### Shipped — Workstream 3: Detection Depth (analysis hardening)

- **Prompt risk depth** — move beyond single-line regex in `PROMPT_*` /
  `PROMPT_FILE_*` rules: multi-line prompt concatenation detection, cross-file
  prompt interpolation (prompt file read and interpolated into code), indirect
  injection via tool calls embedded in prompts, XML/HTML tag injection
  (`<system>`, `</system>`) in prompts, template variable injection in `.md`
  files. Heuristic detectors use hedged language to avoid overclaiming.
- **Data leakage depth** — expand `DATA_LEAKAGE` beyond the 4 basic patterns:
  private keys (`-----BEGIN RSA PRIVATE KEY-----`), JWT tokens (`eyJ...`),
  AWS access keys (`AKIA...`), connection strings (`mongodb://`, `postgres://`),
  base64-encoded secrets, hex-encoded secrets. Per-pattern severity
  differentiation (private keys = critical, connection strings = high).
- **Cross-component analysis** — new `safeai/analysis/component_graph.py` that
  analyzes relationships between components with deterministic output (sorted
  edges, adjacency lists, and summary keys).

### Shipped — Workstream 4: Community & Onboarding

- **Community scans expansion** — expanded from 5 to 25 AI tool targets across
  all categories (workflow platforms, LLM frameworks, multi-agent, RAG, stateful
  orchestration).
- **First-time user experience** — `safeai welcome` guided first-run command
  displaying recommended rules, first scan instructions, result interpretation,
  registry commands, and documentation links.

### Definition of done

- All CE 1.4, CE 1.5, and CE 1.8 items in ROADMAP.md can be confidently marked ✅ shipped.
- Prompt injection detection covers multi-line, cross-file, and indirect
  injection patterns; data leakage covers private keys, JWT, AWS keys, and
  connection strings with per-pattern severity.
- Cross-component relationships (skill→tool→workflow→MCP→model) are analyzed
  and surfaced in reports.
- A reviewer can see, for any tool or MCP server, where it is declared and
  where it is implemented, and SafeAI flags mismatches. Suppressions are
  provably valid against the current code, and every finding carries its
  longitudinal history — unblocking CE 2.0 (Plugin SDK & Static IaC
  Correlation).

### Fixes (post-review)

- **Lifecycle provenance** — resolved lifecycle rows now preserve last-known
  `file_path` and `line` from `scan_findings`; `previous_event` uses actual
  history instead of hardcoded value.
- **Tool provenance** — orphan findings now include declaration/implementation
  source path and line when available; summary includes deterministic mappings.
- **Deterministic output** — component graph and target taxonomy output is
  deterministic independent of input ordering (sorted edges, adjacency, buckets).
- **Heuristic wording** — prompt detectors use hedged language ("pattern detected",
  "may enable") to avoid overstating confidence; severity adjusted for
  `PROMPT_INDIRECT_INJECTION` (high→medium) and `PROMPT_XML_INJECTION` (medium→low).

## [1.6.0] - 2026-08-13

### Added — SafeAI Security Scorecard

- **Security Scorecard** (`safeai/scorecard.py`): a deterministic, auditable
  0–10 report that summarises a scan into an overall score, per-category
  scores, and a `pass`/`warn`/`fail` outcome. It is a Scorecard-style report,
  **not** an OpenSSF Scorecard report, and says so in every rendering.
- **Scoring model** (documented in-module): severity weights
  `critical=4.0, high=2.0, medium=0.75, low=0.25, info=0.0`, diminishing
  returns for repeated findings at the same `(rule_id, file, line)`, and
  fingerprint deduplication. Suppressed findings are excluded from the score
  and from gating.
- **Five new scan flags**: `--scorecard`/`--scorecard-md` (Markdown),
  `--scorecard-json` (JSON), `--scorecard-summary` (append to the GitHub
  Actions step summary via `$GITHUB_STEP_SUMMARY`), and
  `--scorecard-fail-under N` (fail the scan when the score is below `N`,
  validated to `[0, 10]`).
- **Machine-readable contract** (`safeai/scorecard-schema.json`,
  `schema_version: 1`) with `additionalProperties: false` on the `policy`,
  `coverage`, and finding objects so producer/consumer drift fails validation.
- **Injection-safe rendering**: all untrusted finding text is Markdown-escaped
  and secret-redacted before it reaches the report or the job summary.
- Robustness: malformed finding input (non-numeric `line`, unknown severity,
  unrecognised `--fail-on`) never crashes the scorecard; an unknown fail-on
  threshold fails closed. ~55 scorecard tests in `tests/test_scorecard.py`.

### Added — Community Scan programme (private pilot)

- **`community-scans/`**: a governed workflow for scanning public third-party
  agent frameworks and disclosing results responsibly. Includes the target
  manifest (`targets.yml` + `targets-schema.json`), `methodology.md`,
  `disclosure-policy.md`, `private-pilot.md`, and a pinned-dependency
  `requirements.txt`.
- **Pipeline scripts** (`community-scans/scripts/`): `validate_targets.py`
  (read-only GitHub API validation, path-traversal-safe refs), `resolve_meta.py`
  (pin a target to a 40-char commit SHA), `build_scan_manifest.py` (provenance
  manifest), `sanitise_report.py` (redact a private report into a public-safe
  summary), and `render_reddit_draft.py` (human-review disclosure drafts).
- **Workflows**: `.github/workflows/community-scan.yml` (SHA-pinned actions,
  `contents: read` only, concurrency group, 30-minute timeout, private/public
  artifact split) and `.github/workflows/validate-community-scan.yml`.
- Nothing is published automatically; every report is private by default and
  requires human review before any external disclosure.

### Added — CLI version support & developer guide

- **`safeai/version.py`**: single source of truth for the version string
  (`SAFEAI_VERSION`) plus `version_requested()`/`print_version()` helpers.
  `safeai --version` / `-V` prints a stable machine-readable line.
- **`DEVELOPER_GUIDE.md`**: local development and GitHub Actions usage guide,
  including the Security Scorecard flags.

### Changed — GitHub Action hardening

- **Version source of truth**: `pyproject.toml` reads the version dynamically
  from `safeai.__version__` (`setuptools` `attr:`), so the package metadata and
  the source can no longer drift.
- **Hermetic install path**: `scripts/safeai-action.py` honours
  `SAFEAI_ACTION_FIND_LINKS` so CI can install a freshly built wheel instead of
  a published PyPI version; dependencies still resolve from PyPI.
- **Output hardening**: `set_output()` strips `\n`/`\r` to prevent
  `$GITHUB_OUTPUT` key injection; path inputs are rejected when they contain
  control characters; `get_safeai_version()` failures surface as `::warning::`.

### Notes

- Version bumped to `1.6.0` (tag `v1.6`). Full suite: 459 tests collected.

## [1.5.0] - 2026-08-11

### Added — GitHub Actions Marketplace action

- **Composite action** (`action.yml` at the repository root): a ready-to-use
  GitHub Actions action with inputs `path`, `version`, `fail-on`, `sarif`,
  `rules`, `baseline`, `fail-on-new`, `fail-on-escalation`, `no-registry`,
  and `extra-args`; a `sarif-path` output; and `shield`/`purple` branding.
- **Pure-Python driver** (`scripts/safeai-action.py`): installs the
  `SafeAI-Static-Analyzer` PyPI distribution into the runner's Python and
  runs `python -m safeai scan`. All inputs arrive as `INPUT_*` environment
  variables and are forwarded to the tool as an argv list — no shell
  evaluation, no `eval`, no interpolation of user input into `run:`.
- **Native exit-code passthrough** (0 = pass, 1 = policy/finding threshold hit,
  2 = operational error), with the SARIF artifact written even on a failing
  scan so downstream uploads keep working. The action prints `::warning::`
  if a failed scan produced no SARIF.
- **Least-privilege design**: the action only needs `contents: read` and runs
  with the runner's default Python 3.11+ (`setup-python@v5` recommended);
  `no-registry: true` is the default so scans stay ephemeral.
- **Self-validating CI** (`.github/workflows/action-test.yml`): runs the
  action itself (`uses: ./`) against clean and risky fixture repositories,
  builds the wheel, installs it into a throwaway venv, and validates SARIF
  2.1.0 output and failure behavior on every commit.
- Local validation helpers: `scripts/run_local_integration.py` (build →
  venv-install → scan → SARIF/exit-code check, with `PYTHONPATH` cleared so
  only the installed package is used) and `scripts/check_wheel.py` (wheel
  entry points, rules data, METADATA name). 24 new tests in
  `tests/test_github_action.py` plus fixtures in `tests/fixtures/action/`.

### Added — Environment Dependency Inventory & Correlation (CE 1.5)

- **Environment and credential dependency inventory**
  (`safeai/analyzers/env_dependency/`): a new analyzer records *references* to
  external configuration and credentials — `os.getenv`/`os.environ`,
  `process.env`, dotenv keys, shell/template interpolation, AWS Secrets
  Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, and Kubernetes
  `secretKeyRef`. **Names and source locations only; values are never read,
  masked, or stored**, preserving the source-private guarantee. Entries are
  flagged `secret: true` when backed by a secret manager or a secret-ish name.
- **Dependency-to-capability correlation**
  (`safeai/analysis/dependency_correlation.py`): the inventory is matched
  against the per-tool capability surface via a reviewable name-family keyword
  model, producing two new findings:
  - `DEP_UNDECLARED_CAPABILITY` (medium) — a referenced credential/config
    family has no declared capability to consume it: a candidate undeclared
    capability.
  - `DEP_ORPHANED_TOOL` (low) — a credential-demanding capability is declared
    with no matching credential/config reference anywhere: a probable dead or
    misconfigured tool.
- Correlation findings feed the severity counts, trust score, SARIF, terminal
  and HTML outputs, and are written to the KYA manifest (`dependency_inventory`
  and `dependency_correlation`, plus a `summary.dependency_count`).
- New rules in `safeai/rules/base_rules.yaml`: `ENV_DEP_INVENTORY`,
  `DEP_UNDECLARED_CAPABILITY`, `DEP_ORPHANED_TOOL`.

### Fixed — CE 1.5 architecture review hardening

- **Family matching is now word-segment based**
  (`safeai/analysis/dependency_correlation.py`): names are split on
  non-alphanumeric boundaries instead of raw substring matching, so short
  tokens no longer false-positive inside unrelated words (e.g. `jdbc` no longer
  maps to the database family via `db`). Provider-specific families
  (`cloud`/`database`/`messaging`) take precedence over the generic `api`
  fallback, keeping `SLACK_TOKEN` aligned with a declared `slack` capability and
  eliminating simultaneous false `DEP_UNDECLARED_CAPABILITY` +
  `DEP_ORPHANED_TOOL` pairs.
- **Single scoring pass** (`safeai/engine/orchestrator.py`): correlation now
  runs before the single count/score/relativize pass so its findings are
  included exactly once; the second `_relativize_report()` call was removed.
- **Payload-carrying findings are never suppressed**
  (`safeai/kya/suppressions.py`): `ENV_DEP_INVENTORY` (and
  `MCP_ASSETS_DISCOVERED`) are exempt from `apply_suppressions`, so a broad
  `rule_id`/`path` suppression cannot blank the dependency-inventory section.

### Notes

- The informational `ENV_DEP_INVENTORY` finding is counted in the severity
  breakdown and baseline; scans of repositories with a declared dependency
  inventory will report one more finding than v1.4 for the same input.

### Changed — first stable release & packaging fixes

- Version bumped to `1.5.0` and the `Development Status :: 4 - Beta`
  classifier replaced with `5 - Production/Stable` (`pyproject.toml`).
- `safeai.cmd.postprocess._safeai_version()` now resolves the installed
  version through `importlib.metadata` using the `SafeAI-Static-Analyzer`
  distribution name (with the previous `safeai` name as fallback).
- `data_files`-free pure-Python wheel confirmed to package
  `safeai/rules/base_rules.yaml` as package data; a wheel check script now
  guards this in CI.

## [1.4.0-beta] - 2026-08-02

### Added — Tool-Centric Capability Model & Escalation Detection

- **Tool identity** (`safeai/analysis/tool_identity.py`): capabilities are now
  attributed to a named tool rather than only to an agent. A tool identity
  carries a `kind` (`agent`, `mcp_server`, `skill`, `tool`, `workflow_node`,
  or `unknown`), a `name`, and a `framework`, and reduces to a deterministic
  `tool_key` (for example `mcp_server:invoice-lookup`, `tool:send_email`).
  The key is stable across scans when a name is available, and falls back to
  a path-derived hash only when a tool is genuinely unnamed. Capabilities
  that cannot be attributed to any tool are grouped under a fixed
  `unknown:unattributed` identity rather than dropped or guessed at.
- **Access modes**: every capability now carries an `access_mode` on an
  ascending scale of `none < read < write < mutate < execute`. Where a
  framework or configuration does not explicitly declare the mode, SafeAI
  infers it conservatively (defaulting to `read`) and marks the capability
  `access_mode_inferred: true`. Inferred access can trigger a rule, but its
  severity is capped below critical, and never on its own claims the same
  certainty as a declared, evidenced access mode. See `LIMITATIONS.md`.
- **Capability diff, schema version 2** (`safeai/analysis/capability_diff.py`):
  the baseline comparison now keys on `(tool_key, capability_name,
  access_mode)` instead of capability name alone, so the diff can tell you
  which tool gained or lost which authority, not just that "shell" appeared
  somewhere in the project. The output adds a `tools` breakdown, `counts`
  (new/escalated/reduced/removed/unchanged tools, plus escalations by
  severity), and a `highest_escalation` summary. The pre-2.0 flat
  added/removed/changed diff is preserved verbatim under a `legacy` key and
  at the top level for existing consumers.
- **Thirteen capability escalation rules** (`safeai/analysis/escalation.py`):
  `ESC_SHELL_ADDED`, `ESC_FILESYSTEM_WRITE_ADDED`,
  `ESC_EXTERNAL_ACCESS_ADDED`, `ESC_MCP_SERVER_ADDED`,
  `ESC_MCP_READ_TO_MUTATE`, `ESC_APPROVAL_GATE_REMOVED`,
  `ESC_MEMORY_SCOPE_EXPANDED`, `ESC_WRITE_TOOL_ADDED`,
  `ESC_NEW_EXTERNAL_DESTINATION`, `ESC_AUTONOMY_INCREASED`, plus three
  combination rules that only fire when two conditions are true of the same
  tool at once — `ESC_COMBO_UNTRUSTED_INPUT_SHELL`,
  `ESC_COMBO_AUTONOMY_BROAD_DATA`, and
  `ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT`. These exist because a single
  capability rarely tells you whether a change matters: an agent gaining
  shell access is a different story than one that already had it, and an
  agent that gains both autonomy and broad data access at once is riskier
  than the sum of the two changes taken separately.
- **Tool surface** (`safeai/analysis/tool_surface.py`): a per-tool capability
  index, built from data the scan already collected (agent models and MCP
  assets), with no additional file access. It is written into the JSON
  report, the KYA manifest (`tool_surface`, added at manifest schema 1.1),
  and the registry. An MCP configuration that does not name its server is
  recorded under the unattributed tool identity rather than assigned an
  invented name.

### Added — Deep Claude Code Analysis

- The Claude Code adapter moves from presence detection to structural
  analysis of `.claude/settings.json` and `.claude/settings.local.json` (in
  that precedence order), `.mcp.json`, `.claude/commands/*.md` slash
  commands, `.claude/agents/*.md` subagent definitions, and lifecycle hooks.
  See `FRAMEWORK_SUPPORT.md` for the full scope boundary.
- **Ten new rules**, documented with exact severities and OWASP LLM mappings
  in `RULES_REFERENCE.md`: `CC_WILDCARD_PERMISSION`,
  `CC_BYPASS_PERMISSIONS`, `CC_DENY_SHADOWED`, `CC_FS_WRITE_OUTSIDE_ROOT`,
  `CC_SLASH_COMMAND_SHELL`, `CC_SLASH_COMMAND_ARG_INJECTION`,
  `CC_SUBAGENT_PRIVILEGE_ESCALATION`, `CC_HOOK_SHELL_EXEC`,
  `CC_MCP_UNCONSTRAINED`, and `CC_SETTINGS_UNPARSEABLE`. Configuration that
  cannot be parsed is reported as a low-severity finding rather than
  silently skipped or treated as a crash.

### Added — PR Comment, CI Context, and the Assurance Boundary

- **PR comment renderer** (`safeai/report/pr_comment.py`): produces a short,
  reviewer-facing Markdown summary of capability escalations, grouped by
  tool with the worst severity first, capped at 60 lines. With no baseline
  it summarizes the first scan rather than fabricating a diff; with no
  changes it prints a single line. SafeAI only ever writes this file to
  disk or stdout — it never posts it anywhere and makes no network call of
  any kind. Publishing the comment is left entirely to the CI workflow. See
  the "Capability escalation in CI" section in `README.md`.
- **CI context detection** (`safeai/kya/ci_context.py`): reads environment
  variables (and, on GitHub Actions, the pull request event payload) to
  identify the provider, branch, base ref, commit, PR number, and
  repository. It never raises — outside CI it returns an
  all-`unknown`/`None` result — and supports GitHub Actions, GitLab CI, and
  Azure Pipelines.
- **Three new `safeai scan` flags**: `--pr-comment PATH` writes the Markdown
  summary to a file; `--pr-comment-stdout` prints it to stdout; and
  `--fail-on-escalation {critical,high,medium}` fails the scan when a
  capability escalation at or above that severity is found. This is a
  separate gate from `--fail-on`/`--fail-on-new`, which act on findings, not
  capability escalations; the two gates only add to the failing set, never
  subtract from it, and `--fail-on-escalation` requires `--baseline` because
  an escalation is by definition a change relative to something.
- **Assurance boundary** (`safeai/kya/assurance.py`): a short, factual
  statement of what a scan verified statically (declared tools, prompt and
  instruction files, MCP server configuration, workflow structure,
  permission configuration) and what it structurally cannot verify (IAM and
  cloud permissions, runtime identity, deployed network policy, actual
  runtime behaviour, dynamically constructed tool bindings). It is computed
  from real scan data — files actually skipped, configuration that actually
  failed to parse, and the count of access modes that were actually
  inferred rather than declared — never from a fixed template. Written into
  the manifest as `assurance_boundary` (manifest schema 1.2). See
  `KYA_MANIFEST.md` and `LIMITATIONS.md`.

### Added — Registry Schema v2

- **`agent_tool_snapshots` table**: one row per tool per scan, storing the
  tool's identity, kind, framework, its capability list, and a summarized
  access level. `agent_id` is nullable by design — a tool is attributed to
  an agent only when the tool's evidence paths overlap the agent's source
  locations, and a tool with no such overlap is stored unattributed rather
  than assigned a guessed owner or dropped. Uniqueness is enforced by an
  expression index (`IFNULL(agent_id, ''), scan_id, tool_key`) because
  SQLite treats `NULL` as distinct for ordinary `UNIQUE` constraints. See
  `REGISTRY.md`.
- **Automatic migration from schema v1**: existing registries gain the new
  table and indexes in place on the next scan. Migrations are additive and
  forward-only; no existing row in any table is dropped, rewritten, or
  renumbered.

### Changed

- `MANIFEST_SCHEMA_VERSION` is now `1.2`. The `tool_surface` array
  (introduced at 1.1, alongside this release) and the `assurance_boundary`
  object (new at 1.2) are both present in every manifest written by this
  version. `KYA_MANIFEST.md` has been brought up to date to document both.
- Baseline loading accepts a legacy JSON report or a KYA manifest of schema
  1.1 or later as the `--baseline` input, matching the existing baseline
  contract.
- Version bumped to `1.4.0b0` (`pyproject.toml`).

### Compatibility

- **Registries** created under schema v1 migrate automatically on the next
  scan and retain every existing row; nothing is deleted or renumbered by
  the migration.
- **Baselines** captured before v1.4 (no `tool_surface` in the manifest, or
  a legacy JSON report) still work with `--baseline` and
  `--fail-on-escalation`, but because they predate per-tool attribution,
  the diff cannot trust their structural tool status. In that case,
  individual per-tool escalation rules are suppressed and only the three
  combination rules are evaluated, since those depend on conditions within
  a single scan rather than on trusting the baseline's tool structure.
- No new runtime dependency was introduced. PyYAML remains the only
  third-party dependency.

## [1.3.0-beta] - 2026-07-31

### Added — KYA Baseline & Local Registry

- **Canonical KYA manifest** (`safeai-manifest.json`, schema v1.0): the
  portable public contract for scan-derived agent evidence, written via
  `--manifest`. See `KYA_MANIFEST.md`.
- **Local SQLite KYA registry** at `.safeai/registry.db`, created/updated
  automatically on interactive scans (auto-disabled when `CI` is set).
  Historical snapshots are append-only. See `REGISTRY.md`.
- **`safeai registry` command group**: `list`, `show`, `history`, `diff`,
  `export` with `--registry PATH` and `--format table|json`.
- **Deterministic finding fingerprints** (documented SHA-256 algorithm),
  stable `finding_id`s, confidence labels (`high|medium|low`), provenance
  records, and remediation defaults for high-value rules.
- **Baseline comparison** (`--baseline`): classifies findings as
  new/existing/resolved; accepts manifests or legacy JSON reports.
- **`--fail-on-new`**: opt-in gating on new/regressed findings only.
  Existing `--fail-on` semantics are unchanged without it.
- **Suppression workflow** (`.safeai/suppressions.yml`): required
  reason/owner/created, optional expiry and path scope; expired entries
  warn; suppressed findings stay visible and are excluded from gating.
- **Minimal policy-as-code** (`.safeai/policy.yml`): `allow|warn|
  require_review|deny` with rule/severity/capability/framework/agent/path/
  MCP-posture selectors; deterministic evaluation; outcome in terminal,
  manifest, HTML, and JSON. `deny` fails the scan.
- New scan flags: `--manifest`, `--registry`, `--no-registry`,
  `--strict-registry`, `--policy`, `--suppressions`, `--fail-on-new`.
- Terminal/HTML/SARIF output: KYA section, registry status, policy
  outcome, baseline counters, SARIF `partialFingerprints` and rule help
  text.
- Docs: `KYA_MANIFEST.md`, `REGISTRY.md`, `LIMITATIONS.md`; maturity
  categories in `FRAMEWORK_SUPPORT.md`; README/USER_GUIDE KYA sections.
- 66 new tests covering manifest determinism, fingerprints, baseline,
  suppressions, policy, registry persistence/queries/CLI, redaction, and
  CI behavior.

### Changed

- Scan engine skips `.safeai/` and SafeAI-generated artifacts (manifests,
  JSON reports) to prevent findings feedback loops. The JSON report now
  carries a `report_type: safeai.scan` marker (additive).
- JSON report findings gain additive keys (`fingerprint`, `finding_id`,
  `status`, `confidence_label`, `provenance`); no keys removed or retyped.
- `--baseline` still feeds legacy capability diff when given a legacy JSON
  report, and now also drives fingerprint comparison.
- Version bumped to `1.3.0b0` (`safeai/__init__.py` now matches
  `pyproject.toml`).

### Backward compatibility

- Existing CLI usage, exit codes, and JSON/HTML/SARIF shapes are preserved;
  all schema changes are additive. The manifest is a new artifact, versioned
  independently (`schema_version: 1.0`).
- Registry write failures never fail a scan unless `--strict-registry` is
  passed (exit code 2).

## [1.2.0] - 2026-07-26

### Added
- Eight new capability detectors (contributed by @yugaaank):
  - Docker (`CAP_docker`): `import docker`, `DockerClient`, `containers.run`
  - Kubernetes (`CAP_kubernetes`): `import kubernetes`, `kubectl`, `kube_config`, `k8s`
  - Redis (`CAP_redis`): `import redis`, `Redis()`, `StrictRedis`
  - S3 / Cloud Storage (`CAP_s3`): `import boto3`, `boto3.client('s3')`
  - Slack (`CAP_slack`): `import slack`, `slack_sdk`, `SlackClient`
  - Jira (`CAP_jira`): `import jira`, `JIRA()`, `jira.Client`
  - Browser Automation (`CAP_browser`): `playwright`, `selenium`, `webdriver`, `browser_use`
  - Google Cloud (`CAP_gcp`): `google.cloud`, `BigQuery`, `gcsfs`
- New capability categories: `Container` and `Collaboration`
- 20 tests in `tests/test_capability_detection.py` covering detection, false positives, multi-capability, and deduplication

### Changed
- `safeai/analysis/capabilities.py`: added `container` and `collaboration` categories
- `safeai/analyzers/capability/analyzer.py`: 8 new `CAP_PATTERNS`, `RULE_BY_CAP`, and `CATEGORY_BY_CAP` entries
- `safeai/rules/base_rules.yaml`: 8 new capability rules

## [1.1.0-beta] - 2026-07-24

### Added
- AI Component Security: skill, prompt file, tool definition, model config, and workflow template analysis
- Deep MCP analysis: per-tool broad permissions, sensitive resource detection, insecure transport detection
- Seven early-preview framework adapters: Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, n8n (15 total)
- Capability diff (`--baseline` flag) comparing current scan against a previous JSON report
- Parser registry with `@register_parser` decorator and `safeai.parsers` entry-point group for third-party plugins
- Diagnostics reporting in scan output

### Changed
- Component and integration paths are relativized to scan root in all report formats
- Provider-aware model safety checks (`MODEL_MISSING_CONTENT_FILTER` scoped to Google/Bedrock/Azure)
- Dify and n8n detection tightened to reduce false positives
- Guard against `IndexError` in parser arg extraction

### Security
- Masked credential values in findings evidence across all report formats

## [1.0.0-beta] - 2026-07-18

### Added
- Multi-framework scanning: LangGraph, CrewAI, LangChain, Semantic Kernel,
  OpenAI Agents SDK, Microsoft Agent Framework, Azure AI Foundry, Bedrock Agent
- Prompt injection detection (LLM01): input interpolation, missing delimiters,
  system prompt leakage, role override attempts
- Capability analysis (LLM06): shell, filesystem, HTTP, database, code
  execution, autonomous loops, `subprocess` with `shell=True`, file writes
- Data leakage detection (LLM02): hardcoded API keys, tokens, passwords,
  environment secret references
- MCP analysis: config discovery, schema validation (v1.0/v1.1), missing auth,
  weak auth, missing permissions, exposed endpoints, hardcoded secrets
- Deterministic trust scoring across 7 risk categories (0–100)
- Reports: terminal, JSON, SARIF 2.1.0, HTML
- Custom YAML rules via `--rules`
- CI/CD exit codes via `--fail-on`
- GitHub Actions workflow with self-scan SARIF dogfooding
- Installable package with `safeai` console script and `python -m safeai`

### Security
- Credential values in findings evidence are masked in all report formats
- Scans exclude VCS directories, dependency caches, and oversized files
