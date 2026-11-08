# Credibility track — plan and study protocols

> Opened 2026-11-07 at v2.16.0 (`main` at `9dbf544`). Roadmap entry:
> `ROADMAP.md` §Credibility track (C-1 to C-8). This document is the
> plan *and* the pre-registration: targets, samples, metrics and
> reporting rules are fixed here **before** any study runs. A change to
> a protocol after the first run is recorded in the *Protocol changes*
> log at the end, with its date and reason.

## Starting point (what the numbers are today)

| Measure | Value at v2.16.0 | Source |
|---|---|---|
| Authority corpus | 58 cases; 21 written independently, 37 migrated from SafeAI's own fixtures | `docs/benchmarks/authority/VALIDATION_REPORT.md` |
| Change detection P/R/F1 | 1.0 on **5** cases | same |
| Escalation P/R/F1 | 1.0 on **4** cases | same |
| End-to-end attribution | **0.4851** (69 of 134 unattributed) | same |
| Pending cases (AI-drafted truth, not reviewed) | **44** | `tests/benchmarks/authority-pending/` |
| Signals that can gate | tool / capability / access-mode changes; everything since v2.9 is review-only | `ROADMAP.md` |
| Overall verdict | NOT LANE-A READY | `VALIDATION_REPORT.md` |

The track's job is to replace "1.0 on 5 fixtures" with numbers measured
on code nobody wrote for SafeAI, including the numbers that come out
badly.

## Rules that apply to every study

1. **Pre-registration.** Targets, commit ranges, sample sizes, seeds and
   metrics are written down here (or in the study's `targets.yml`) and
   committed before the first run. Results of a run never change which
   targets are in it.
2. **Humans label.** SafeAI never labels its own output, and no LLM
   produces a label. Each unit is labelled by two people independently;
   disagreements are adjudicated by a third, or by discussion recorded
   in the adjudication file.
3. **Blind where it matters.** The materiality question is asked without
   showing SafeAI's change class, so the label does not anchor on it.
   The "is this real?" question necessarily shows what SafeAI claims.
4. **Intervals, not points.** Every rate is reported with a 95% Wilson
   interval. Below the minimum sample (n < 10 labelled units) the result
   is *insufficient*, never 0 or 1.
5. **Misses are published.** Every false positive and every miss found is
   listed by commit and change, with the same prominence as the hits.
6. **No claim before the number.** README and website wording changes
   only after a result is published (C-8).
7. **Graduation is not decided here.** A change type with good numbers is
   *proposed* for Lane A; ADR-0008 (≥ 95% precision for the graduated
   class) decides. We also report whether the interval's lower bound
   clears 95%.
8. **The scanner stays offline.** Study tooling lives in `scripts/`; it
   clones repositories with `git`, never installs or runs target code,
   and the `safeai` package gains no network path.
9. **Disclosure.** A suspected vulnerability found during any study is
   handled under `community-scans/disclosure-policy.md`: private report
   first, human-confirmed, published only after a fix (C-6).

## C-1 — External review of the pending corpus

**Question.** Is the candidate truth of the 44 pending cases right?

**Procedure.**
1. `python scripts/label_kit.py review-packets --out review/` writes one
   Markdown packet per case (input files, expected truth, what each
   truth key asserts) and one blank label sheet per reviewer
   (`review-sheet.<reviewer>.csv`).
2. Two reviewers fill their sheets independently: per case,
   `verdict` ∈ {`correct`, `partly`, `wrong`} and free-text
   `corrections`.
3. `python scripts/label_kit.py agreement A.csv B.csv --field verdict`
   reports percent agreement, Cohen's kappa and the disagreement list.
4. Disagreements are adjudicated; a case whose truth is `correct` after
   adjudication is promoted following
   `tests/benchmarks/authority-pending/README.md` (truth is fixed, never
   the input). `partly` / `wrong` cases have their truth corrected and
   go through review once more.

**Reported.** Agreement and kappa; how many cases were correct, partly
right, wrong, per category; every correction. A truth correction that
makes a case fail is a SafeAI defect, recorded as such.

**Reviewers.** At least one reviewer from outside the SafeAI authors.
Reviewers are named in the report with their consent.

## C-2 — Real-world change study

**Question.** On real commits, how often is a change SafeAI reports a
real change in agent authority (precision), how often is it material,
and how often does SafeAI miss one (recall)?

**Targets (proposed; confirmed by the owner before the run).** Public
repositories that *define agents or tools* (applications, example
collections, MCP servers), not framework internals, because authority
is decided where tools are wired to agents. Selection criteria:

- open-source licence; public history of at least 50 first-parent
  commits in the range;
- defines agents or tools in a framework SafeAI parses (Claude Code
  settings, MCP configuration, OpenAI Agents SDK, LangGraph, CrewAI,
  AutoGen) or is an MCP server;
- not written by SafeAI's authors.

The list lives in `research/credibility/targets.yml` with
`status: proposed`. The owner flips it to `confirmed` and pins each
range (`from` / `to` commit SHAs) before the run.

**Eligibility check.** `python scripts/target_check.py --targets research/credibility/targets.yml --out research/credibility/target_check.json`
records, per target, the facts the criteria depend on: licence,
archived / fork flags, owner, first-parent commit count, and, at the
head commit only, the frameworks SafeAI detects and how many tools and
MCP assets it finds. It records **no findings**, so choosing a target
cannot depend on how SafeAI scores it. It suggests a range of the last
300 first-parent commits; the owner pins the actual range.

**Check of 2026-11-08.** 6 of 9 proposed targets meet every criterion:
`awslabs-mcp`, `github-mcp-server`, `stripe-ai`,
`cloudflare-mcp-servers`, `playwright-mcp`,
`executeautomation-playwright-mcp`. Not eligible as recorded:
`mcp-reference-servers` (GitHub reports its licence as "Other", not an
SPDX identifier; the owner may read the licence file and confirm it by
hand, noting why), `crewai-examples` (archived, no recognised licence),
`openai-cs-agents-demo` (10 first-parent commits). Side observation, not
a study result: the check reports `azure_foundry` at the head of three
MCP servers and `n8n` at two, which look like framework misdetections;
they are a SafeAI defect to look at, not a reason to drop a target.

**Procedure.**
1. `python scripts/history_study.py --targets research/credibility/targets.yml --out study/`
   clones each confirmed target, exports each first-parent commit in the
   range with `git archive` (no checkout hooks, nothing executed), scans
   it with the previous scanned commit as `--baseline`, and writes:
   - `commits.jsonl` — one row per commit: scanned / skipped / error,
     changed files, highest change class, number of reported changes;
   - `changes.jsonl` — one row per reported change unit: a tool change
     (with its change class, escalations, capabilities added, access-mode
     changes), the unattributed bucket, a delegation change or a
     workload-identity change.
   Commits that touch only binary assets (images, fonts, PDFs) are
   skipped and keep the previous baseline.
2. `python scripts/label_kit.py packets study/ --sample-silent 0.1 --seed 20261107`
   writes the labelling set: **every** reported change unit, plus a
   seeded 10% sample of *silent* commits (scanned, files changed, nothing
   reported), each as a Markdown packet with the commit link and the
   changed files, and a blank sheet per labeller.
3. Labellers answer, per change unit: `real` ∈ {`yes`, `no`, `unsure`}
   (did the agent's potential authority change as SafeAI states?) and
   `material` ∈ {`yes`, `no`, `unsure`} (should a reviewer look before
   this merges?), with SafeAI's class hidden; per silent commit:
   `missed` ∈ {`yes`, `no`, `unsure`} and what was missed.
4. `label_kit.py agreement` on the two sheets; adjudication; then
   `python scripts/label_kit.py score study/ adjudicated.csv` reports:
   - **detection precision** = real=yes / (yes + no), overall and per
     change type, with Wilson intervals; `unsure` is reported separately
     and excluded from the ratio;
   - **materiality agreement**: SafeAI MATERIAL / HIGH_RISK vs labelled
     `material=yes`, as a 2×2 table with precision and recall;
   - **miss rate** in the silent sample, extrapolated to all silent
     commits with its interval (this is an estimate of recall, stated as
     such).

**Minimum for a per-type number.** 10 labelled units of that type;
below it, *insufficient*. A Lane-A proposal for a change type needs at
least 30.

**Not measured.** Whether a change was exploitable; anything at run
time.

## C-3 — Incident replay

**Question.** For publicly disclosed agent, MCP and skill security
flaws, would SafeAI have flagged the vulnerable code before the fix?

**Registry.** `research/credibility/incidents.yml`. Each entry cites the
public advisory, the repository, the vulnerable and fixed revisions, the
commit that introduced the flaw where known, and what a static scanner
could be expected to see:

- `static_visibility: visible` — the flaw is in repository files
  (a tool that runs shell commands from model input, an MCP server
  exposing a write tool without a declared approval, a poisoned tool
  description);
- `static_visibility: runtime-only` — the flaw needs run-time state
  (a network race, a server-side check, behaviour of a dependency).

An entry is `candidate` until a human has read the advisory and the
fix diff and confirmed every field; only `verified` entries are scored.

**Verification.** Two people verify each candidate independently, then
agree (or a third adjudicates):

1. `python scripts/incident_verify.py order --registry research/credibility/incidents.yml`
   prints the pre-registered order: candidates sorted by
   `sha256("20261107:<id>")`. Candidates are verified in this order, so
   verifying the first *N* gives a random sample, not a hand-picked one,
   and a later search does not reshuffle the existing ones.
2. `python scripts/incident_verify.py packets --count 20 --verifiers ana,ben --out verify/`
   writes one packet per candidate (advisory text, CWEs, fix commit and
   its diff, SafeAI's full rule catalogue) and a blank sheet per
   verifier. **Packets never show what SafeAI reports on the code**:
   `expected.rules` is the verifier's answer to "which rules should flag
   this flaw if SafeAI worked as documented?", chosen blind. Otherwise a
   verifier could copy the rules that fired and recall would measure
   nothing.
3. Each verifier answers `decision` (`verified` / `rejected` / `unsure`),
   `static_visibility`, `rules`, `paths` and, if found, `introduced_ref`.
4. `python scripts/incident_verify.py apply --registry research/credibility/incidents.yml verify/sheet.ana.csv verify/sheet.ben.csv [--adjudication verify/sheet.cem.csv]`
   writes rows the two agree on (or the adjudicator settles) into the
   registry with `verified_by` and `verified_on`; every other row stays
   a candidate and is listed. The registry check refuses a verified or
   rejected entry without two named verifiers.

**Procedure.** `python scripts/incident_replay.py --registry research/credibility/incidents.yml --out replay/`
scans the vulnerable revision (and, where given, the introducing commit
against its parent as baseline) and records, per incident, whether any
of the entry's `expected.rules` fired or any reported change touched
`expected.paths`.

**Reported.** Recall over verified `visible` incidents, with its
interval; `runtime-only` incidents reported apart as expected
`unknown` (a static scanner flagging them would be a coincidence, not a
hit); every miss listed with a one-line reason.

**Selection.** Every advisory the recorded search returns, not a
hand-picked subset. `python scripts/incident_search.py` runs it and
applies four written screens in order: (1) reviewed `pip` / `npm`
advisories published on or after 2025-01-01; (2) a keyword screen
(MCP, Model Context Protocol, AI / LLM / coding agents, agentic, agent
skills, Claude Code, tool or function calling, prompt injection, or a
package name containing `mcp` or `agent`); (3) a flaw-class screen
(CWE-22, 23, 59, 73, 77, 78, 88, 94, 95, 918, 1427: injection, path
traversal, SSRF, prompt injection, the classes agent authority evidence
bears on); (4) a fix commit on GitHub to replay. Survivors become
`candidate` entries with the fix's parent as `vulnerable_ref` and the
non-test files the fix changes as `expected.paths`;
`static_visibility` is `undetermined` and `expected.rules` empty until a
human verifies them. `research/credibility/incident_screening.json`
lists every keyword match with the screen that excluded it.

**Search of 2026-11-07.** 7,657 advisories searched; 726 keyword
matches; 375 excluded by flaw class, 167 for want of a fix commit, 1
because its fix commit could not be read; **183 candidates**, none
verified. Replay scores `verified` entries only: a candidate, or an
entry whose visibility is still `undetermined`, is reported as
`unscored` even in a dry run. The rules that fired on the flaw's files
are listed in the replay output for analysing misses after scoring;
they are never counted and never shown to verifiers.

## C-4 to C-8

Planned; each gets its protocol here before it starts.

- **C-4 Comparative measurement** reuses C-2's confirmed targets and
  the authority corpus; tools at pinned versions; scored on SafeAI's
  rubric; LLM-backed analysers off or reported apart.
- **C-5 Census** reports aggregates only (no per-project ranking or
  naming) over a pre-registered target list.
- **C-6 Disclosure** publishes the maintainer acceptance rate
  (accepted / filed) and never a raw finding count.
- **C-7 Design partners** records, per review request, whether the
  maintainer acted on it, dismissed it as noise, or ignored it.
- **C-8 Claims ledger** lists every public claim with the measurement
  that backs it.

## Order of work

| Phase | Work | Exit |
|---|---|---|
| 1 (this change) | Tooling for C-1, C-2, C-3; protocols above; proposed targets; empty incident registry | Tooling tested on fixtures; nothing run on real targets yet |
| 2 (in progress) | Owner confirms C-2 targets and ranges; incident search run and entries verified; reviewers recruited | `targets.yml` confirmed; ≥ 10 verified incidents or a statement that fewer exist |
| 3 | C-1 review; C-2 run and labelling; C-3 replay | Technical report with all numbers, misses and corrections |
| 4 | C-4, C-5, C-8; README wording follows the numbers | Claims ledger published |

## Phase 2 — what is left, and who does it

Tooling for every Phase 2 step exists; each remaining step needs a
person, by Rule 2.

| Step | Who | How |
|---|---|---|
| Confirm C-2 targets | Owner | Read `research/credibility/target_check.json`; in `targets.yml` set eligible targets to `confirmed` with `from` / `to` (the suggested range or another), and ineligible or unwanted ones to `excluded` with a `reason`. Commit before any run. |
| Verify incidents | Two verifiers (+ an adjudicator) | `incident_verify.py packets --count 20` in the pre-registered order, fill the sheets, `apply`. Continue in batches until at least 10 verified `visible` incidents, or the candidates run out. |
| Recruit C-1 reviewers | Owner | At least one from outside SafeAI's authors, who consents to be named. `label_kit.py review-packets` produces their packets. |

## Protocol changes

| Date | Change | Reason |
|---|---|---|
| 2026-11-07 | Initial protocol | — |
| 2026-11-08 | C-3 verification fixed before any verification: seeded order, two verifiers with adjudication, `verified_by` / `verified_on` required, and `expected.rules` chosen blind (packets show the rule catalogue, never SafeAI's output). The earlier wording that the rules which fired are "listed to help the verifier" is withdrawn | Letting a verifier see what fired would let `expected.rules` follow SafeAI's output and make recall circular; a seeded order makes a partly verified registry a random sample |
| 2026-11-08 | C-2: seven more proposed targets (MCP servers, an Agents SDK application, a multi-framework toolkit) and a recorded eligibility check that stores no findings | Two targets could not reach 30 labelled units per change type; the check lets the owner confirm from recorded facts. Targets added before any history run |
| 2026-11-07 | C-3 search made concrete before any scoring: the keyword list replaced by the written keyword, flaw-class and fix-commit screens; `undetermined` visibility for candidates | The first search returned 726 keyword matches, most of them flaws (XSS, missing authentication) that no static authority evidence bears on; the screens are recorded so the exclusion of each advisory can be checked |
