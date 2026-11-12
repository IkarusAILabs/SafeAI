# Static authority evidence vs runtime authorization: experiment specification

Version `0.1-draft`. **A proposal for discussion, not an agreed
specification.** It follows
[discussion #251](https://github.com/IkarusAILabs/SafeAI/discussions/251)
and the scope both sides described there. Everything in it is open to
change, including the record formats and the outcome rules.

## 1. Question

Can source-derived evidence about an agent's authority help explain,
predict or audit runtime authorization decisions?

Two kinds of evidence are compared:

- **Static evidence** says what authority the source and configuration
  *could* give an agent. SafeAI produces it without running anything.
- **Runtime observation** says what an authorization layer *decided* for
  a concrete request, and what then happened. A runtime harness
  produces it.

This is a research experiment. It is not an integration, and neither
record supports a claim that an agent is safe.

## 2. What is kept apart

Each scenario records five things separately. None is derived from
another.

| Part | Meaning | Where it lives |
|---|---|---|
| Declared intent | What the scenario's author means the agents to be able to do | `scenario.yml`, `intent` |
| Static evidence | What an analyzer establishes from source, with locations | static evidence record |
| Runtime policy | The authorization rules the harness is configured with | `scenario.yml`, `runtime.policy` |
| Runtime observation | The decision, the execution attempt and the observed effect, per request | runtime observation record |
| Uncertainty | What is unresolved, unsupported or untested | `status` and `reason` fields in both records; `limits` |

Two consequences are built into the outcome rules (section 6):

- Static evidence of potential access together with a runtime `DENY` is
  not a disagreement.
- A runtime `PERMIT` does not establish that an effect occurred.

## 3. Scenarios

Six synthetic scenarios, in `scenarios/`. Each has a `fixture/` and a
`scenario.yml`. They use one framework's handoff model so that
differences between scenarios come from authority, not from syntax.

| Id | Scenario | What it isolates |
|---|---|---|
| `s0_direct_tool` | Direct tool access | Calibration: one agent, one read-only tool |
| `s1_delegated_access` | Delegated access | An agent with no tools reaches a tool through a handoff |
| `s2_attenuated_delegation` | Attenuated delegation | The delegate holds fewer tools than the delegator |
| `s3_attempted_escalation` | Attempted escalation | The delegate holds a destructive tool the delegator lacks |
| `s4_runtime_denial` | Runtime denial | The source wires a tool that the policy withholds |
| `s5_incomplete_identity_link` | Incomplete identity link | A role exists and nothing ties the agent to it |

The fixtures contain no secrets, no real endpoints (`*.example.test`)
and no production data. Nothing in this repository runs them.

### Status of the ground truth

Every `scenario.yml` is marked `ai_assisted_draft`,
`pending_human_review`. The intent, the proposed policy and the expected
outcomes were drafted from the fixtures with AI assistance. **They are
not ground truth.** A scenario counts only after a person from each
project has reviewed it and is named under `annotation.reviewers`, and
that review happens before either side runs its tool on the final
scenario set.

## 4. Static evidence record

One JSON file per scenario, in `records/static/`. Produced by
`scripts/collab_evidence.py static`.

```json
{
  "spec_version": "0.1-draft",
  "scenario": "s3_attempted_escalation",
  "producer": {"tool": "safeai", "kind": "static", "version": "2.16.0"},
  "agents": [{"id": "intern", "framework": "openai_agents",
              "source": {"file": "agents.py", "line": 20}}],
  "identities": [],
  "claims": [],
  "limits": []
}
```

`claims` holds three kinds of claim. Every claim has a stable `id` and a
`status`.

**`tool_access`**: an agent has a path to a tool.

| Field | Meaning |
|---|---|
| `agent`, `tool` | Who, and which tool |
| `via` | Delegation path to the agent that holds the tool. `[]` means the agent holds it directly |
| `status` | `established` or `unresolved` |
| `capabilities` | What the tool's body does: `name`, `access_mode` (`read`, `write`, `mutate`, `execute`), `inferred`, and source `evidence` |
| `capabilities_status` | `detected` or `none_detected` |

**`delegation`**: one agent can hand work to another.

| Field | Meaning |
|---|---|
| `from`, `to` | The edge. `to` is `null` when the target cannot be resolved |
| `mechanism` | How the source expresses it, for example `handoff` |
| `scope` | The delegate's tool set relative to the delegator's: `narrower`, `equal`, `broader_or_different`, `unknown` |
| `scope_basis` | What `scope` was computed from. Today: `tool-name sets` |
| `delegate_exceeds_delegator` | Tools the delegate holds and the delegator does not |
| `evidence` | Source locations |

**`identity_link`**: whether an agent is tied to a principal.

| Field | Meaning |
|---|---|
| `agent` | The agent |
| `principal` | `{kind, name}`, or `null` |
| `status` | `established` or `unresolved` |
| `reason` | When unresolved: `no_identity_in_repository` or `identity_present_not_linked` |

`limits` states, in every record, what static evidence cannot establish:

- It shows potential authority only, never a runtime grant.
- Delegation scope compares tool-name sets and says nothing about
  runtime enforcement.
- Helper functions that a tool calls are not followed.
- Identity links come only from configuration in the repository.

## 5. Runtime observation record

One JSON file per scenario, produced by a runtime harness. **This
format is a proposal for the runtime side to correct.** No such record
exists yet, and this repository contains none.

```json
{
  "spec_version": "0.1-draft",
  "scenario": "s3_attempted_escalation",
  "producer": {"tool": "<harness>", "kind": "runtime", "version": "<version>"},
  "policy_ref": "<identifier or digest of the policy in force>",
  "observations": [
    {
      "request_id": "req-3",
      "agent": "intern",
      "principal": "<runtime principal, or null when it cannot be established>",
      "tool": "delete_account",
      "decision": "DENY",
      "execution": "not_executed",
      "effect": "not_observed",
      "audit_ref": "<pointer to the audit entry>"
    }
  ]
}
```

| Field | Values | Meaning |
|---|---|---|
| `request_id` | unique string | Links the request, the decision, the execution attempt and the observed effect |
| `agent` | scenario agent id | The agent on whose behalf the request was made |
| `principal` | string or `null` | The runtime identity the decision was made for |
| `tool` | scenario tool name | The action requested |
| `decision` | `PERMIT`, `DENY` | The authorization decision alone |
| `execution` | `executed`, `not_executed`, `unknown` | Whether the tool was invoked |
| `effect` | `observed`, `not_observed`, `unknown` | Whether the effect was seen at the effect target, checked independently of the executor |
| `audit_ref` | string | Where the decision is recorded |

Open points for the runtime side:

- Whether delegation context (who the request is on behalf of, and the
  delegation chain) needs its own fields.
- Whether `policy_ref` should be a digest.
- Which fields the native audit schema already carries.

## 6. Outcome rules

A **comparison unit** is one `(agent, tool)` pair. There is one row per
runtime observation, plus one row per static `tool_access` claim that
was never requested at run time. When an agent reaches a tool by several
paths, the shortest path represents the unit.

The rules are applied in order, and the first that applies wins.

| # | Condition | Outcome | Reason |
|---|---|---|---|
| 1 | Static claim, no runtime observation | insufficient evidence | `not_tested` |
| 2 | Observation has no principal | insufficient evidence | `principal_unresolved` |
| 3 | Static claim is `unresolved` | insufficient evidence | `static_unresolved` |
| 4 | `DENY`, yet executed or effect observed | disagreement | `denied_but_effect_observed` |
| 5 | `DENY`, static claim exists | agreement | `potential_restricted` |
| 6 | `DENY`, no static claim | agreement | `absent_and_denied` |
| 7 | `PERMIT`, no static claim | disagreement | `permitted_without_static_path` |
| 8 | `PERMIT`, static claim, effect observed | agreement | `potential_exercised` |
| 9 | `PERMIT`, static claim, effect not observed or unknown | insufficient evidence | `effect_unverified` |

Notes on the rules:

- **Rule 4** is a finding about the runtime, not about static analysis.
- **Rule 7** is a static miss: something was permitted that the source
  analysis shows no path to.
- **Rules 5 and 6** count as agreement because the two records do not
  contradict each other. They do not show that the denial is correct.
  Whether a denial matches *intent* is a separate check of runtime
  policy against declared intent.

Open points:

- Whether rule 2 should also apply when the *static* identity link is
  unresolved. Today it does not, because the harness knows which agent
  it ran.
- Whether access mode should be part of the unit, so that reading and
  writing through the same tool are compared separately.

## 7. Reporting

Report, for every scenario and in total:

- the number of units, and the counts of agreement, disagreement and
  insufficient evidence;
- the count for each reason;
- agreement over resolved units **and** over all units, each with its
  denominator.

A rate over resolved units is never reported without the count of
unresolved units next to it. With six scenarios the sample is small:
report counts, not percentages.

Separately from the comparison, each side can report its own accuracy
against the reviewed intent: agent, tool, capability and delegation-edge
detection, with unresolved items counted.

## 8. Boundaries

- Each project stays independently runnable. This repository contains
  no AxiomGate code and calls none.
- Records are exchanged as files. No adapter or combined decision engine
  is written before the specification is agreed.
- No secrets, credentials, private code or production data.
- Runtime execution happens only in an isolated, synthetic environment.
- Licences are recorded before any implementation code is shared.
  SafeAI's tooling here is under this repository's licence. The fixtures
  and this specification are intended to be freely reusable.
- No claim about general safety, and no runtime guarantee, beyond the
  evidence actually collected.

## 9. Running the SafeAI half

```bash
python scripts/collab_evidence.py static
```

```bash
python scripts/collab_evidence.py check
```

```bash
python scripts/collab_evidence.py compare --runtime <directory of runtime records>
```

`static` regenerates the static records. `check` validates the
scenarios and fails if a committed record no longer matches a scan.
`compare` applies the outcome rules to runtime records supplied by a
harness.
