# Static authority evidence vs runtime authorization

A starting point for the research experiment proposed in
[discussion #251](https://github.com/IkarusAILabs/SafeAI/discussions/251):
can source-derived evidence about an agent's authority help explain,
predict or audit runtime authorization decisions?

**Status: draft proposal.** Nothing here is agreed, and no runtime has
been run. The scenario ground truth is an AI-assisted draft awaiting
review by a person from each project.

## What is here

| Path | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | Draft experiment specification: scenarios, record formats, outcome rules, reporting, boundaries |
| `scenarios/<id>/fixture/` | Six synthetic agent projects |
| `scenarios/<id>/scenario.yml` | Draft intent, proposed runtime policy and requests, expected outcomes |
| `records/static/<id>.json` | SafeAI's static evidence for each scenario, in the proposed neutral format |
| [`scripts/collab_evidence.py`](../../../scripts/collab_evidence.py) | Produces the static records and applies the outcome rules |

## What works today

The static half runs end to end. For each scenario SafeAI reports:

- the agents, and each tool an agent can reach, directly or through a
  handoff;
- what each tool's body does (read, write, delete, execute), with file
  and line;
- each delegation edge, and whether the delegate holds fewer, the same
  or more tools than the delegator;
- whether the agent is tied to an identity, and why not when it isn't.

The outcome rules are implemented and tested against observations that
the tests construct from each scenario's *proposed* requests. Those are
test inputs. They are not measurements.

## What is missing

- **Runtime observations.** None exist. The format in `SPEC.md`
  section 5 is a proposal for the runtime side to correct.
- **Reviewed ground truth.** Every scenario is `pending_human_review`.
- **Scenarios beyond the first six.** Dynamic or unknown delegation
  targets and contradictory evidence are left for a later round.

## Known limits of the static side

- It shows potential authority, never a runtime grant.
- Delegation scope is a comparison of tool names. A delegate with
  fewer tools is reported as `narrower`; that says nothing about whether
  a runtime enforces the narrowing.
- Helper functions that a tool calls are not followed.
- All six fixtures use one framework's handoff model.

## Try it

```bash
python scripts/collab_evidence.py check
```
