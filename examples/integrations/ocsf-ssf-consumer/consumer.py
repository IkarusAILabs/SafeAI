# SPDX-License-Identifier: Apache-2.0
"""Reference consumer for SafeAI's file-only OCSF and SSF exports (plan 2.13-3; ROADMAP B6).

It shows what a receiver can do with the two files without SafeAI
installed and without any network access:

1. validate every record against the published schemas (OCSF 1.9.0
   class schemas, SafeAI's SET payload schema), when ``jsonschema`` is
   installed;
2. check that each SET names the manifest digest the operator expects
   (``--manifest-digest``), so payloads from another scan are rejected;
3. join each SET to the OCSF IAM Analysis Finding for the same tool and
   print a review queue: what changed, which escalations explain it,
   and what the tool may now do.

The queue leaves out scan IDs, times and project IDs, so the same
fixture gives the same queue on any machine. It is a review list, not
a decision: this example never blocks, revokes or sends anything.

Usage::

    python consumer.py --ocsf events.ocsf.jsonl --ssf-set events.set.jsonl \\
        [--schemas ../../../schemas] [--manifest-digest SHA256] [--output queue.json]
"""

import argparse
import json
import os
import sys

OCSF_SCHEMAS = {2007: "ocsf/1.9.0/application_security_posture_finding.json",
                2008: "ocsf/1.9.0/iam_analysis_finding.json"}
SET_SCHEMA = "safeai-ssf-set/v0.1.0.json"
EVENT_TYPE = ("https://github.com/IkarusAILabs/SafeAI/blob/main/docs/exports/"
              "ssf-agent-authority-change-v0.1-experimental.md")


def load_jsonl(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def validate(ocsf_events, set_payloads, schema_root):
    """Schema errors as ``["<file>:<record>: <message>", ...]``; None without jsonschema."""
    try:
        import jsonschema
    except ImportError:
        return None

    def _load(rel):
        with open(os.path.join(schema_root, rel), encoding="utf-8") as handle:
            return jsonschema.Draft7Validator(json.load(handle))

    ocsf = {uid: _load(rel) for uid, rel in OCSF_SCHEMAS.items()}
    sets = _load(SET_SCHEMA)
    errors = []
    for index, event in enumerate(ocsf_events):
        validator = ocsf.get(event.get("class_uid"))
        if validator is None:
            errors.append(f"ocsf:{index}: unexpected class_uid {event.get('class_uid')}")
            continue
        errors += [f"ocsf:{index}: {e.message}" for e in validator.iter_errors(event)]
    for index, payload in enumerate(set_payloads):
        errors += [f"set:{index}: {e.message}" for e in sets.iter_errors(payload)]
    return errors


def review_queue(ocsf_events, set_payloads, manifest_digest=None):
    """The review queue (see module docstring) and the SETs rejected on digest."""
    privileges = {}
    severities = {}
    for event in ocsf_events:
        safeai = (event.get("unmapped") or {}).get("safeai") or {}
        if event.get("class_uid") == 2008:
            results = event.get("permission_analysis_results") or [{}]
            privileges[safeai.get("tool_key")] = results[0].get("granted_privileges") or []
        elif event.get("class_uid") == 2007:
            key = str(event.get("severity_id"))
            severities[key] = severities.get(key, 0) + 1
    queue, rejected = [], []
    for payload in set_payloads:
        event = (payload.get("events") or {}).get(EVENT_TYPE)
        if event is None:
            rejected.append({"jti": payload.get("jti"), "reason": "unknown event type"})
            continue
        digest = (event.get("evidence") or {}).get("manifest_payload_sha256")
        if manifest_digest and digest != manifest_digest:
            rejected.append({"jti": payload.get("jti"),
                             "reason": "manifest digest differs from the expected one"})
            continue
        tool = event.get("tool") or {}
        queue.append({
            "tool": tool.get("key"),
            "change_class": event.get("change_class"),
            "change_types": event.get("change_types"),
            "inferred_only": event.get("inferred_only"),
            "escalations": [f"{e.get('id')} ({e.get('severity')}): {e.get('summary')}"
                            for e in event.get("escalations") or []],
            "granted_privileges": privileges.get(tool.get("key"), []),
        })
    order = {"HIGH_RISK_CHANGE": 0, "MATERIAL_CHANGE": 1}
    queue.sort(key=lambda item: (order.get(item["change_class"], 9), str(item["tool"])))
    return {"review_queue": queue, "rejected": rejected,
            "finding_counts_by_ocsf_severity_id": dict(sorted(severities.items()))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ocsf", required=True, help="OCSF JSON Lines export")
    parser.add_argument("--ssf-set", required=True, help="SSF SET payload JSON Lines export")
    parser.add_argument("--schemas", help="Directory holding ocsf/ and safeai-ssf-set/ schemas")
    parser.add_argument("--manifest-digest", help="Expected manifest payload SHA-256")
    parser.add_argument("--output", help="Write the queue as JSON here (default: stdout)")
    args = parser.parse_args(argv)

    ocsf_events, set_payloads = load_jsonl(args.ocsf), load_jsonl(args.ssf_set)
    if args.schemas:
        errors = validate(ocsf_events, set_payloads, args.schemas)
        if errors is None:
            print("jsonschema not installed: schema validation skipped", file=sys.stderr)
        elif errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
    result = review_queue(ocsf_events, set_payloads, args.manifest_digest)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 1 if result["rejected"] else 0


if __name__ == "__main__":
    sys.exit(main())
